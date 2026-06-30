"""DevOps Commander — alert receiver.

Single HTTP-triggered Function that accepts webhook payloads from
Datadog and Grafana Cloud, validates a shared-secret header, and logs
the payload to Application Insights for replay and downstream
processing by the agent fleet (Step 7+).
"""

from __future__ import annotations

import json
import logging
import os
import urllib.request
import uuid
from datetime import datetime, timezone

import azure.functions as func

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

def _classify_source(user_agent: str, body: dict | None) -> str:
    """Best-effort tag for which monitoring tool sent the alert."""
    ua = (user_agent or "").lower()
    if "datadog" in ua:
        return "datadog"
    if "grafana" in ua or "alertmanager" in ua:
        return "grafana"
    if isinstance(body, dict):
        if "alerts" in body and isinstance(body["alerts"], list):
            return "grafana"
        if "alert_type" in body or "monitor_id" in body:
            return "datadog"
    return "unknown"

@app.route(route="alert", methods=["POST"])
def alert_receiver(req: func.HttpRequest) -> func.HttpResponse:
    """POST /api/alert — entry point for Datadog and Grafana webhooks."""

    expected = os.environ.get("ALERT_SHARED_SECRET", "")
    presented = req.headers.get("X-Alert-Token", "")
    if not expected:
        logging.error("ALERT_SHARED_SECRET app setting is not configured")
        return func.HttpResponse("server misconfigured", status_code=500)
    if presented != expected:
        logging.warning(
            "Rejected alert: bad/missing X-Alert-Token from %s",
            req.headers.get("X-Forwarded-For", req.headers.get("Remote-Addr", "?")),
        )
        return func.HttpResponse("unauthorized", status_code=401)

    try:
        body = req.get_json()
    except ValueError:
        body = {"raw": req.get_body().decode("utf-8", errors="replace")}

    source = _classify_source(req.headers.get("User-Agent", ""), body if isinstance(body, dict) else None)

    event = {
        "received_at": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "user_agent": req.headers.get("User-Agent", ""),
        "remote_addr": req.headers.get("X-Forwarded-For", ""),
        "payload": body,
    }

    # Single-line JSON makes it cheap to grep in App Insights:
    #   traces | where message startswith "alert_received "
    logging.info("alert_received %s", json.dumps(event, default=str))

    # First agent: a Foundry Agent Service agent produces a root-cause analysis
    # (keyless). rca pulls in the azure-ai-projects / azure-identity SDKs, so
    # import it lazily and guard everything — an agent or dependency failure must
    # never stop us acknowledging the webhook or break function indexing.
    rca_text = None
    if os.environ.get("AZURE_AI_PROJECT_ENDPOINT"):
        try:
            import rca

            rca_text = rca.analyze_alert(event)
            if rca_text:
                logging.info(
                    "alert_rca %s",
                    json.dumps({"source": source, "analysis": rca_text}, default=str),
                )
        except Exception:
            logging.exception("rca_unavailable")

    return func.HttpResponse(
        json.dumps({"status": "accepted", "source": source, "rca": rca_text}),
        status_code=202,
        mimetype="application/json",
    )

@app.route(route="pipeline", methods=["POST"])
def pipeline_failure(req: func.HttpRequest) -> func.HttpResponse:
    """POST /api/pipeline — a CI/CD pipeline reported a failed run.

    Called by a 'notify on failure' step in the GitHub Actions workflows. The
    body carries the failed run's coordinates (repo, run_id, run_url, branch,
    head_sha, workflow). We hand it to the pipeline-triage agent, which reads
    the run with the read-only GitHub MCP, finds the exact reason, and emails a
    gated one-click fix. Protected by a shared-secret header (``X-Pipeline-Token``,
    falling back to ``X-Alert-Token``); the secret is ``PIPELINE_SHARED_SECRET``
    or, if unset, ``ALERT_SHARED_SECRET``.
    """
    expected = (
        os.environ.get("PIPELINE_SHARED_SECRET")
        or os.environ.get("ALERT_SHARED_SECRET", "")
    )
    presented = (
        req.headers.get("X-Pipeline-Token")
        or req.headers.get("X-Alert-Token", "")
    )
    if not expected:
        logging.error("PIPELINE_SHARED_SECRET/ALERT_SHARED_SECRET is not configured")
        return func.HttpResponse("server misconfigured", status_code=500)
    if presented != expected:
        logging.warning("Rejected pipeline: bad/missing X-Pipeline-Token")
        return func.HttpResponse("unauthorized", status_code=401)

    try:
        body = req.get_json()
    except ValueError:
        body = {"raw": req.get_body().decode("utf-8", errors="replace")}
    if not isinstance(body, dict):
        body = {"raw": body}

    event = {
        "received_at": datetime.now(timezone.utc).isoformat(),
        "source": "github-actions",
        "payload": body,
    }
    logging.info("pipeline_failure_received %s", json.dumps(event, default=str))

    rca_text = None
    if os.environ.get("AZURE_AI_PROJECT_ENDPOINT"):
        try:
            import rca

            rca_text = rca.analyze_pipeline_failure(event)
        except Exception:
            logging.exception("pipeline_rca_unavailable")

    return func.HttpResponse(
        json.dumps({"status": "accepted", "source": "github-actions", "rca": rca_text}),
        status_code=202,
        mimetype="application/json",
    )

# Other route definitions omitted for brevity
