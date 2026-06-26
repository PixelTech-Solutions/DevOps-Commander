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


@app.route(route="health", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def health(req: func.HttpRequest) -> func.HttpResponse:
    """GET /api/health — liveness probe (no auth)."""
    return func.HttpResponse(
        json.dumps({"status": "ok", "service": "devops-commander-alert-receiver"}),
        status_code=200,
        mimetype="application/json",
    )


@app.route(route="chat", methods=["POST"])
def chat(req: func.HttpRequest) -> func.HttpResponse:
    """POST /api/chat — ChatOps front door: a human talks to the agent fleet.

    A second entry point into the same coordinator brain (the first is the alert
    webhook). The request carries a free-text ``message`` and, on follow-up
    turns, the ``conversation_id`` we returned previously so the assistant keeps
    its context. Protected by a shared-secret header (``X-Chat-Token``), falling
    back to the alert secret so it works before any new app setting is added.
    This is advisory only — the assistant cannot execute anything yet.
    """

    expected = os.environ.get("CHAT_SHARED_SECRET") or os.environ.get("ALERT_SHARED_SECRET", "")
    presented = req.headers.get("X-Chat-Token", "")
    if not expected:
        logging.error("Neither CHAT_SHARED_SECRET nor ALERT_SHARED_SECRET is configured")
        return func.HttpResponse("server misconfigured", status_code=500)
    if presented != expected:
        logging.warning("Rejected chat: bad/missing X-Chat-Token")
        return func.HttpResponse("unauthorized", status_code=401)

    if not os.environ.get("AZURE_AI_PROJECT_ENDPOINT"):
        return func.HttpResponse("chat is not configured", status_code=503)

    try:
        body = req.get_json()
    except ValueError:
        body = {}
    message = (body or {}).get("message", "").strip()
    conversation_id = (body or {}).get("conversation_id") or None
    if not message:
        return func.HttpResponse(
            json.dumps({"error": "missing 'message'"}),
            status_code=400,
            mimetype="application/json",
        )

    try:
        import rca

        result = rca.analyze_chat(message, conversation_id)
    except Exception:
        logging.exception("chat_unavailable")
        result = None

    if not result:
        return func.HttpResponse(
            json.dumps({"error": "chat temporarily unavailable"}),
            status_code=502,
            mimetype="application/json",
        )

    logging.info(
        "chat_turn %s",
        json.dumps(
            {"conversation_id": result.get("conversation_id"), "message": message[:500]},
            default=str,
        ),
    )
    return func.HttpResponse(
        json.dumps(result),
        status_code=200,
        mimetype="application/json",
    )
