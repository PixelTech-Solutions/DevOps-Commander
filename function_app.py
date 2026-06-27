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


@app.route(route="action", methods=["GET", "POST"])
def action(req: func.HttpRequest) -> func.HttpResponse:
    """GET/POST /api/action — the hands of the system (development only).

    GET returns the safe allow-list of what can be run (names only, no
    commands). POST runs one allow-listed, read-only action against a *dev* VM
    via Azure Run Command and returns its output. Every guard that matters lives
    in ``executor`` (environment block, allow-list, typed params, RBAC scope);
    this route is just the authenticated HTTP edge. Protected by the same shared
    secret as chat (``X-Chat-Token``).
    """

    expected = os.environ.get("CHAT_SHARED_SECRET") or os.environ.get("ALERT_SHARED_SECRET", "")
    presented = req.headers.get("X-Chat-Token", "")
    if not expected:
        logging.error("Neither CHAT_SHARED_SECRET nor ALERT_SHARED_SECRET is configured")
        return func.HttpResponse("server misconfigured", status_code=500)
    if presented != expected:
        logging.warning("Rejected action: bad/missing X-Chat-Token")
        return func.HttpResponse("unauthorized", status_code=401)

    import executor

    if req.method == "GET":
        return func.HttpResponse(
            json.dumps({"actions": executor.list_actions(), "environments": list(executor.ALLOWED_ENVS)}),
            status_code=200,
            mimetype="application/json",
        )

    try:
        body = req.get_json()
    except ValueError:
        body = {}
    body = body or {}
    action_name = (body.get("action") or "").strip()
    env = (body.get("env") or "").strip()
    params = body.get("params") or {}
    if not action_name or not env:
        return func.HttpResponse(
            json.dumps({"error": "missing 'action' or 'env'"}),
            status_code=400,
            mimetype="application/json",
        )

    try:
        result = executor.request_action(action_name, env, params)
    except executor.ActionError as exc:
        logging.warning("action_refused %s", json.dumps({"action": action_name, "env": env, "reason": str(exc)}))
        return func.HttpResponse(
            json.dumps({"error": str(exc)}),
            status_code=400,
            mimetype="application/json",
        )
    except Exception:
        logging.exception("action_failed")
        return func.HttpResponse(
            json.dumps({"error": "action execution failed"}),
            status_code=502,
            mimetype="application/json",
        )

    # Destructive actions don't run yet — they return a token to approve. Use
    # 202 Accepted so callers can distinguish "pending approval" from "done".
    status = 202 if result.get("requires_approval") else 200
    return func.HttpResponse(
        json.dumps(result),
        status_code=status,
        mimetype="application/json",
    )


@app.route(route="approve", methods=["POST"])
def approve(req: func.HttpRequest) -> func.HttpResponse:
    """POST /api/approve — spend a single-use token and run the destructive action.

    The body carries the ``token`` returned by a destructive ``/api/action``
    request. The executor verifies the signature, checks expiry, spends the
    nonce (so it can't run twice), and only then touches the dev VM. Protected
    by the same shared secret as the other action routes.
    """

    expected = os.environ.get("CHAT_SHARED_SECRET") or os.environ.get("ALERT_SHARED_SECRET", "")
    presented = req.headers.get("X-Chat-Token", "")
    if not expected:
        logging.error("Neither CHAT_SHARED_SECRET nor ALERT_SHARED_SECRET is configured")
        return func.HttpResponse("server misconfigured", status_code=500)
    if presented != expected:
        logging.warning("Rejected approve: bad/missing X-Chat-Token")
        return func.HttpResponse("unauthorized", status_code=401)

    import executor

    try:
        body = req.get_json()
    except ValueError:
        body = {}
    token = ((body or {}).get("token") or "").strip()
    if not token:
        return func.HttpResponse(
            json.dumps({"error": "missing 'token'"}),
            status_code=400,
            mimetype="application/json",
        )

    try:
        result = executor.approve_and_run(token)
    except executor.ActionError as exc:
        logging.warning("approval_refused %s", json.dumps({"reason": str(exc)}))
        return func.HttpResponse(
            json.dumps({"error": str(exc)}),
            status_code=400,
            mimetype="application/json",
        )
    except Exception:
        logging.exception("approval_failed")
        return func.HttpResponse(
            json.dumps({"error": "action execution failed"}),
            status_code=502,
            mimetype="application/json",
        )

    return func.HttpResponse(
        json.dumps(result),
        status_code=200,
        mimetype="application/json",
    )


@app.route(route="messages", methods=["POST"])
async def messages(req: func.HttpRequest) -> func.HttpResponse:
    """POST /api/messages — Bot Framework endpoint for the Web Chat channel.

    This is the protocol edge the Azure Bot resource points its messaging
    endpoint at. Authentication is handled inside the Bot Framework SDK using
    the Function's user-assigned managed identity (secretless), so there is no
    shared-secret check here. The bot forwards the user's text to the same
    coordinator brain as ``/api/chat``.
    """

    try:
        body = req.get_json()
    except ValueError:
        return func.HttpResponse("expected a JSON activity", status_code=400)

    auth_header = req.headers.get("Authorization", "")
    try:
        import bot

        invoke_response = await bot.process(body, auth_header)
    except PermissionError:
        logging.warning("Rejected message: failed Bot Framework authentication")
        return func.HttpResponse("unauthorized", status_code=401)
    except Exception:
        logging.exception("messages_failed")
        return func.HttpResponse("bot error", status_code=500)

    if invoke_response:
        return func.HttpResponse(
            json.dumps(invoke_response.body, default=str),
            status_code=invoke_response.status,
            mimetype="application/json",
        )
    return func.HttpResponse(status_code=201)


@app.route(route="directline-token", methods=["POST"])
def directline_token(req: func.HttpRequest) -> func.HttpResponse:
    """POST /api/directline-token — mint a short-lived Direct Line token.

    The Direct Line secret never leaves the server: we exchange it for a
    conversation-scoped token that the browser uses to open Web Chat. This is
    the recommended embedding pattern (the page never sees the secret).
    """

    secret = os.environ.get("DIRECTLINE_SECRET", "")
    if not secret:
        logging.error("DIRECTLINE_SECRET app setting is not configured")
        return func.HttpResponse("server misconfigured", status_code=500)

    payload = json.dumps({"user": {"id": f"dl_{uuid.uuid4().hex[:16]}"}}).encode("utf-8")
    request = urllib.request.Request(
        "https://directline.botframework.com/v3/directline/tokens/generate",
        data=payload,
        headers={
            "Authorization": f"Bearer {secret}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception:
        logging.exception("directline_token_failed")
        return func.HttpResponse(
            json.dumps({"error": "could not mint a Direct Line token"}),
            status_code=502,
            mimetype="application/json",
        )

    return func.HttpResponse(
        json.dumps({"token": data.get("token"), "expires_in": data.get("expires_in")}),
        status_code=200,
        mimetype="application/json",
    )


# Embeddable Web Chat page. It fetches a short-lived token from
# ``/api/directline-token`` on the same host, so the Direct Line secret stays
# server-side. BotFramework-WebChat is loaded from the official CDN.
_WEBCHAT_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>DevOps Commander</title>
  <script crossorigin="anonymous"
          src="https://cdn.botframework.com/botframework-webchat/latest/webchat.js"></script>
  <style>
    html, body { height: 100%; margin: 0; font-family: 'Segoe UI', Arial, sans-serif; }
    #app { display: flex; flex-direction: column; height: 100%; background: #f3f5f8; }
    #header { background: #2b6cb0; color: #fff; padding: 14px 20px; font-weight: 600;
              font-size: 18px; letter-spacing: .2px; }
    #header span { font-weight: 400; opacity: .85; font-size: 13px; }
    #webchat { flex: 1 1 auto; max-width: 820px; width: 100%; margin: 0 auto; }
    #status { padding: 12px 20px; color: #c05621; }
  </style>
</head>
<body>
  <div id="app">
    <div id="header">DevOps Commander
      <span>&middot; ChatOps for the ERP dev environment</span></div>
    <div id="webchat" role="main"></div>
    <div id="status"></div>
  </div>
  <script>
    (async function () {
      try {
        const res = await fetch('directline-token', { method: 'POST' });
        if (!res.ok) { throw new Error('token request failed (' + res.status + ')'); }
        const { token } = await res.json();
        window.WebChat.renderWebChat(
          {
            directLine: window.WebChat.createDirectLine({ token: token }),
            styleOptions: {
              botAvatarInitials: 'DC',
              userAvatarInitials: 'You',
              accent: '#2b6cb0'
            }
          },
          document.getElementById('webchat')
        );
      } catch (e) {
        document.getElementById('status').innerText =
          'Could not start chat: ' + e.message;
      }
    })();
  </script>
</body>
</html>"""


@app.route(route="webchat", methods=["GET"])
def webchat(req: func.HttpRequest) -> func.HttpResponse:
    """GET /api/webchat — embeddable Web Chat page for DevOps Commander."""
    return func.HttpResponse(_WEBCHAT_HTML, status_code=200, mimetype="text/html")
