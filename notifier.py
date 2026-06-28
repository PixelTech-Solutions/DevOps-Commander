"""Human notifications for alert handling — email (and best-effort Teams).

When an alert is processed, the system must make a human aware of *what
happened* and, when the code gate decides a fix needs sign-off, give that human
a way to approve or reject **out of band** (without opening the chat).

Two channels, both best-effort and independent — a failure in one never blocks
the other or the alert acknowledgement:

* **Email** via Azure Communication Services (ACS). Azure-native, no SMTP
  server, no third-party key. Configured by ``ACS_CONNECTION_STRING`` +
  ``NOTIFY_FROM`` + ``NOTIFY_TO_EMAILS``.
* **Teams** via the existing bot (proactive message). Dormant until the bot has
  at least one stored conversation reference (i.e. someone messaged it in a
  licensed Teams), then it lights up automatically.

For HOLD decisions we mint the same single-use approval token the chat approval
card uses, so the email's Approve/Reject links and the Teams card all share one
token and the existing ``/api/approve`` gate.
"""

from __future__ import annotations

import logging
import os
import re
import time
import urllib.parse
import uuid

# Map an alert/remediation report to a concrete, allow-listed executor action so
# the notification can carry real Approve/Reject controls. Deliberately narrow:
# only unambiguous matches produce an approval, everything else is informational.
_RESTART_RE = re.compile(r"\brestart(?:ing|s|ed)?\b", re.I)
_SERVICE_RE = re.compile(r"\b(?:erp[-_ ]?backend|backend|service)\b", re.I)
_DELETE_CUSTOMER_RE = re.compile(r"\b(?:delete|remove|drop)\b.*?customer\D*(\d+)", re.I)


def _base_url() -> str:
    base = os.environ.get("PUBLIC_BASE_URL", "").strip()
    if base:
        return base.rstrip("/")
    host = os.environ.get("WEBSITE_HOSTNAME", "").strip()
    return f"https://{host}" if host else ""


def _recipients() -> list[str]:
    raw = os.environ.get("NOTIFY_TO_EMAILS", "")
    return [a.strip() for a in raw.split(",") if a.strip()]


# --- Alert context store (to seed live chat from an email link) ---------------
# The email's "Open live chat" link carries an unguessable alert id; the Web Chat
# page fetches the stored RCA via /api/alert-context to continue the same
# investigation. Reuses the Functions storage account (no new infra).
_ALERT_TABLE = "alerts"


def _alert_table():
    conn = os.environ.get("AzureWebJobsStorage", "")
    if not conn:
        return None
    from azure.data.tables import TableServiceClient

    service = TableServiceClient.from_connection_string(conn)
    return service.create_table_if_not_exists(_ALERT_TABLE)


def _save_alert_context(alert_id: str, report: str, decision: str,
                        reason: str, source: str) -> None:
    try:
        table = _alert_table()
        if table is None:
            return
        table.upsert_entity(
            {
                "PartitionKey": "alert",
                "RowKey": alert_id,
                "report": report,
                "decision": decision,
                "reason": reason,
                "source": source,
                "ts": int(time.time()),
            }
        )
    except Exception:  # pragma: no cover - best effort
        logging.exception("alert_context_save_failed")


def load_alert_context(alert_id: str) -> dict | None:
    """Return the stored RCA for an alert id, or None. Used by /api/alert-context."""
    try:
        table = _alert_table()
        if table is None:
            return None
        entity = table.get_entity("alert", alert_id)
        return {
            "report": entity.get("report", ""),
            "decision": entity.get("decision", ""),
            "reason": entity.get("reason", ""),
            "source": entity.get("source", ""),
        }
    except Exception:
        logging.info("alert_context_not_found %s", alert_id)
        return None


def _detect_action(report: str) -> tuple[str, dict] | None:
    """Best-effort map of a report to (action, params); None when unclear."""
    match = _DELETE_CUSTOMER_RE.search(report)
    if match:
        return "delete_customer", {"id": int(match.group(1))}
    if _RESTART_RE.search(report) and _SERVICE_RE.search(report):
        return "restart_service", {}
    return None


def _maybe_make_approval(decision: str, report: str) -> dict | None:
    """For a HOLD decision with a recognisable action, mint an approval token.

    Returns the ``executor.request_action`` result (carries token + summary) or
    None. Never raises — approval is a bonus, not a requirement.
    """
    if decision != "HOLD":
        return None
    try:
        import executor

        if not executor.is_enabled():
            return None
        detected = _detect_action(report)
        if not detected:
            return None
        action, params = detected
        result = executor.request_action(action, "dev", params)
        return result if result.get("requires_approval") else None
    except Exception:
        logging.exception("notify_approval_mint_failed")
        return None


def _approval_links(token: str) -> tuple[str, str]:
    base = _base_url()
    q = urllib.parse.quote(token, safe="")
    approve = f"{base}/api/approval?token={q}&decision=approve"
    reject = f"{base}/api/approval?token={q}&decision=reject"
    return approve, reject


def _build_email(report: str, decision: str, reason: str,
                 source: str, approval: dict | None, chat_url: str) -> tuple[str, str]:
    """Return (plain_text, html) bodies for the notification email."""
    safe_report = report.replace("<", "&lt;").replace(">", "&gt;")
    lines = [
        f"Source: {source}",
        f"Gate decision: {decision} — {reason}",
        "",
        report,
    ]
    text = "\n".join(lines)

    approval_html = ""
    approval_text = ""
    if approval:
        approve_url, reject_url = _approval_links(approval.get("token", ""))
        summary = approval.get("summary", "An action requires approval.")
        mins = max(1, int(approval.get("expires_in_seconds") or 600) // 60)
        approval_text = (
            f"\n\nACTION REQUIRES APPROVAL: {summary}\n"
            f"Approve: {approve_url}\nReject:  {reject_url}\n"
            f"(expires in {mins} min, single use)"
        )
        text += approval_text
        approval_html = (
            f'<hr><p><strong>&#9888;&#65039; Action requires approval:</strong> '
            f'{summary}</p>'
            f'<p><a href="{approve_url}" style="background:#107c10;color:#fff;'
            f'padding:10px 18px;text-decoration:none;border-radius:4px;'
            f'margin-right:8px;">&#9989; Approve</a>'
            f'<a href="{reject_url}" style="background:#a4262c;color:#fff;'
            f'padding:10px 18px;text-decoration:none;border-radius:4px;">'
            f'&#10060; Reject</a></p>'
            f'<p style="color:#666;font-size:12px;">Expires in {mins} min, '
            f'single use.</p>'
        )

    color = "#a4262c" if decision == "HOLD" else "#107c10"
    chat_html = ""
    if chat_url:
        text += f"\n\nStill not resolved? Open a live chat about this alert:\n{chat_url}"
        chat_html = (
            f'<hr><p style="font-size:13px;color:#444;">Still not resolved after the '
            f'action above? Continue investigating with the agent (live logs, metrics '
            f'&amp; further fixes):</p>'
            f'<p><a href="{chat_url}" style="background:#2b6cb0;color:#fff;'
            f'padding:10px 18px;text-decoration:none;border-radius:4px;">'
            f'&#128172; Open live chat about this alert</a></p>'
        )
    html = (
        f'<div style="font-family:Segoe UI,Arial,sans-serif;max-width:680px;">'
        f'<h2 style="margin-bottom:4px;">DevOps Commander &mdash; alert</h2>'
        f'<p style="margin:0 0 12px;color:#666;">Source: <strong>{source}</strong></p>'
        f'<p style="font-size:16px;"><strong>Gate decision:</strong> '
        f'<span style="color:{color};font-weight:bold;">{decision}</span> '
        f'&mdash; {reason}</p>'
        f'<pre style="white-space:pre-wrap;background:#f3f2f1;padding:14px;'
        f'border-radius:6px;font-size:13px;">{safe_report}</pre>'
        f'{approval_html}{chat_html}</div>'
    )
    return text, html


def _send_email(subject: str, text: str, html: str) -> None:
    conn = os.environ.get("ACS_CONNECTION_STRING", "")
    sender = os.environ.get("NOTIFY_FROM", "")
    recipients = _recipients()
    if not conn or not sender or not recipients:
        logging.info("notify_email_skipped (ACS not fully configured)")
        return
    try:
        from azure.communication.email import EmailClient

        client = EmailClient.from_connection_string(conn)
        message = {
            "senderAddress": sender,
            "recipients": {"to": [{"address": a} for a in recipients]},
            "content": {"subject": subject, "plainText": text, "html": html},
        }
        poller = client.begin_send(message)
        result = poller.result()
        logging.info(
            "notify_email_sent %s",
            getattr(result, "id", None) or (result.get("id") if isinstance(result, dict) else ""),
        )
    except Exception:
        logging.exception("notify_email_failed")


def _send_teams(text: str, approval: dict | None) -> None:
    """Proactive Teams message — best-effort, no-op until the bot has refs."""
    try:
        import asyncio

        import bot

        asyncio.run(bot.notify_teams_proactive(text, approval))
    except Exception:
        logging.exception("notify_teams_failed")


def notify_alert(report: str, decision: str, reason: str, source: str) -> None:
    """Send the alert outcome to humans via email and (best-effort) Teams.

    ``report`` is the agent's compiled analysis; ``decision``/``reason`` come
    from the code gate. For a HOLD with a recognisable action, an approval token
    is minted and surfaced as Approve/Reject controls in both channels.
    Never raises — notification must not break alert acknowledgement.
    """
    try:
        approval = _maybe_make_approval(decision, report)
        # Persist the RCA so the email's "Open live chat" link can seed a
        # conversation with this incident's context.
        alert_id = uuid.uuid4().hex
        _save_alert_context(alert_id, report, decision, reason, source)
        base = _base_url()
        chat_url = f"{base}/api/webchat?alert={alert_id}" if base else ""

        subject = f"[DevOps Commander] {decision} — {source} alert"
        text, html = _build_email(report, decision, reason, source, approval, chat_url)
        _send_email(subject, text, html)

        teams_text = f"\U0001f6a8 {source} alert — gate: {decision} ({reason})\n\n{report}"
        _send_teams(teams_text, approval)
    except Exception:
        logging.exception("notify_alert_failed")
