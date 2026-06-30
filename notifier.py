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
from datetime import datetime, timezone

# Map an alert/remediation report to a concrete, allow-listed executor action so
# the notification can carry real Approve/Reject controls. Deliberately narrow:
# only unambiguous matches produce an approval, everything else is informational.
_RESTART_RE = re.compile(r"\brestart(?:ing|s|ed)?\b", re.I)
_SERVICE_RE = re.compile(r"\b(?:erp[-_ ]?backend|backend|service)\b", re.I)
_DELETE_CUSTOMER_RE = re.compile(r"\b(?:delete|remove|drop)\b.*?customer\D*(\d+)", re.I)
# A deallocated/stopped dev Azure VM whose fix is to start it. Match an explicit
# "start the VM" / "az vm start" intent and capture the dev VM name anywhere in
# the report. Restricted to the two known dev VMs so prod is never targeted.
_VM_NAME_RE = re.compile(r"\b(vm-erp-dev-(?:app|db))\b", re.I)
_START_VM_RE = re.compile(
    r"\b(?:az\s+vm\s+start|start(?:ing)?\s+(?:the\s+)?vm|vm\s+start|"
    r"start\s+the\s+(?:deallocated|stopped)\s+vm|power[\s-]?on)\b",
    re.I,
)


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
    # Deallocated dev VM whose remediation is to start it.
    vm = _VM_NAME_RE.search(report)
    if vm and _START_VM_RE.search(report):
        return "start_vm", {"vm": vm.group(1).lower()}
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


_FONT = ("-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,"
         "Arial,sans-serif")
_MONO = "'SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace"

# Labels the RCA report is composed of, in display order, with an icon each.
_REPORT_FIELDS: list[tuple[str, str]] = [
    ("Root cause", "&#128269;"),     # magnifying glass
    ("Severity", "&#127777;"),       # thermometer
    ("Evidence", "&#128202;"),       # bar chart
    ("Proposed fix", "&#128295;"),   # wrench
    ("Command", "&#9000;"),          # keyboard-ish
    ("Risk", "&#9888;"),             # warning
    ("Approval", "&#9989;"),         # check
]
_FIELD_RE = re.compile(
    r"(?im)^[ \t>#*_-]*(Root cause|Severity|Evidence|Proposed fix|Command|Risk|"
    r"Approval|Gate(?:\s*\([^)]*\))?)\**[ \t]*[:\-\u2014][ \t]*\**[ \t]*"
)


def _esc(value: str) -> str:
    return (value or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _parse_report(report: str) -> dict[str, str]:
    """Split a labelled RCA report into {label: value}. Empty if unstructured."""
    matches = list(_FIELD_RE.finditer(report))
    if not matches:
        return {}
    fields: dict[str, str] = {}
    for i, m in enumerate(matches):
        raw_label = m.group(1).strip()
        key = re.sub(r"\s*\(.*\)\s*", "", raw_label).strip()
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(report)
        value = report[start:end].strip()
        value = re.sub(r"(?m)\s*^[-*_]{3,}\s*$", "", value).strip()
        fields[key] = value
    return fields


def _severity_badge(value: str) -> tuple[str, str]:
    """Return (background_color, label) for a severity string."""
    v = (value or "").lower()
    if "critical" in v:
        return "#b10e1c", "CRITICAL"
    if "high" in v or "sev1" in v:
        return "#d13438", "HIGH"
    if "medium" in v or "moderate" in v or "sev2" in v:
        return "#c05621", "MEDIUM"
    if "low" in v or "info" in v:
        return "#107c10", "LOW"
    return "#605e5c", (value.strip().upper() if value.strip() else "UNKNOWN")


def _build_email(report: str, decision: str, reason: str,
                 source: str, approval: dict | None, chat_url: str,
                 *, subtitle: str = "Autonomous SRE · Incident Report",
                 kicker: str = "Triggered by", subject_noun: str = "alert",
                 followup_label: str = "Open live chat about this alert",
                 followup_text: str = (
                     "Need to dig deeper? Continue the investigation with the "
                     "agent — live logs, metrics and further fixes."
                 )) -> tuple[str, str]:
    """Return (plain_text, html) bodies for the notification email."""
    fields = _parse_report(report)

    # ---- Plain-text part (clean, readable fallback) -------------------------
    text_lines = [
        "DEVOPS COMMANDER — INCIDENT REPORT",
        "==================================",
        f"Source:        {source}",
        f"Gate decision: {decision} — {reason}",
        "",
    ]
    if fields:
        for label, _ in _REPORT_FIELDS:
            if label in fields:
                text_lines.append(f"{label}: {fields[label]}")
    else:
        text_lines.append(report)
    text = "\n".join(text_lines)

    # ---- Structured field rows (HTML) ---------------------------------------
    rows_html = ""
    if fields:
        for label, icon in _REPORT_FIELDS:
            if label not in fields:
                continue
            value = fields[label]
            if label == "Severity":
                bg, sev = _severity_badge(value)
                value_html = (
                    f'<span style="display:inline-block;background:{bg};color:#fff;'
                    f'font:700 12px/1 {_FONT};letter-spacing:.04em;padding:5px 12px;'
                    f'border-radius:20px;">{_esc(sev)}</span>'
                )
            elif label == "Command":
                cmd = re.sub(r"```[a-zA-Z0-9]*", "", value).replace("`", "").strip()
                value_html = (
                    f'<div style="margin-top:7px;background:#0d1117;color:#d6deeb;'
                    f'font:13px/1.55 {_MONO};padding:14px 16px;border-radius:8px;'
                    f'border:1px solid #1f2733;word-break:break-all;'
                    f'white-space:pre-wrap;">{_esc(cmd)}</div>'
                )
                rows_html += (
                    f'<tr><td style="padding:0 0 18px;">'
                    f'<div style="font:700 11px/1 {_FONT};letter-spacing:.09em;'
                    f'text-transform:uppercase;color:#8a94a6;">{icon}&nbsp; {label}'
                    f'</div>{value_html}</td></tr>'
                )
                continue
            else:
                value_html = (
                    f'<div style="margin-top:5px;font:15px/1.55 {_FONT};'
                    f'color:#1f2933;">{_esc(value)}</div>'
                )
            rows_html += (
                f'<tr><td style="padding:0 0 18px;">'
                f'<div style="font:700 11px/1 {_FONT};letter-spacing:.09em;'
                f'text-transform:uppercase;color:#8a94a6;">{icon}&nbsp; {label}</div>'
                f'{value_html}</td></tr>'
            )
    else:
        rows_html = (
            f'<tr><td style="padding:0 0 18px;">'
            f'<pre style="white-space:pre-wrap;margin:0;background:#f4f6f9;'
            f'padding:16px;border-radius:8px;font:13px/1.6 {_MONO};color:#1f2933;'
            f'">{_esc(report)}</pre></td></tr>'
        )

    # ---- Gate / decision banner ---------------------------------------------
    hold = decision.upper() == "HOLD"
    gate_bg = "#fff4e5" if hold else "#e8f5e9"
    gate_border = "#f0a500" if hold else "#107c10"
    gate_color = "#8a4b00" if hold else "#0b5d1e"
    gate_icon = "&#9888;" if hold else "&#9989;"
    gate_html = (
        f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
        f'style="margin:0 0 22px;background:{gate_bg};border-left:4px solid '
        f'{gate_border};border-radius:6px;"><tr>'
        f'<td style="padding:13px 16px;font:14px/1.5 {_FONT};color:{gate_color};">'
        f'<span style="font-size:16px;">{gate_icon}</span>&nbsp; '
        f'<strong>Gate decision: {_esc(decision)}</strong> &mdash; {_esc(reason)}'
        f'</td></tr></table>'
    )

    # ---- Approval action panel ----------------------------------------------
    approval_html = ""
    if approval:
        approve_url, reject_url = _approval_links(approval.get("token", ""))
        summary = approval.get("summary", "An action requires approval.")
        mins = max(1, int(approval.get("expires_in_seconds") or 600) // 60)
        text += (
            f"\n\n>>> ACTION REQUIRES APPROVAL <<<\n{summary}\n"
            f"Approve: {approve_url}\nReject:  {reject_url}\n"
            f"(expires in {mins} min, single use)"
        )
        approval_html = (
            f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
            f'style="margin:6px 0 8px;background:#f8fafc;border:1px solid #e2e8f0;'
            f'border-radius:10px;"><tr><td style="padding:20px 22px;">'
            f'<div style="font:700 11px/1 {_FONT};letter-spacing:.09em;'
            f'text-transform:uppercase;color:#9a3412;">&#9888;&nbsp; '
            f'Action requires your approval</div>'
            f'<div style="margin:8px 0 16px;font:15px/1.5 {_FONT};color:#1f2933;">'
            f'{_esc(summary)}</div>'
            f'<table role="presentation" cellpadding="0" cellspacing="0"><tr>'
            f'<td style="border-radius:8px;background:#107c10;">'
            f'<a href="{approve_url}" style="display:inline-block;padding:12px 30px;'
            f'font:700 14px/1 {_FONT};color:#ffffff;text-decoration:none;">'
            f'&#10003;&nbsp; Approve</a></td>'
            f'<td style="width:12px;">&nbsp;</td>'
            f'<td style="border-radius:8px;background:#c1242b;">'
            f'<a href="{reject_url}" style="display:inline-block;padding:12px 30px;'
            f'font:700 14px/1 {_FONT};color:#ffffff;text-decoration:none;">'
            f'&#10007;&nbsp; Reject</a></td>'
            f'</tr></table>'
            f'<div style="margin-top:14px;font:12px/1.4 {_FONT};color:#94a3b8;">'
            f'&#128274; Single-use, expires in {mins} min. No login required.</div>'
            f'</td></tr></table>'
        )

    # ---- Live-chat follow-up ------------------------------------------------
    chat_html = ""
    if chat_url:
        text += f"\n\n{followup_text}\n{chat_url}"
        chat_html = (
            f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
            f'style="margin-top:18px;"><tr><td style="padding-top:18px;'
            f'border-top:1px solid #eaecef;">'
            f'<div style="font:13px/1.55 {_FONT};color:#586069;margin-bottom:12px;">'
            f'{_esc(followup_text)}</div>'
            f'<table role="presentation" cellpadding="0" cellspacing="0"><tr>'
            f'<td style="border-radius:8px;border:1px solid #d0d7de;background:#ffffff;">'
            f'<a href="{chat_url}" style="display:inline-block;padding:11px 24px;'
            f'font:600 14px/1 {_FONT};color:#0969da;text-decoration:none;">'
            f'&#128172;&nbsp; {_esc(followup_label)}</a>'
            f'</td></tr></table></td></tr></table>'
        )

    # ---- Assemble ------------------------------------------------------------
    sent_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    sev_bg, sev_label = _severity_badge(fields.get("Severity", ""))
    html = (
        '<!DOCTYPE html><html><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '</head>'
        '<body style="margin:0;padding:0;background:#eef1f5;">'
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
        'style="background:#eef1f5;"><tr><td align="center" '
        'style="padding:28px 14px;">'
        '<table role="presentation" width="600" cellpadding="0" cellspacing="0" '
        'style="max-width:600px;width:100%;background:#ffffff;border-radius:14px;'
        'overflow:hidden;box-shadow:0 2px 10px rgba(20,30,60,.08);">'
        # Header band
        '<tr><td style="background:#161a35;padding:24px 28px;">'
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0">'
        '<tr><td style="vertical-align:middle;">'
        f'<div style="font:700 18px/1.2 {_FONT};color:#ffffff;">'
        '&#128737;&#65039;&nbsp; DevOps Commander</div>'
        f'<div style="margin-top:3px;font:12px/1.2 {_FONT};color:#9aa4c4;">'
        f'{_esc(subtitle)}</div>'
        '</td><td align="right" style="vertical-align:middle;">'
        f'<span style="display:inline-block;background:{sev_bg};color:#fff;'
        f'font:700 11px/1 {_FONT};letter-spacing:.04em;padding:6px 13px;'
        f'border-radius:20px;">{_esc(sev_label)}</span>'
        '</td></tr></table></td></tr>'
        # Sub-header (source + time)
        '<tr><td style="padding:20px 28px 4px;">'
        f'<div style="font:12px/1 {_FONT};color:#8a94a6;text-transform:uppercase;'
        f'letter-spacing:.08em;">{_esc(kicker)}</div>'
        f'<div style="margin-top:5px;font:600 17px/1.3 {_FONT};color:#161a35;">'
        f'{_esc(source)} {_esc(subject_noun)}</div>'
        f'<div style="margin-top:3px;font:12px/1 {_FONT};color:#a0a8b8;">'
        f'{sent_at}</div></td></tr>'
        # Body
        '<tr><td style="padding:20px 28px 8px;">'
        f'{gate_html}'
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0">'
        f'{rows_html}</table>'
        f'{approval_html}{chat_html}'
        '</td></tr>'
        # Footer
        '<tr><td style="background:#f7f8fa;padding:18px 28px;border-top:'
        '1px solid #eaecef;">'
        f'<div style="font:11px/1.5 {_FONT};color:#9aa1ad;">'
        'This is an automated message from DevOps Commander. Approval links are '
        'signed, single-use and expire automatically. Do not forward.'
        '</div></td></tr>'
        '</table></td></tr></table></body></html>'
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


def _workflow_file_from_payload(payload: dict) -> str:
    """Best-effort: the workflow file basename, for a re-run dispatch.

    Accepts an explicit ``workflow_path``/``workflow_file`` or derives it from
    GitHub's ``workflow_ref`` (e.g. ``owner/repo/.github/workflows/x.yml@ref``).
    """
    direct = payload.get("workflow_path") or payload.get("workflow_file")
    if direct:
        return str(direct)
    ref = payload.get("workflow_ref") or ""
    if ref:
        path = ref.split("@", 1)[0]
        idx = path.find(".github/workflows/")
        if idx != -1:
            return path[idx:]
    return ""


def _maybe_make_pipeline_approval(payload: dict, fix: dict | None) -> dict | None:
    """Store the proposed fix and mint a ``fix_pipeline`` approval token.

    Returns the executor approval result (token + summary) or None when the
    executor/GitHub is not configured or there is no concrete fix to apply.
    Never raises — the email still goes out without buttons.
    """
    if not fix or not fix.get("files"):
        return None
    try:
        import executor

        if not executor.github_is_enabled():
            return None
        repo = payload.get("repo") or payload.get("repository") or ""
        record = {
            "repo": repo,
            "base_branch": (
                fix.get("base_branch")
                or payload.get("branch")
                or payload.get("ref_name")
                or payload.get("head_branch")
            ),
            "run_id": payload.get("run_id"),
            "run_url": payload.get("run_url") or payload.get("html_url"),
            "workflow_path": _workflow_file_from_payload(payload),
            "summary": fix.get("summary"),
            "files": fix.get("files"),
        }
        fix_id = executor.store_pipeline_fix(record)
        result = executor.request_action(
            "fix_pipeline", "github", {"fix_id": fix_id, "repo": repo}
        )
        return result if result.get("requires_approval") else None
    except Exception:
        logging.exception("pipeline_approval_mint_failed")
        return None


def notify_pipeline_failure(report: str, decision: str, reason: str,
                            payload: dict, fix: dict | None) -> None:
    """Email a failed-pipeline RCA with a gated, one-click fix (Approve/Reject).

    ``report`` is the agent's CI/CD triage; ``payload`` is the GitHub Actions
    failure context; ``fix`` is the parsed change-set (or None). When a concrete
    fix and a write PAT are available, an approval token is minted so a human
    can apply it from the email. Never raises.
    """
    try:
        payload = payload or {}
        repo = payload.get("repo") or payload.get("repository") or "repository"
        workflow = payload.get("workflow") or payload.get("workflow_name") or "workflow"
        run_url = payload.get("run_url") or payload.get("html_url") or ""

        approval = _maybe_make_pipeline_approval(payload, fix)

        subject = f"[DevOps Commander] Pipeline failed — {repo} · {workflow}"
        text, html = _build_email(
            report, decision, reason, repo, approval, run_url,
            subtitle="Autonomous SRE · CI/CD Triage",
            kicker="Failed pipeline",
            subject_noun=f"· {workflow}",
            followup_label="View the failed workflow run",
            followup_text="Inspect the full CI logs for this run on GitHub.",
        )
        _send_email(subject, text, html)

        teams_text = (
            f"\U0001f6a8 Pipeline failed — {repo} · {workflow} "
            f"(gate: {decision})\n\n{report}"
        )
        _send_teams(teams_text, approval)
    except Exception:
        logging.exception("notify_pipeline_failure_failed")
