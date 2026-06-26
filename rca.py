"""DevOps Commander multi-agent fleet (Foundry Agent Service, Connected Agents).

A coordinator agent receives each alert and delegates to specialist agents that
are registered as its tools (the Connected Agents pattern). The coordinator
decides the order in natural language; no hand-coded routing.

  coordinator (devops-commander-coordinator)
    ├─ diagnose_incident   -> devops-commander-rca         (root cause + severity)
    └─ propose_remediation -> devops-commander-remediation (safe fix + risk flag)

Everything runs server-side on the Foundry project, authenticated keyless with
the Function App's user-assigned managed identity (Foundry User role). No API
key is read or stored. AZURE_CLIENT_ID (an app setting) selects the identity.

Each alert gets its own thread (one incident = one conversation). Sub-agents are
created once and reused across cold starts (looked up by name), so they never
pile up as duplicates. Connected-agent replies are visible only to the
coordinator, which compiles the final report returned to the caller.
"""

from __future__ import annotations

import json
import logging
import os
from functools import lru_cache

from azure.ai.agents.models import ConnectedAgentTool, ListSortOrder, MessageRole
from azure.ai.projects import AIProjectClient
from azure.identity import DefaultAzureCredential

# --- Specialist agents (the "tools" the coordinator delegates to) ------------
_DIAGNOSE_NAME = "devops-commander-rca"
_DIAGNOSE_TOOL = "diagnose_incident"
_DIAGNOSE_INSTRUCTIONS = (
    "You are the diagnosis specialist for a multi-cloud ERP (Azure + AWS). "
    "Given a monitoring alert, identify the single most likely root cause and "
    "its severity. Reply with exactly two short lines:\n"
    "Root cause: <one sentence>\n"
    "Severity: <low|medium|high|critical>"
)

_REMEDIATION_NAME = "devops-commander-remediation"
_REMEDIATION_TOOL = "propose_remediation"
_REMEDIATION_INSTRUCTIONS = (
    "You are the remediation specialist for a multi-cloud ERP (Azure + AWS). "
    "Given a diagnosed incident (root cause + severity), propose the safest "
    "concrete fix. Reply with exactly three short lines:\n"
    "Proposed fix: <one sentence describing the action>\n"
    "Command: <the single command or playbook step to run>\n"
    "Approval: <auto-safe | needs-human>  (use needs-human for anything "
    "destructive, stateful, or production-impacting; never recommend running "
    "destructive actions without human approval)."
)

# --- Coordinator (the "main" agent the Function talks to) --------------------
_COORDINATOR_NAME = "devops-commander-coordinator"
_COORDINATOR_INSTRUCTIONS = (
    "You are DevOps Commander, the incident coordinator for a multi-cloud ERP. "
    "For each alert: first call diagnose_incident to get the root cause and "
    "severity, then call propose_remediation to get a safe fix for that "
    "diagnosis. Then compile ONE final report with exactly these lines:\n"
    "Root cause: ...\n"
    "Severity: <low|medium|high|critical>\n"
    "Proposed fix: ...\n"
    "Command: ...\n"
    "Approval: <auto-safe | needs-human>\n"
    "Do not execute anything yourself. Be concise and concrete."
)


def is_enabled() -> bool:
    """True when the Foundry project endpoint is configured."""
    return bool(os.environ.get("AZURE_AI_PROJECT_ENDPOINT"))


@lru_cache(maxsize=1)
def _client() -> AIProjectClient:
    return AIProjectClient(
        endpoint=os.environ["AZURE_AI_PROJECT_ENDPOINT"],
        credential=DefaultAzureCredential(),
    )


def _model() -> str:
    return os.environ.get("AZURE_OPENAI_DEPLOYMENT", "gpt-4o")


def _ensure_agent(name: str, instructions: str, tools=None) -> str:
    """Get-or-create an agent by name; return its id.

    Looking up by our well-known name keeps cold starts from piling up
    duplicate agents in the project.
    """
    client = _client()
    for agent in client.agents.list_agents():
        if agent.name == name:
            return agent.id
    created = client.agents.create_agent(
        model=_model(),
        name=name,
        instructions=instructions,
        tools=tools or [],
    )
    return created.id


@lru_cache(maxsize=1)
def _coordinator_id() -> str:
    """Ensure the two specialists + the coordinator exist; return coordinator id.

    The coordinator is created with the specialists wired in as Connected Agent
    tools, so it can delegate to them by name at runtime.
    """
    diagnose_id = _ensure_agent(_DIAGNOSE_NAME, _DIAGNOSE_INSTRUCTIONS)
    remediation_id = _ensure_agent(_REMEDIATION_NAME, _REMEDIATION_INSTRUCTIONS)

    diagnose_tool = ConnectedAgentTool(
        id=diagnose_id,
        name=_DIAGNOSE_TOOL,
        description="Diagnose the root cause and severity of an incident from its alert.",
    )
    remediation_tool = ConnectedAgentTool(
        id=remediation_id,
        name=_REMEDIATION_TOOL,
        description="Propose a safe, concrete fix and command for a diagnosed incident, flagging whether human approval is required.",
    )
    tools = diagnose_tool.definitions + remediation_tool.definitions
    return _ensure_agent(_COORDINATOR_NAME, _COORDINATOR_INSTRUCTIONS, tools=tools)


def _build_user_message(event: dict) -> str:
    source = event.get("source", "unknown")
    payload = event.get("payload")
    body = json.dumps(payload, default=str)[:4000]
    return f"Alert source: {source}\nAlert payload:\n{body}"


def _extract_answer(messages) -> str | None:
    """Return the text of the most recent assistant (coordinator) message."""
    answer = None
    for message in messages:
        if message.role != MessageRole.AGENT:
            continue
        for content in message.content:
            text = getattr(content, "text", None)
            value = getattr(text, "value", None) if text else None
            if value:
                answer = value
    return answer


def analyze_alert(event: dict) -> str | None:
    """Run the coordinator over an alert and return its compiled report, or None.

    The coordinator delegates to the diagnosis and remediation specialists and
    returns one combined report. Best-effort: any error is logged and swallowed
    so the caller can still acknowledge the webhook.
    """
    try:
        client = _client()
        coordinator_id = _coordinator_id()
        thread = client.agents.threads.create()
        try:
            client.agents.messages.create(
                thread_id=thread.id,
                role="user",
                content=_build_user_message(event),
            )
            run = client.agents.runs.create_and_process(
                thread_id=thread.id,
                agent_id=coordinator_id,
            )
            if run.status == "failed":
                logging.error("agent_run_failed %s", getattr(run, "last_error", None))
                return None
            messages = client.agents.messages.list(
                thread_id=thread.id,
                order=ListSortOrder.ASCENDING,
            )
            return _extract_answer(messages)
        finally:
            # One incident = one thread; clean it up so the project stays tidy.
            try:
                client.agents.threads.delete(thread.id)
            except Exception:
                logging.debug("thread_cleanup_failed", exc_info=True)
    except Exception:
        logging.exception("agent_rca_failed")
        return None
