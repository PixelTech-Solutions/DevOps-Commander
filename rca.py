"""DevOps Commander multi-agent fleet (Foundry Agent Service, Connected Agents).

A coordinator agent receives each alert and delegates to specialist agents that
are registered as its tools (the Connected Agents pattern). The coordinator
decides the order in natural language; no hand-coded routing.

  coordinator (devops-commander-coordinator)
    ├─ diagnose_incident   -> devops-commander-rca         (root cause + severity)
    ├─ propose_remediation -> devops-commander-remediation (safe fix + command)
    └─ assess_risk         -> devops-commander-risk        (independent approval verdict)

After the agents reply, a deterministic CODE gate (_enforce_gate) has the FINAL
say on whether a fix may proceed automatically or must be held for a human. The
model proposes; the code disposes — an agent can never approve its own action.

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

from azure.ai.agents.models import (
    AzureAISearchQueryType,
    AzureAISearchTool,
    ConnectedAgentTool,
    ListSortOrder,
    MessageRole,
)
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

# When the Azure AI Search knowledge base is configured, the diagnosis agent
# grounds its answer in recorded knowledge and cites the closest match (RAG).
_DIAGNOSE_RAG_SUFFIX = (
    "\nYou also have a knowledge tool over recorded ERP knowledge: past "
    "incidents, the infrastructure inventory (environments, services, and "
    "server IPs), and implementation history. Before answering, search it for "
    "records relevant to this alert (e.g. the affected service or host) and let "
    "the closest matches inform your root cause. Add a third line citing your "
    "evidence:\n"
    "Evidence: <id or title of the most relevant knowledge record, or 'none found'>"
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

_RISK_NAME = "devops-commander-risk"
_RISK_TOOL = "assess_risk"
_RISK_INSTRUCTIONS = (
    "You are the risk and approval reviewer for a multi-cloud ERP (Azure + AWS). "
    "You are INDEPENDENT from whoever proposed the fix — never rubber-stamp it. "
    "Given a proposed fix and its command, judge how dangerous it is to run in "
    "production. Reply with exactly two short lines:\n"
    "Risk: <low|medium|high>\n"
    "Verdict: <auto-safe | needs-human>\n"
    "Treat anything destructive, stateful, data-affecting, restart/scaling, or "
    "production-impacting as needs-human. Only genuinely low-risk, read-only or "
    "trivially reversible actions may be auto-safe."
)

# --- Coordinator (the "main" agent the Function talks to) --------------------
_COORDINATOR_NAME = "devops-commander-coordinator"
_COORDINATOR_INSTRUCTIONS = (
    "You are DevOps Commander, the incident coordinator for a multi-cloud ERP. "
    "For each alert: (1) call diagnose_incident to get the root cause and "
    "severity, (2) call propose_remediation to get a safe fix for that "
    "diagnosis, (3) call assess_risk to get an INDEPENDENT risk review of that "
    "fix. Then compile ONE final report with exactly these lines:\n"
    "Root cause: ...\n"
    "Severity: <low|medium|high|critical>\n"
    "Evidence: <the knowledge record the diagnosis cited, or 'none'>\n"
    "Proposed fix: ...\n"
    "Command: ...\n"
    "Risk: <low|medium|high>\n"
    "Approval: <auto-safe | needs-human>\n"
    "Use the independent risk reviewer's verdict for the Approval line; if the "
    "reviewer and the remediation agent disagree, always choose the safer one "
    "(needs-human). Do not execute anything yourself. Be concise and concrete."
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


def _ensure_agent(name: str, instructions: str, tools=None, tool_resources=None) -> str:
    """Get-or-create an agent by name; return its id.

    Looking up by our well-known name keeps cold starts from piling up
    duplicate agents in the project. When the agent already exists it is
    updated in place so changes (new instructions, an attached knowledge tool)
    take effect without anyone deleting and recreating it by hand.
    """
    client = _client()
    for agent in client.agents.list_agents():
        if agent.name == name:
            try:
                client.agents.update_agent(
                    agent.id,
                    model=_model(),
                    instructions=instructions,
                    tools=tools or [],
                    tool_resources=tool_resources,
                )
            except Exception:
                logging.debug("agent_update_failed name=%s", name, exc_info=True)
            return agent.id
    created = client.agents.create_agent(
        model=_model(),
        name=name,
        instructions=instructions,
        tools=tools or [],
        tool_resources=tool_resources,
    )
    return created.id


def _search_tool():
    """Build the Azure AI Search knowledge tool, or None when RAG isn't configured.

    Requires a Foundry project connection (CONNECTION_ID) to the Search service
    and the index name. SIMPLE = keyword search, so no embeddings are needed.
    Absent these settings the diagnosis agent simply runs without grounding.
    """
    conn_id = os.environ.get("AZURE_AI_SEARCH_CONNECTION_ID")
    index = os.environ.get("AZURE_AI_SEARCH_INDEX")
    if not conn_id or not index:
        return None
    return AzureAISearchTool(
        index_connection_id=conn_id,
        index_name=index,
        query_type=AzureAISearchQueryType.SIMPLE,
        top_k=3,
    )


@lru_cache(maxsize=1)
def _coordinator_id() -> str:
    """Ensure the three specialists + the coordinator exist; return coordinator id.

    The coordinator is created with the specialists wired in as Connected Agent
    tools, so it can delegate to them by name at runtime.
    """
    search = _search_tool()
    if search is not None:
        diagnose_id = _ensure_agent(
            _DIAGNOSE_NAME,
            _DIAGNOSE_INSTRUCTIONS + _DIAGNOSE_RAG_SUFFIX,
            tools=search.definitions,
            tool_resources=search.resources,
        )
    else:
        diagnose_id = _ensure_agent(_DIAGNOSE_NAME, _DIAGNOSE_INSTRUCTIONS)
    remediation_id = _ensure_agent(_REMEDIATION_NAME, _REMEDIATION_INSTRUCTIONS)
    risk_id = _ensure_agent(_RISK_NAME, _RISK_INSTRUCTIONS)

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
    risk_tool = ConnectedAgentTool(
        id=risk_id,
        name=_RISK_TOOL,
        description="Independently review a proposed fix and command, rate its risk, and decide whether human approval is required before it may run.",
    )
    tools = (
        diagnose_tool.definitions
        + remediation_tool.definitions
        + risk_tool.definitions
    )
    return _ensure_agent(_COORDINATOR_NAME, _COORDINATOR_INSTRUCTIONS, tools=tools)


# A deterministic, code-side human-in-the-loop gate. The agents only advise;
# this function -- not the model -- decides whether a fix may run automatically.
# Any of these substrings in the proposed command marks it as sensitive.
_SENSITIVE_OPS = (
    "rm ", "rm -", "drop ", "delete", "truncate", "restart", "reboot",
    "kill", "stop ", "terminate", "scale", "rollout", "rollback",
    "failover", "shutdown", "systemctl", "format", "chmod", "chown",
)


def _enforce_gate(report: str) -> tuple[str, str]:
    """Deterministic human-in-the-loop gate -- code, not the model, has final say.

    Returns (decision, reason). HOLD means a human must approve before anything
    runs; AUTO-APPROVED means the action is low-risk and reversible. Because
    nothing is executed yet, this only classifies and records the decision -- but
    it is the same gate a later execution step will obey.
    """
    text = report.lower()
    # 1. If any agent already asked for a human, honor it unconditionally.
    if "needs-human" in text:
        return "HOLD", "an agent flagged the fix as needs-human"
    # 2. Independently scan the proposed command for sensitive operations.
    for op in _SENSITIVE_OPS:
        if op in text:
            return "HOLD", f"command contains a sensitive operation ('{op.strip()}')"
    # 3. High/critical incidents always get a human, even for a 'safe' command.
    if "severity: high" in text or "severity: critical" in text:
        return "HOLD", "high/critical severity requires human sign-off"
    return "AUTO-APPROVED", "low-risk, reversible action"


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

    The coordinator delegates to the diagnosis, remediation, and risk specialists
    and returns one combined report; a deterministic code gate then appends the
    final HOLD / AUTO-APPROVED decision. Best-effort: any error is logged and
    swallowed so the caller can still acknowledge the webhook.
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
            report = _extract_answer(messages)
            if report:
                # Code has the final say on whether a human is needed.
                decision, reason = _enforce_gate(report)
                report = f"{report}\nGate (enforced in code): {decision} — {reason}"
            return report
        finally:
            # One incident = one thread; clean it up so the project stays tidy.
            try:
                client.agents.threads.delete(thread.id)
            except Exception:
                logging.debug("thread_cleanup_failed", exc_info=True)
    except Exception:
        logging.exception("agent_rca_failed")
        return None
