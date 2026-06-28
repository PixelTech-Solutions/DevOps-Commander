"""DevOps Commander — agent fleet on the Foundry prompt-agent runtime.

Migrated from the classic Assistants/threads-runs agents (azure-ai-agents) to the
unified **prompt-agent runtime** (azure-ai-projects 2.x, Responses API) so the
fleet can ground its analysis in the team's existing observability through
**official remote MCP servers**:

  * Datadog (US5)  — metrics, monitors, logs, APM traces
  * Grafana Cloud  — dashboards, Prometheus/Loki queries, alert rules, incidents

Two prompt agents are referenced by name through the Responses API:

  * devops-commander-coordinator  — one-shot incident RCA for alerts
  * devops-commander-chat         — multi-turn ChatOps assistant

Both attach the Datadog + Grafana MCP servers (read-only) and, when configured,
the Azure AI Search knowledge tool (RAG). Auth to Foundry is keyless (the
Function App's user-assigned managed identity, Foundry User role); MCP auth is
supplied by Foundry "Custom keys" project connections referenced by name (the
service forbids inline headers) — no secret is committed or kept in app settings.

A deterministic CODE gate (``_enforce_gate``) — not the model — still has the
final say on whether a fix may proceed automatically. The destructive-action
approval flow lives entirely in ``bot.py`` / ``executor.py`` and is untouched by
this migration: the model proposes, the code disposes.

Why two single agents instead of the old connected-agent coordinator? The
prompt-agent runtime has no "connected agents as tools" primitive; the same
diagnose→remediate→assess reasoning is folded into one well-instructed agent
whose independent safety guarantee is provided by ``_enforce_gate`` in code.
"""

from __future__ import annotations

import json
import logging
import os
from functools import lru_cache

from azure.ai.projects import AIProjectClient
from azure.ai.projects.models import (
    FunctionTool,
    MCPTool,
    PromptAgentDefinition,
)
from azure.identity import DefaultAzureCredential

# --- Agent names (referenced by name through the Responses API) --------------
_COORDINATOR_NAME = "devops-commander-coordinator"
_CHAT_NAME = "devops-commander-chat"

# Cap on local function-tool round-trips per turn (guards against a tool loop).
_MAX_TOOL_ITERS = 5

# Azure subscription/tenant the agents should target, read from the environment
# (never hardcoded in source). When set, the agents are told the exact values so
# the model never invents a placeholder tenant/subscription; when unset they are
# told to use whatever the tools are already configured for.
_AZ_SUB = os.environ.get("AZURE_SUBSCRIPTION_ID", "").strip()
_AZ_TEN = os.environ.get("AZURE_TENANT_ID", "").strip()
if _AZ_SUB and _AZ_TEN:
    _AZ_TARGET = f"operate on subscription {_AZ_SUB} in tenant {_AZ_TEN}. "
elif _AZ_SUB:
    _AZ_TARGET = f"operate on subscription {_AZ_SUB}. "
else:
    _AZ_TARGET = (
        "operate only on the subscription and tenant the tools are already "
        "configured for. "
    )
_AZURE_TOOL_GUIDANCE = (
    "AZURE CONTEXT: when you call any Azure tool, " + _AZ_TARGET +
    "Only pass a tenant or subscription argument when the tool truly requires "
    "it, and then use exactly those real values — never invent or pass "
    "placeholders such as 'your-tenant-id' or 'your-subscription-id'.\n"
    "To inspect VMs: first list them (e.g. group_resource_list or "
    "compute_vm_get without instance-view), then for power state call the VM "
    "with a specific vm-name — the instance-view/power-state option only works "
    "for one named VM, never for a whole resource group at once.\n"
)

# --- Instructions ------------------------------------------------------------
_COORDINATOR_INSTRUCTIONS = (
    "You are DevOps Commander, the incident coordinator for a multi-cloud ERP "
    "(Azure + AWS). For each monitoring alert, produce ONE root-cause report.\n"
    "You have these live tools:\n"
    "- Datadog (read-only): infrastructure/host metrics, monitors, logs, traces.\n"
    "- Grafana Cloud (read-only): dashboards, Prometheus/Loki queries, alert "
    "rules, incidents.\n"
    "- Azure (manage): inventory, Azure Monitor metrics/logs, resource health, "
    "and management actions (start/stop/restart VMs, run commands, scale) for "
    "the Azure-hosted ERP servers.\n"
    "- AWS (manage): EC2/SSM/CloudWatch inventory plus management actions "
    "(start/stop/reboot instances, run commands, read logs/metrics) for the "
    "AWS-hosted ERP servers.\n"
    + _AZURE_TOOL_GUIDANCE +
    "When an Azure AI Search knowledge tool is available, it holds the ERP "
    "knowledge base: past incidents, runbooks, and the infrastructure inventory "
    "(environments, services, hosts and IPs).\n"
    "Before answering: query Datadog and/or Grafana for the affected service or "
    "host to ground your analysis in real telemetry, and search the knowledge "
    "base for relevant prior incidents or runbooks. If the alert includes a "
    "'Live telemetry' line, treat it as primary evidence. Keep Datadog and "
    "Grafana read-only (never modify dashboards, monitors, or alerts). You MAY "
    "use the Azure and AWS tools to investigate and to carry out remediation, "
    "but anything destructive, stateful, data-affecting, or production-impacting "
    "must be marked needs-human and not auto-run.\n"
    "Then compile ONE report with exactly these lines:\n"
    "Root cause: <one sentence>\n"
    "Severity: <low|medium|high|critical>\n"
    "Evidence: <the Datadog/Grafana signal or knowledge record you relied on, or 'none'>\n"
    "Proposed fix: <one sentence>\n"
    "Command: <the single command or playbook step to run>\n"
    "Risk: <low|medium|high>\n"
    "Approval: <auto-safe | needs-human>\n"
    "VERIFY BEFORE YOU CONCLUDE — never guess. In order: (1) identify the "
    "affected host(s) from the alert; (2) establish whether each host is "
    "actually UP before anything else. If the alert includes a 'Ground truth' "
    "power-state line, it is AUTHORITATIVE — a VM that is deallocated/stopped "
    "means the host is DOWN. Otherwise check whether the host's series is still "
    "reporting in Grafana/Prometheus (absent()/up) and whether the service is "
    "running; (3) only once liveness is settled, read the relevant metrics/logs "
    "and search the knowledge base for the runbook.\n"
    "MISSING DATA IS NOT HEALTHY: empty results, 'no data', or a series that has "
    "stopped reporting for an alerting host means the host is most likely DOWN "
    "(an outage) — raise severity, never report it as low or resolved. An alert "
    "query that uses absent() reporting 100 means the host VANISHED, not that "
    "memory is high. Never propose a fix that contradicts the ground truth (e.g. "
    "do not say 'restart node_exporter' when the whole VM is deallocated — the "
    "fix is to start the VM). If you cannot positively verify the state, say so "
    "and make the Command the concrete verification step rather than a guess.\n"
    "Treat anything destructive, stateful, data-affecting, restart/scaling, or "
    "production-impacting as needs-human and never auto-approve it. Do not "
    "execute remediation yourself. Be concise and concrete."
)

_CHAT_INSTRUCTIONS = (
    "You are DevOps Commander, a conversational ChatOps assistant for a "
    "multi-cloud ERP (Azure + AWS) that spans development and production. A "
    "human engineer talks to you in plain language about the systems.\n"
    "You have live observability and management tools:\n"
    "- Datadog (read-only): infrastructure/host metrics, monitors, logs, traces.\n"
    "- Grafana Cloud (read-only): dashboards, Prometheus/Loki queries, alert "
    "rules, incidents.\n"
    "- Azure (manage): resource inventory, Azure Monitor metrics/logs, resource "
    "health, and management operations (start/stop/restart VMs, run commands, "
    "scale, config) for the Azure-hosted ERP servers.\n"
    "- AWS (manage): EC2/SSM/CloudWatch inventory and management (start/stop/"
    "reboot instances, run commands, read logs/metrics) for the AWS-hosted ERP "
    "servers.\n"
    + _AZURE_TOOL_GUIDANCE +
    "When an Azure AI Search knowledge tool is available, it holds the ERP "
    "knowledge base: the infrastructure inventory (every environment, service, "
    "host and IP), past incidents, and implementation history.\n"
    "For ANY question about system health or 'why is X slow/down/erroring', "
    "query Datadog and/or Grafana for the relevant service or host and ground "
    "your answer in what you actually observe. For factual questions about the "
    "systems (hosts, IPs, what runs where, prior incidents), search the "
    "knowledge base FIRST and cite the record; if it genuinely has no answer, "
    "say so plainly instead of guessing. Keep Datadog and Grafana read-only "
    "(never modify dashboards, monitors, or alerts). You MAY use the Azure and "
    "AWS tools to manage the servers (start/stop/restart, run commands) when the "
    "user asks; for destructive or production-impacting actions, confirm intent "
    "and route through the approval gate first.\n"
    "You can ALSO run a small set of READ-ONLY actions against the DEVELOPMENT "
    "environment directly via your tools: count customers, list customers, look "
    "up one customer by id, check whether the erp-backend service is running, "
    "read recent app logs, check disk usage, read an Azure Monitor VM metric "
    "trend (dev_vm_metric), and run a read-only KQL query over operational "
    "telemetry (query_dev_telemetry). When the user asks to SEE or FETCH live "
    "dev data, CALL the matching tool and report the real result — do not just "
    "explain how, and do not ask for database credentials (the tools run safely "
    "on the dev VM with no secrets exposed).\n"
    "You CANNOT run destructive actions (deleting a customer, restarting a "
    "service) and you CANNOT touch PRODUCTION. If the user asks for either, "
    "explain exactly what the action would be, which environment and host it "
    "targets, and that it must go through the approval gate (a human approves "
    "before anything runs). Never claim to have performed a destructive or "
    "production action.\n"
    "CRITICAL — missing data is NOT healthy. Empty query results, 'no data', a "
    "metric that stops reporting, or a host/series that has disappeared do NOT "
    "mean an incident is resolved. For a host that was just alerting, absent "
    "metrics most likely mean the host is DOWN or unreachable — an outage, which "
    "is MORE severe, not fixed. Only state that an incident is resolved when you "
    "have POSITIVE evidence: a recent metric value that is back inside the normal "
    "range, and cite the value and time. If telemetry is unavailable or empty, "
    "say so explicitly ('I could not retrieve current metrics for <host> — it may "
    "be down'), verify the specific alerting host (e.g. query whether its series "
    "still reports in Grafana/Prometheus), and recommend the next concrete check. "
    "Never infer health from silence. Be concise, friendly, and concrete."
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


# --- Tools -------------------------------------------------------------------
def _mcp_tools() -> list:
    """Build the Datadog + Grafana MCP tools from app settings.

    Each MCP server is the vendor's official remote endpoint. Auth is supplied
    by a Foundry "Custom keys" project connection referenced by name via
    ``project_connection_id`` (the service injects the connection's key/value
    pairs as request headers and forbids inline ``headers``), so no secret is
    committed or placed in app settings. A server is attached only when both its
    URL and connection name are present, so the fleet degrades gracefully to
    base reasoning when observability isn't configured. Datadog and Grafana are
    observability (read-only); the Azure and AWS servers are management-capable
    (their connection identity carries whatever write scope the server allows).
    ``require_approval='never'`` lets calls flow without a human round-trip.
    """
    tools: list = []

    dd_url = os.environ.get("DATADOG_MCP_URL")
    dd_conn = os.environ.get("DATADOG_MCP_CONNECTION", "datadog-mcp")
    if dd_url and dd_conn:
        tools.append(
            MCPTool(
                server_label="datadog",
                server_url=dd_url,
                server_description=(
                    "Datadog observability (read-only): host/infra metrics, "
                    "monitors, logs, and APM traces."
                ),
                project_connection_id=dd_conn,
                require_approval="never",
            )
        )

    # Accept either the full MCP URL or just the stack base URL.
    g_url = os.environ.get("GRAFANA_MCP_URL")
    if not g_url:
        base = os.environ.get("GRAFANA_URL")
        if base:
            g_url = base.rstrip("/") + "/api/mcp"
    g_conn = os.environ.get("GRAFANA_MCP_CONNECTION", "grafana-mcp")
    if g_url and g_conn:
        tools.append(
            MCPTool(
                server_label="grafana",
                server_url=g_url,
                server_description=(
                    "Grafana Cloud (read-only): dashboards, Prometheus/Loki "
                    "queries, alert rules, and incidents."
                ),
                project_connection_id=g_conn,
                require_approval="never",
            )
        )

    # Azure MCP (manage): Azure control-plane operations for the Azure-hosted
    # ERP — resource inventory, Azure Monitor metrics & logs, resource health,
    # AND management actions (start/stop/restart VMs, run commands, scale,
    # config). Remote endpoint + an optional Custom-keys connection whose
    # identity carries the write RBAC the server is allowed to use. The
    # connection is opt-in: leave AZURE_MCP_CONNECTION unset (or empty) for a
    # no-auth host; set it to a connection name to attach credentials.
    az_url = os.environ.get("AZURE_MCP_URL")
    if az_url:
        az_kwargs = {
            "server_label": "azure",
            "server_url": az_url,
            "server_description": (
                "Azure (manage): resource inventory, Azure Monitor metrics/logs, "
                "resource health, and management operations — start/stop/restart "
                "VMs, run commands, scale, and update config — for the "
                "Azure-hosted ERP."
            ),
            "require_approval": "never",
        }
        az_conn = os.environ.get("AZURE_MCP_CONNECTION", "")
        if az_conn:
            az_kwargs["project_connection_id"] = az_conn
        tools.append(MCPTool(**az_kwargs))

    # AWS MCP (manage): the AWS-managed remote MCP (IAM-scoped, CloudTrail-
    # audited) covering the AWS half of the ERP (e.g. erp-aws-app-server-dev)
    # that Azure tools can't see — EC2/SSM/CloudWatch inventory AND management
    # (start/stop/reboot instances, run commands, read logs/metrics). Same
    # remote pattern; leave AWS_MCP_CONNECTION unset for a no-auth endpoint.
    aws_url = os.environ.get("AWS_MCP_URL")
    if aws_url:
        aws_kwargs = {
            "server_label": "aws",
            "server_url": aws_url,
            "server_description": (
                "AWS (manage): EC2/SSM/CloudWatch inventory and management — "
                "start/stop/reboot instances, run commands, and read "
                "logs/metrics — for the AWS-hosted ERP servers."
            ),
            "require_approval": "never",
        }
        aws_conn = os.environ.get("AWS_MCP_CONNECTION", "")
        if aws_conn:
            aws_kwargs["project_connection_id"] = aws_conn
        tools.append(MCPTool(**aws_kwargs))

    return tools


def _search_tool():
    """Build the Azure AI Search knowledge tool, or None when RAG isn't configured.

    The prompt-agent service requires ``project_connection_id`` + ``index_name``
    (the typed ``AzureAISearchTool`` model serializes ``connectionName``, which
    the service rejects), so the tool is emitted as a plain dict. Best-effort:
    a missing index/connection simply drops grounding rather than breaking the
    agent.
    """
    index = os.environ.get("AZURE_AI_SEARCH_INDEX")
    conn_id = os.environ.get("AZURE_AI_SEARCH_CONNECTION_ID")
    if not index or not conn_id:
        return None
    # The erp-knowledge index is keyword-only (no vector field/vectorizer), so
    # pin query_type to "simple". The prompt-agent runtime otherwise defaults to
    # vector_semantic_hybrid, which 400s on a non-vectorized index. Override via
    # AZURE_AI_SEARCH_QUERY_TYPE if a vectorizer is ever added.
    query_type = os.environ.get("AZURE_AI_SEARCH_QUERY_TYPE", "simple")
    return {
        "type": "azure_ai_search",
        "azure_ai_search": {
            "indexes": [
                {
                    "project_connection_id": conn_id,
                    "index_name": index,
                    "query_type": query_type,
                }
            ]
        },
    }


# --- Dev read-only action tools (ChatOps live data) --------------------------
# These wrap the dev-only executor and the observability module and are exposed
# to the CHAT agent as function tools. Only NON-destructive actions are exposed;
# destructive ones still go through the signed approval gate in bot.py and are
# never callable from chat. The prompt-agent runtime has no auto-runner, so the
# response loop in `_respond` executes these locally and feeds the results back.
def _dev_action(action: str, params: dict | None = None) -> str:
    import executor

    try:
        result = executor.run_action(action, "dev", params or {})
    except executor.ActionError as exc:
        return f"Could not run {action} on dev: {exc}"
    except Exception:
        logging.exception("chat_dev_action_failed %s", action)
        return f"Could not run {action} on dev: an internal error occurred."
    return str(result.get("output", "")).strip() or "(no output)"


def count_dev_customers() -> str:
    return _dev_action("count_customers")


def list_dev_customers(limit: int = 10) -> str:
    return _dev_action("list_customers", {"limit": limit})


def get_dev_customer(customer_id: int) -> str:
    return _dev_action("get_customer", {"id": customer_id})


def dev_service_status() -> str:
    return _dev_action("service_status")


def dev_recent_app_logs(lines: int = 30) -> str:
    return _dev_action("recent_app_logs", {"lines": lines})


def dev_disk_usage() -> str:
    return _dev_action("disk_usage")


def dev_vm_metric(metric: str = "cpu", host: str = "app", hours: int = 1) -> str:
    import observability

    if not observability.is_enabled():
        return "Live metrics are not configured."
    try:
        return observability.vm_metric(host, metric, hours)
    except Exception as exc:  # noqa: BLE001
        return f"Could not read the '{metric}' metric for dev {host}: {exc}"


def query_dev_telemetry(kql: str, hours: int = 1) -> str:
    import observability

    if not observability.is_enabled():
        return "Live telemetry is not configured."
    try:
        return observability.query_telemetry(kql, hours)
    except Exception as exc:  # noqa: BLE001
        return f"Could not run the telemetry query: {exc}"


_TOOL_DISPATCH = {
    "count_dev_customers": count_dev_customers,
    "list_dev_customers": list_dev_customers,
    "get_dev_customer": get_dev_customer,
    "dev_service_status": dev_service_status,
    "dev_recent_app_logs": dev_recent_app_logs,
    "dev_disk_usage": dev_disk_usage,
    "dev_vm_metric": dev_vm_metric,
    "query_dev_telemetry": query_dev_telemetry,
}


def _dispatch_tool(name: str, arguments: str) -> str:
    """Execute one local function tool call and return its text result."""
    fn = _TOOL_DISPATCH.get(name)
    if fn is None:
        return f"Unknown tool: {name}"
    try:
        kwargs = json.loads(arguments) if arguments else {}
    except Exception:
        kwargs = {}
    try:
        return str(fn(**kwargs))
    except TypeError as exc:
        return f"Bad arguments for {name}: {exc}"
    except Exception:
        logging.exception("tool_failed %s", name)
        return f"Tool {name} failed."


def _obj(props: dict | None = None, required: list | None = None) -> dict:
    return {"type": "object", "properties": props or {}, "required": required or []}


def _dev_function_tools() -> list:
    """FunctionTool definitions for the dev read-only actions, or [] when the
    executor isn't configured to reach Azure."""
    try:
        import executor

        if not executor.is_enabled():
            return []
    except Exception:
        return []
    return [
        FunctionTool(
            name="count_dev_customers",
            description="Count the rows in the development ERP customers table.",
            parameters=_obj(),
        ),
        FunctionTool(
            name="list_dev_customers",
            description="List customers from the development ERP database.",
            parameters=_obj({"limit": {"type": "integer", "description": "How many customers to return (1-50). Default 10."}}),
        ),
        FunctionTool(
            name="get_dev_customer",
            description="Show one development ERP customer by id.",
            parameters=_obj({"customer_id": {"type": "integer", "description": "The customer id to look up (>= 1)."}}, ["customer_id"]),
        ),
        FunctionTool(
            name="dev_service_status",
            description="Show whether the erp-backend service is running on the dev app server.",
            parameters=_obj(),
        ),
        FunctionTool(
            name="dev_recent_app_logs",
            description="Show recent erp-backend logs from the dev app server.",
            parameters=_obj({"lines": {"type": "integer", "description": "How many log lines to return (1-200). Default 30."}}),
        ),
        FunctionTool(
            name="dev_disk_usage",
            description="Show root filesystem disk usage on the dev app server.",
            parameters=_obj(),
        ),
        FunctionTool(
            name="dev_vm_metric",
            description="Show an Azure Monitor metric trend (avg/peak/latest) for a dev ERP VM.",
            parameters=_obj({
                "metric": {"type": "string", "description": "cpu | network in | network out | disk read | disk write. Default cpu."},
                "host": {"type": "string", "description": "Which dev VM: 'app' (erp-backend) or 'db' (MySQL). Default app."},
                "hours": {"type": "integer", "description": "Hours back to summarize (1-24). Default 1."},
            }),
        ),
        FunctionTool(
            name="query_dev_telemetry",
            description="Run a read-only Kusto (KQL) query over operational telemetry (incidents handled, executor actions) recorded in Application Insights.",
            parameters=_obj({
                "kql": {"type": "string", "description": "The Kusto query to run, e.g. 'traces | take 5'."},
                "hours": {"type": "integer", "description": "Time window in hours (1-24). Default 1."},
            }, ["kql"]),
        ),
    ]


@lru_cache(maxsize=1)
def _ensure_agents() -> bool:
    """Create-or-update the coordinator and chat agents once per worker process.

    ``create_version`` records a new version each call; caching keeps a cold
    start from minting more than one version per agent. Agents are referenced by
    name at invoke time, which always resolves to the latest version, so new
    instructions or tools take effect on the next cold start.
    """
    client = _client()
    base = _mcp_tools()
    search = _search_tool()
    if search is not None:
        base = base + [search]

    client.agents.create_version(
        _COORDINATOR_NAME,
        definition=PromptAgentDefinition(
            model=_model(),
            instructions=_COORDINATOR_INSTRUCTIONS,
            tools=base,
        ),
    )
    # The chat agent also gets the dev read-only action tools (executed locally
    # by the response loop), so ChatOps can fetch live dev data conversationally.
    client.agents.create_version(
        _CHAT_NAME,
        definition=PromptAgentDefinition(
            model=_model(),
            instructions=_CHAT_INSTRUCTIONS,
            tools=base + _dev_function_tools(),
        ),
    )
    return True


# --- Responses API invocation ------------------------------------------------
def _resp_text(resp) -> str:
    """Extract the assistant's text from a Responses API result."""
    text = getattr(resp, "output_text", None)
    if text:
        return text.strip()
    parts: list[str] = []
    for item in getattr(resp, "output", None) or []:
        if getattr(item, "type", None) != "message":
            continue
        for content in getattr(item, "content", None) or []:
            value = getattr(content, "text", None)
            if isinstance(value, str):
                parts.append(value)
            elif value is not None and hasattr(value, "value"):
                parts.append(value.value)
    return "\n".join(parts).strip()


def _respond(agent_name: str, message: str, conversation_id: str | None = None):
    """Run one turn against a named agent; return (reply_text, conversation_id).

    A conversation id carries multi-turn memory server-side; when the caller
    supplies one we reuse it. If a supplied conversation has gone stale (e.g.
    across a redeploy), we retry once on a fresh conversation so a chat never
    dies on a dangling id.
    """
    client = _client()
    _ensure_agents()
    oc = client.get_openai_client()
    agent_ref = {"agent_reference": {"name": agent_name, "type": "agent_reference"}}

    def _run(conv_id: str) -> str:
        resp = oc.responses.create(
            conversation=conv_id,
            extra_body=agent_ref,
            input=message,
        )
        # The runtime executes MCP/Search server-side, but local dev function
        # tools run here: drive any function calls to completion before reading
        # the final text. Capped so a tool loop can never spin forever.
        for _ in range(_MAX_TOOL_ITERS):
            calls = [
                it
                for it in (getattr(resp, "output", None) or [])
                if getattr(it, "type", None) == "function_call"
            ]
            if not calls:
                break
            outputs = [
                {
                    "type": "function_call_output",
                    "call_id": getattr(call, "call_id", None),
                    "output": _dispatch_tool(
                        getattr(call, "name", ""), getattr(call, "arguments", "")
                    ),
                }
                for call in calls
            ]
            resp = oc.responses.create(
                conversation=conv_id, extra_body=agent_ref, input=outputs
            )
        return _resp_text(resp)

    if conversation_id:
        try:
            return _run(conversation_id), conversation_id
        except Exception:
            logging.warning("chat_conversation_stale; starting a fresh one", exc_info=True)

    conv_id = oc.conversations.create().id
    return _run(conv_id), conv_id


# --- Deterministic human-in-the-loop gate (code, not the model, decides) -----
# Any of these substrings in the proposed command marks it as sensitive.
_SENSITIVE_OPS = (
    "rm ", "rm -", "drop ", "delete", "truncate", "restart", "reboot",
    "kill", "stop ", "terminate", "scale", "rollout", "rollback",
    "failover", "shutdown", "systemctl", "format", "chmod", "chown",
)


def _enforce_gate(report: str) -> tuple[str, str]:
    """Deterministic human-in-the-loop gate — code, not the model, has final say.

    Returns (decision, reason). HOLD means a human must approve before anything
    runs; AUTO-APPROVED means the action is low-risk and reversible. Nothing is
    executed here — it classifies and records the decision, the same gate a
    later execution step obeys.
    """
    text = report.lower()
    if "needs-human" in text:
        return "HOLD", "an agent flagged the fix as needs-human"
    for op in _SENSITIVE_OPS:
        if op in text:
            return "HOLD", f"command contains a sensitive operation ('{op.strip()}')"
    if "severity: high" in text or "severity: critical" in text:
        return "HOLD", "high/critical severity requires human sign-off"
    return "AUTO-APPROVED", "low-risk, reversible action"


def _build_user_message(event: dict) -> str:
    source = event.get("source", "unknown")
    payload = event.get("payload")
    body = json.dumps(payload, default=str)[:4000]
    return f"Alert source: {source}\nAlert payload:\n{body}"


def _fallback_report(event: dict) -> str:
    """A minimal, gate-able report used when the RCA agent cannot complete.

    A human notification must never depend on a flawless agent run (a single
    failing telemetry tool returns a 400 that aborts the whole response). When
    that happens we forward the raw alert flagged needs-human so the gate holds
    and a person still gets emailed.
    """
    source = str(event.get("source") or "alert")
    summary = json.dumps(event.get("payload"), default=str)[:1500]
    return (
        "Root cause: Automated RCA was unavailable for this alert (the analysis "
        "agent could not complete — e.g. a telemetry tool returned an error), so "
        "the raw alert is forwarded for human review.\n"
        "Severity: Unknown\n"
        f"Evidence: {source} alert payload: {summary}\n"
        "Proposed fix: A human should inspect the affected host(s) directly. "
        "Missing telemetry may mean the host is DOWN, not healthy.\n"
        "Risk: Unknown\n"
        "Approval: Needs-human"
    )


# --- Public interface (unchanged for function_app.py / bot.py) ---------------
def analyze_alert(event: dict) -> str | None:
    """Run the coordinator over an alert and return its compiled report, or None.

    The coordinator grounds its analysis in live Datadog/Grafana telemetry and
    the knowledge base, then a deterministic code gate appends the final
    HOLD / AUTO-APPROVED decision. Best-effort: any error is logged and
    swallowed so the caller can still acknowledge the webhook.
    """
    try:
        content = _build_user_message(event)
        # Enrich with a fast live-telemetry snapshot so the diagnosis is grounded
        # even before the agent reaches for its MCP tools. Best-effort only.
        try:
            import observability

            telemetry = observability.incident_context("app", 1)
            if telemetry:
                content = f"{content}\n\n{telemetry}"
        except Exception:
            logging.debug("alert_enrich_failed", exc_info=True)

        # The agent grounds RCA in live telemetry, but a single failing MCP
        # tool returns a 400 that aborts the whole response. A human must still
        # be notified, so on any agent error we fall back to the raw alert.
        try:
            report, _ = _respond(_COORDINATOR_NAME, content)
        except Exception:
            logging.exception("agent_rca_failed")
            report = _fallback_report(event)

        if report:
            decision, reason = _enforce_gate(report)
            report = f"{report}\nGate (enforced in code): {decision} — {reason}"
            # Tell a human out of band (email + best-effort Teams), carrying
            # Approve/Reject controls when the gate holds. Best-effort only.
            try:
                import notifier

                notifier.notify_alert(report, decision, reason, str(event.get("source") or "alert"))
            except Exception:
                logging.exception("alert_notify_failed")
        return report or None
    except Exception:
        logging.exception("agent_rca_failed")
        return None


def analyze_chat(message: str, conversation_id: str | None = None) -> dict | None:
    """Run the conversational ChatOps agent over a human message.

    Multi-turn: the caller passes back the ``conversation_id`` we return to keep
    the same Foundry conversation (and its memory). Returns
    ``{"reply": str, "conversation_id": str}`` or ``None`` on hard failure.
    """
    try:
        reply, conv_id = _respond(_CHAT_NAME, (message or "")[:4000], conversation_id)
        return {"reply": reply or "(no reply)", "conversation_id": conv_id}
    except Exception:
        logging.exception("agent_chat_failed")
        return None
