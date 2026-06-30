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

import contextvars
import json
import logging
import os
import re
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
_PIPELINE_NAME = "devops-commander-pipeline"

# Cap on local function-tool round-trips per turn (guards against a tool loop).
_MAX_TOOL_ITERS = 5

# A single server-side MCP tool error (bad arg syntax, 404, etc.) returns a 400
# that aborts the whole Responses run. Rather than collapse to a fallback, we
# re-run telling the agent which tool failed and why, so it self-corrects.
_MAX_RCA_RETRIES = 4
# Matches the runtime's "An error occurred invoking 'tool_name': ..." messages.
_TOOL_ERR_RE = re.compile(r"invoking '([^']+)'\s*:?\s*(.*)", re.DOTALL)

# When a chat turn proposes a destructive cloud action, the function tool stores
# the executor's signed approval request here so ``analyze_chat`` can hand it to
# the bot, which renders the Approve/Reject card. Nothing has run at that point.
_pending_approval: contextvars.ContextVar = contextvars.ContextVar(
    "pending_approval", default=None
)

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
    "When querying Azure Monitor metrics, ALWAYS use a RECENT window: the last "
    "1-6 hours up to now. NEVER hardcode old dates (e.g. 2023) — metrics older "
    "than ~93 days are out of retention and return 400. Pass times as ISO 8601 "
    "UTC timestamps (e.g. 2025-01-01T12:00:00Z) computed relative to now — NEVER "
    "relative strings like 'now-1h' (Azure MCP rejects them). Metrics are "
    "OPTIONAL; the authoritative up/down check is compute_vm_get instance-view.\n"
    "NEVER conclude a host is 'down/deallocated' from absent telemetry alone — "
    "that is a guess. CONFIRM with compute_vm_get instance-view for the mapped VM "
    "first. If it reports 'VM running', the host is UP: the issue is the "
    "monitoring agent / metric pipeline (recommend restarting the agent), NOT a "
    "VM outage. Only call a VM down when instance-view actually shows stopped/"
    "deallocated. Cite the power state you observed.\n"
)

# Alerts label hosts by a friendly DNS-style name; the cloud resources have
# different names. Map them so the agent never guesses a resource group/VM and
# 404s. Used as grounding context only — investigation still drives the call.
_FLEET_INVENTORY = (
    "ERP FLEET (alert host label -> cloud resource): "
    "erp-azure-app-server-dev = Azure VM 'vm-erp-dev-app' in RG 'RG-ERP-DEV'; "
    "erp-azure-db-server-dev = Azure VM 'vm-erp-dev-db' in RG 'RG-ERP-DEV'; "
    "erp-azure-app-server-prod = Azure VM 'vm-erp-prod-app' in RG 'RG-ERP-PROD'; "
    "erp-azure-db-server-prod = Azure VM 'vm-erp-prod-db' in RG 'RG-ERP-PROD'; "
    "erp-aws-app-server-dev = AWS EC2 i-083032133276a6d9f; "
    "erp-aws-db-server-dev = AWS EC2 i-079e547101bf680a2; "
    "erp-aws-app-server-prod = AWS EC2 i-0b0e764b1a8718155; "
    "erp-aws-db-server-prod = AWS EC2 i-0fb4424824abf1893. "
    "Use exactly these names/RGs; do not invent resource-group names. If a host "
    "label is missing above, list resources first, never guess.\n"
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
    + _AZURE_TOOL_GUIDANCE + _FLEET_INVENTORY +
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
    "INVESTIGATE THE REAL CAUSE — never guess and never stop at the first "
    "plausible answer. Identify the affected host(s), then enumerate ALL "
    "candidate causes and rule them in or out with read-only evidence before "
    "concluding. Use every tool you have: Grafana/Datadog for CPU, memory, disk, "
    "I/O, network, OOM kills, swap, restarts and the absent()/up series; Azure "
    "Monitor/AWS CloudWatch for power state, health, deployments and quota; the "
    "knowledge base for prior incidents and runbooks; and read-only remote "
    "commands (Azure VM run-command / AWS SSM) for ground truth on the host — "
    "service status, recent logs, disk usage, top processes, recent config or "
    "package changes. Consider the full range: host down, agent/exporter crash, "
    "genuine resource exhaustion (mem/disk/CPU), OOM, a dependency or network "
    "outage, a bad deploy/config change, throttling, certificate/auth failure. "
    "Branch your checks on what each command returns; keep digging until the "
    "evidence points to one cause. Read-only diagnostics auto-approve; only the "
    "final remediation is needs-human. If the data is genuinely insufficient, "
    "say so and make the Command the next read-only step, not a fix.\n"
    "MISSING DATA IS NOT HEALTHY: empty results, 'no data', or a series that has "
    "stopped reporting for an alerting host means the host is most likely DOWN "
    "(an outage) — raise severity, never report it as low or resolved. An alert "
    "query that uses absent() reporting 100 means the host VANISHED, not that "
    "memory is high. Never propose a fix that contradicts the evidence (e.g. "
    "do not say 'restart node_exporter' when the whole VM is deallocated — the "
    "fix is to start the VM).\n"
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
    "- Azure (read-only): resource inventory, Azure Monitor metrics/logs, and "
    "resource health for the Azure-hosted ERP servers. Observation only.\n"
    "- AWS (read-only): EC2/SSM/CloudWatch inventory, instance status, logs and "
    "metrics for the AWS-hosted ERP servers. Observation only.\n"
    + _AZURE_TOOL_GUIDANCE + _FLEET_INVENTORY +
    "When an Azure AI Search knowledge tool is available, it holds the ERP "
    "knowledge base: the infrastructure inventory (every environment, service, "
    "host and IP), past incidents, and implementation history.\n"
    "For ANY question about system health or 'why is X slow/down/erroring', "
    "query Datadog and/or Grafana for the relevant service or host and ground "
    "your answer in what you actually observe. For factual questions about the "
    "systems (hosts, IPs, what runs where, prior incidents), search the "
    "knowledge base FIRST and cite the record; if it genuinely has no answer, "
    "say so plainly instead of guessing. Your observability tools (Datadog, "
    "Grafana, Azure, AWS) are READ-ONLY: never modify dashboards, monitors, "
    "alerts, or cloud resources through them.\n"
    "You can ALSO run a small set of READ-ONLY actions against the DEVELOPMENT "
    "environment directly via your tools: count customers, list customers, look "
    "up one customer by id, check whether the erp-backend service is running, "
    "read recent app logs, check disk usage, read an Azure Monitor VM metric "
    "trend (dev_vm_metric), and run a read-only KQL query over operational "
    "telemetry (query_dev_telemetry). When the user asks to SEE or FETCH live "
    "dev data, CALL the matching tool and report the real result — do not just "
    "explain how, and do not ask for database credentials (the tools run safely "
    "on the dev VM with no secrets exposed).\n"
    "For DEVELOPMENT AWS EC2 power changes you have dedicated tools: start_ec2 "
    "(starts a stopped dev instance immediately), and stop_ec2 / reboot_ec2 "
    "(DESTRUCTIVE — each returns an approval request and shows the user an "
    "Approve/Reject card; they do NOT act until a human clicks Approve). These "
    "tools require the REAL EC2 instance id (format i-0123456789abcdef0). When "
    "the user refers to an instance by role or name (e.g. 'the dev db'), FIRST "
    "call list_dev_ec2 to get the real instance id and current state \u2014 never "
    "pass a monitoring label, hostname, or knowledge-base nickname as the "
    "instance id, and do not guess Name tags. When the user asks "
    "to stop or reboot a dev instance, CALL the tool with that id, then tell the "
    "user an approval card is shown and they must click Approve. NEVER say the "
    "instance was stopped or rebooted until it actually is.\n"
    "For DEVELOPMENT Azure VM power changes you have dedicated tools: start_vm "
    "(start a stopped/deallocated dev VM to restore service), stop_vm "
    "(deallocate a dev VM) and restart_vm. ALL THREE are gated: each returns an "
    "approval request and shows the user an Approve/Reject card; they do NOT act "
    "until a human clicks Approve. The managed dev VMs are vm-erp-dev-app and "
    "vm-erp-dev-db. When the user refers to a VM by role or host label (e.g. "
    "'the dev app server' / 'erp-azure-app-server-dev'), use the mapping above "
    "to resolve the real VM name, or call list_dev_vms to confirm the name and "
    "current power state first. When an incident is caused by a deallocated/"
    "stopped Azure VM and the fix is to start it, CALL start_vm with that VM "
    "name, then tell the user an approval card is shown and they must click "
    "Approve. NEVER say the VM was started, stopped, or restarted until it "
    "actually is.\n"
    "Destructive actions (deleting a customer, restarting a service, stopping or "
    "rebooting an EC2 instance) ALWAYS require human approval, and you can NEVER "
    "touch PRODUCTION — only the development environment, and only the two known "
    "dev EC2 instances. If asked for a production change, refuse and explain it "
    "is blocked in code. Never claim to have performed a destructive or "
    "production action that has not been approved and executed.\n"
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

# Pipeline-triage agent: diagnoses a failed GitHub Actions run and proposes a
# concrete, minimal fix. It reads the failing run with the GitHub MCP (logs +
# the offending file) and returns BOTH a human report and a machine-readable
# fix block. It NEVER writes — branch/commit/PR/re-run happen later in code,
# behind the approval gate.
_PIPELINE_INSTRUCTIONS = (
    "You are DevOps Commander's CI/CD triage engineer. A GitHub Actions "
    "pipeline has FAILED. Find the EXACT reason and propose a minimal, "
    "high-confidence fix.\n"
    "You have a read-only GitHub MCP tool. Investigate the failed run that the "
    "message identifies (use its repository and run id):\n"
    "IMPORTANT: the number you are given is a GitHub ACTIONS WORKFLOW RUN ID — "
    "it is NOT a pull request number and NOT an issue number. NEVER call any "
    "pull-request or issue tool (e.g. pull_request_read / get_pull_request); "
    "they will 404 on a run id. Use ONLY the Actions and repository-contents "
    "tools.\n"
    "1. Get the workflow RUN by its run id, then LIST THE JOBS for that run, "
    "then fetch the LOGS of the FAILED job/step (request failed jobs only if the "
    "tool supports it). Read the actual error lines — do not guess.\n"
    "2. Identify the single root cause (e.g. a YAML syntax error, a bad action "
    "version, a missing input/secret/variable, a failing shell command, a "
    "dependency/version conflict, a lint/test failure).\n"
    "3. Fetch the current contents of the file that must change (usually a "
    "workflow file under .github/workflows/, or a build/config file) with the "
    "repository file-contents tool so your fix is based on the real, current "
    "text.\n"
    "4. Produce the corrected, COMPLETE file content for each file you change.\n\n"
    "Output EXACTLY two parts, in this order:\n"
    "PART 1 \u2014 a human report with these labelled lines (one per line):\n"
    "Root cause: <the precise reason the run failed, citing the error>\n"
    "Severity: <low|medium|high>\n"
    "Evidence: <the exact log line(s)/error you saw, and the run id>\n"
    "Proposed fix: <plain-English description of the change>\n"
    "Command: <the file(s) being changed, e.g. edit .github/workflows/deploy.yml>\n"
    "Risk: <low|medium|high>\n"
    "Approval: needs-human\n\n"
    "PART 2 \u2014 a single fenced JSON code block (```json ... ```) with the "
    "machine-applicable fix, of the form:\n"
    '{\"summary\": \"<one-line PR title>\", \"base_branch\": \"<the branch the run '
    'failed on>\", \"files\": [{\"path\": \"<repo-relative path>\", \"content\": '
    '\"<the FULL new file content>\"}]}\n'
    "Rules for PART 2: include every file you change with its ENTIRE new content "
    "(not a diff, not a snippet); keep the change minimal and surgical; only "
    "touch files needed to fix THIS failure; never include secrets. If you "
    "genuinely cannot determine a safe fix, set \"files\" to an empty list and "
    "explain why in the report \u2014 do NOT invent a change.\n"
    "Always end with Approval: needs-human \u2014 a human approves before anything "
    "is committed."
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

    # GitHub MCP (READ-ONLY): the official remote GitHub MCP server, used to
    # triage CI/CD failures — read workflow runs, job logs and file contents to
    # find the EXACT reason a pipeline failed. The endpoint is the read-only
    # variant (.../mcp/readonly) and the connection's PAT is read-scoped, so the
    # model can inspect but never mutate a repo. All writes (branch, commit, PR,
    # re-run) happen later in executor.py behind the human approval gate.
    gh_url = os.environ.get("GITHUB_MCP_URL")
    gh_conn = os.environ.get("GITHUB_MCP_CONNECTION", "github-mcp")
    if gh_url and gh_conn:
        tools.append(
            MCPTool(
                server_label="github",
                server_url=gh_url,
                server_description=(
                    "GitHub (read-only): workflow runs, job logs, file contents "
                    "and commits. Use it to diagnose why a CI/CD pipeline failed."
                ),
                project_connection_id=gh_conn,
                require_approval="never",
            )
        )

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


def _cloud_request(action: str, env: str, params: dict) -> str:
    """Route a cloud control-plane action through the executor.

    Read-only/restorative actions (e.g. starting a stopped instance) run now and
    report their result. Destructive actions (stop, reboot) do NOT run — the
    executor returns a signed, single-use approval token, which we stash for the
    bot to render as an Approve/Reject card. The model is told it is not done.
    """
    import executor

    try:
        result = executor.request_action(action, env, params or {})
    except executor.ActionError as exc:
        return f"Could not run {action} on {env}: {exc}"
    except Exception:
        logging.exception("chat_cloud_action_failed %s", action)
        return f"Could not run {action} on {env}: an internal error occurred."

    if result.get("requires_approval"):
        _pending_approval.set(result)
        return (
            "APPROVAL REQUIRED — this has NOT run yet. "
            + (result.get("summary") or "")
            + " An Approve/Reject card is now shown to the user; a human must "
            "click Approve before anything happens. Tell the user you have "
            "requested approval and they must click Approve — do NOT claim the "
            "action was performed."
        )
    return str(result.get("output") or "Done.")


def stop_ec2(instance_id: str) -> str:
    return _cloud_request("stop_ec2", "aws", {"instance_id": instance_id})


def start_ec2(instance_id: str) -> str:
    return _cloud_request("start_ec2", "aws", {"instance_id": instance_id})


def reboot_ec2(instance_id: str) -> str:
    return _cloud_request("reboot_ec2", "aws", {"instance_id": instance_id})


def list_dev_ec2() -> str:
    """Deterministic lookup of the managed dev EC2 instances (name, id, state)."""
    import executor

    try:
        rows = executor.describe_dev_instances()
    except Exception:
        logging.exception("list_dev_ec2_failed")
        return "Could not list dev EC2 instances."
    if not rows:
        return "No development EC2 instances are configured."
    return "\n".join(
        f"{r['name']}: {r['instance_id']} (state: {r['state']})" for r in rows
    )


def start_vm(vm: str) -> str:
    return _cloud_request("start_vm", "dev", {"vm": vm})


def stop_vm(vm: str) -> str:
    return _cloud_request("stop_vm", "dev", {"vm": vm})


def restart_vm(vm: str) -> str:
    return _cloud_request("restart_vm", "dev", {"vm": vm})


def list_dev_vms() -> str:
    """Deterministic lookup of the managed dev Azure VMs (name, state)."""
    import executor

    try:
        rows = executor.describe_dev_vms()
    except Exception:
        logging.exception("list_dev_vms_failed")
        return "Could not list dev Azure VMs."
    if not rows:
        return "No development Azure VMs are configured."
    return "\n".join(f"{r['vm']}: {r['state']}" for r in rows)


_TOOL_DISPATCH = {
    "count_dev_customers": count_dev_customers,
    "list_dev_customers": list_dev_customers,
    "get_dev_customer": get_dev_customer,
    "dev_service_status": dev_service_status,
    "dev_recent_app_logs": dev_recent_app_logs,
    "dev_disk_usage": dev_disk_usage,
    "dev_vm_metric": dev_vm_metric,
    "query_dev_telemetry": query_dev_telemetry,
    "list_dev_ec2": list_dev_ec2,
    "stop_ec2": stop_ec2,
    "start_ec2": start_ec2,
    "reboot_ec2": reboot_ec2,
    "list_dev_vms": list_dev_vms,
    "start_vm": start_vm,
    "stop_vm": stop_vm,
    "restart_vm": restart_vm,
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


def _cloud_function_tools() -> list:
    """FunctionTool definitions for AWS EC2 power management, or [] when no
    dedicated exec IAM key is configured. Destructive ones (stop, reboot) mint
    an approval token instead of running; start runs immediately."""
    try:
        import executor
    except Exception:
        return []

    tools: list = []
    if executor.aws_is_enabled():
        _iid = {
            "instance_id": {
                "type": "string",
                "description": "The EC2 instance id, e.g. i-079e547101bf680a2. Development instances only.",
            }
        }
        tools += [
            FunctionTool(
                name="list_dev_ec2",
                description="List the managed DEVELOPMENT AWS EC2 instances with their real instance id and live power state. Use this to find an instance id before any power action.",
                parameters=_obj(),
            ),
            FunctionTool(
                name="stop_ec2",
                description="Stop a DEVELOPMENT AWS EC2 instance. Destructive: this returns an approval request (a human must click Approve); it does NOT stop the instance by itself.",
                parameters=_obj(_iid, ["instance_id"]),
            ),
            FunctionTool(
                name="reboot_ec2",
                description="Reboot a DEVELOPMENT AWS EC2 instance. Destructive: this returns an approval request (a human must click Approve); it does NOT reboot by itself.",
                parameters=_obj(_iid, ["instance_id"]),
            ),
            FunctionTool(
                name="start_ec2",
                description="Start a stopped DEVELOPMENT AWS EC2 instance. Runs immediately.",
                parameters=_obj(_iid, ["instance_id"]),
            ),
        ]

    # Azure VM power management uses the Function managed identity (no extra key),
    # so it is available whenever the executor can reach Azure. Every action here
    # returns an approval request — a human must click Approve before it runs.
    if executor.is_enabled():
        _vm = {
            "vm": {
                "type": "string",
                "description": "The Azure VM name: vm-erp-dev-app or vm-erp-dev-db. Development VMs only.",
            }
        }
        tools += [
            FunctionTool(
                name="list_dev_vms",
                description="List the managed DEVELOPMENT Azure VMs with their live power state (running/deallocated). Use this to confirm a VM name and state before any power action.",
                parameters=_obj(),
            ),
            FunctionTool(
                name="start_vm",
                description="Start a stopped/deallocated DEVELOPMENT Azure VM to restore service. Returns an approval request (a human must click Approve); it does NOT start the VM by itself.",
                parameters=_obj(_vm, ["vm"]),
            ),
            FunctionTool(
                name="stop_vm",
                description="Deallocate (stop) a DEVELOPMENT Azure VM. Returns an approval request (a human must click Approve); it does NOT stop the VM by itself.",
                parameters=_obj(_vm, ["vm"]),
            ),
            FunctionTool(
                name="restart_vm",
                description="Restart a DEVELOPMENT Azure VM. Returns an approval request (a human must click Approve); it does NOT restart the VM by itself.",
                parameters=_obj(_vm, ["vm"]),
            ),
        ]
    return tools


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
            tools=base + _dev_function_tools() + _cloud_function_tools(),
        ),
    )
    # The pipeline-triage agent gets the same read-only base (incl. GitHub MCP)
    # so it can read failed runs/logs/files; it proposes a fix but never writes.
    client.agents.create_version(
        _PIPELINE_NAME,
        definition=PromptAgentDefinition(
            model=_model(),
            instructions=_PIPELINE_INSTRUCTIONS,
            tools=base,
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


def _log_mcp_activity(resp, where: str) -> None:
    """Log every server-side MCP item in a Responses result.

    MCP tools execute server-side, so the only window into what the agent
    actually did is the response's output items. We log each ``mcp_call``
    (server/tool/args + whether it returned output or an error) and each
    ``mcp_list_tools`` discovery, so a triage that hallucinates instead of
    reading real logs is visible in App Insights. Best-effort; never raises.
    """
    try:
        for item in getattr(resp, "output", None) or []:
            itype = getattr(item, "type", None)
            if itype == "mcp_call":
                err = getattr(item, "error", None)
                out = getattr(item, "output", None)
                args = getattr(item, "arguments", "")
                if isinstance(args, str):
                    args = args[:300]
                logging.info(
                    "mcp_call where=%s server=%s tool=%s args=%s "
                    "error=%s output_len=%s",
                    where,
                    getattr(item, "server_label", "?"),
                    getattr(item, "name", "?"),
                    args,
                    (str(err)[:300] if err else None),
                    (len(out) if isinstance(out, str) else None),
                )
            elif itype == "mcp_list_tools":
                tools = getattr(item, "tools", None) or []
                names = [getattr(t, "name", "?") for t in tools][:50]
                logging.info(
                    "mcp_list_tools where=%s server=%s tools=%s",
                    where,
                    getattr(item, "server_label", "?"),
                    names,
                )
    except Exception:  # noqa: BLE001
        logging.debug("mcp_activity_log_failed", exc_info=True)


def _tool_error_note(exc: Exception) -> str | None:
    """If ``exc`` is a server-side MCP/tool failure, return a short corrective
    note (which tool failed and why) to feed back into a retry; else None.

    A single tool 400 aborts the whole Responses run, so we detect those and
    let the agent try again with the failure spelled out, instead of giving up.
    """
    text = str(exc)
    if "tool_user_error" not in text and "invoking '" not in text:
        return None
    match = _TOOL_ERR_RE.search(text)
    if not match:
        return "a tool call failed; avoid that call or fix its arguments"
    tool = match.group(1)
    detail = " ".join(match.group(2).split())[:300]
    return f"tool '{tool}' failed: {detail}"


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

    def _run(conv_id: str, text: str) -> str:
        resp = oc.responses.create(
            conversation=conv_id,
            extra_body=agent_ref,
            input=text,
        )
        _log_mcp_activity(resp, "initial")
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

    def _run_resilient(base_text: str) -> tuple[str, str]:
        """Run a turn, and if a server-side tool 400 aborts it, re-run with the
        failing tool/error fed back so the agent corrects itself.

        Each attempt uses a fresh conversation (the errored turn can leave the
        prior one in a half-finished state) and accumulates "avoid" notes for
        every tool call that has failed so far. Returns (reply_text, conv_id).
        """
        avoid: list[str] = []
        last_exc: Exception | None = None
        for attempt in range(_MAX_RCA_RETRIES):
            text = base_text
            if avoid:
                text = (
                    base_text
                    + "\n\nIMPORTANT — earlier tool attempts in this incident "
                    "FAILED. Do NOT repeat them; fix the arguments or use a "
                    "different tool/source instead:\n"
                    + "\n".join(f"- {note}" for note in avoid)
                )
            conv_id = oc.conversations.create().id
            try:
                return _run(conv_id, text), conv_id
            except Exception as exc:  # noqa: BLE001
                note = _tool_error_note(exc)
                if note is None:
                    raise
                last_exc = exc
                avoid.append(note)
                logging.warning(
                    "rca_tool_error attempt=%s note=%s", attempt + 1, note
                )
        # Exhausted retries on tool errors — surface the last one.
        raise last_exc if last_exc else RuntimeError("RCA retries exhausted")

    if conversation_id:
        try:
            return _run(conversation_id, message), conversation_id
        except Exception as exc:
            if _tool_error_note(exc) is None:
                logging.warning(
                    "chat_conversation_stale; starting a fresh one", exc_info=True
                )
            # Fall through to the resilient fresh-conversation path below.

    return _run_resilient(message)


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


def _fallback_report(event: dict, error: str = "") -> str:
    """A minimal, gate-able report used when the RCA agent cannot complete.

    A human notification must never depend on a flawless agent run (a single
    failing telemetry tool returns a 400 that aborts the whole response). When
    that happens we forward the raw alert flagged needs-human so the gate holds
    and a person still gets emailed. The agent error is surfaced verbatim so a
    human can see exactly which tool failed.
    """
    source = str(event.get("source") or "alert")
    summary = json.dumps(event.get("payload"), default=str)[:1500]
    why = f" Agent error: {error}." if error else ""
    return (
        "Root cause: Automated RCA was unavailable for this alert (the analysis "
        f"agent could not complete).{why}\n"
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
        except Exception as exc:
            logging.exception("agent_rca_failed")
            report = _fallback_report(event, f"{type(exc).__name__}: {exc}"[:600])

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


def _build_pipeline_message(event: dict) -> str:
    """Compose the triage prompt from a GitHub Actions failure payload."""
    p = event.get("payload") if isinstance(event.get("payload"), dict) else event
    p = p or {}
    fields = {
        "repository": p.get("repo") or p.get("repository"),
        "workflow": p.get("workflow") or p.get("workflow_name"),
        "workflow file": p.get("workflow_path") or p.get("workflow_file"),
        "run id": p.get("run_id"),
        "run url": p.get("run_url") or p.get("html_url"),
        "branch": p.get("branch") or p.get("ref_name") or p.get("head_branch"),
        "head sha": p.get("head_sha") or p.get("sha"),
        "triggering event": p.get("event") or p.get("event_name"),
        "actor": p.get("actor"),
    }
    lines = [f"{k}: {v}" for k, v in fields.items() if v]
    extra = json.dumps(p, default=str)[:1500]
    return (
        "A GitHub Actions pipeline run FAILED. Investigate it with the GitHub "
        "MCP (read-only) and return your report plus the JSON fix block.\n"
        "NOTE: 'run id' below is a GitHub Actions WORKFLOW RUN ID — look it up "
        "with the Actions workflow-run/jobs/logs tools, never a pull-request "
        "tool.\n"
        + "\n".join(lines)
        + f"\n\nRaw payload (for any extra context):\n{extra}"
    )


# Pull the first fenced ```json block out of the agent's report. We capture the
# whole block body (not brace-matched) so nested objects/arrays survive intact.
_FIX_JSON_RE = re.compile(r"```json\s*(.+?)```", re.DOTALL | re.IGNORECASE)
# The agent labels its reply in two parts; everything from the PART 2 marker on
# is the machine fix block (heading + fenced json) and must not leak into the
# human email body.
_PART2_RE = re.compile(r"\n[#\s*]*PART\s*2\b.*", re.DOTALL | re.IGNORECASE)


def _parse_fix(report: str) -> tuple[str, dict | None]:
    """Split the agent's reply into (human_report, fix_dict).

    The fix block is removed from the human report so the email stays clean.
    Returns ``(report, None)`` when no valid fix block is present.
    """
    match = _FIX_JSON_RE.search(report or "")
    if not match:
        return _PART2_RE.sub("", report or "").strip(), None
    human = (report[: match.start()] + report[match.end():]).strip()
    # Drop the trailing "PART 2 — JSON Fix" heading (and any stray text after the
    # json block) so only the human report remains in the email.
    human = _PART2_RE.sub("", human).strip()
    try:
        fix = json.loads(match.group(1))
    except Exception:
        logging.warning("pipeline_fix_unparseable", exc_info=True)
        return human, None
    if not isinstance(fix, dict):
        return human, None
    files = fix.get("files")
    if not isinstance(files, list):
        fix["files"] = []
    else:
        fix["files"] = [
            f for f in files
            if isinstance(f, dict) and f.get("path") and isinstance(f.get("content"), str)
        ]
    return human, fix


def analyze_pipeline_failure(event: dict) -> str | None:
    """Diagnose a failed CI/CD run and email a gated, one-click fix.

    Mirrors :func:`analyze_alert` but for GitHub Actions: the pipeline agent
    reads the failed run/logs/file via the read-only GitHub MCP, returns a
    human RCA plus a machine-applicable fix change-set. The change-set is stored
    (Table Storage) and a ``fix_pipeline`` approval token is emailed — only on a
    human Approve does executor.py create the branch, commit the fix, open a PR
    and re-run the workflow. Best-effort: errors are logged and swallowed so the
    webhook is always acknowledged.
    """
    try:
        content = _build_pipeline_message(event)
        try:
            report, _ = _respond(_PIPELINE_NAME, content)
        except Exception as exc:
            logging.exception("pipeline_rca_failed")
            report = (
                "Root cause: Automated CI/CD triage was unavailable (the analysis "
                f"agent could not complete). Agent error: {type(exc).__name__}: {exc}\n"
                "Severity: Unknown\nEvidence: see the failed run on GitHub.\n"
                "Proposed fix: A human should inspect the run logs directly.\n"
                "Risk: Unknown\nApproval: needs-human"
            )

        human_report, fix = _parse_fix(report or "")
        # Pipeline fixes ALWAYS gate to a human — never auto-applied.
        decision, reason = "HOLD", "a pipeline fix always requires human sign-off"
        human_report = (
            f"{human_report}\nGate (enforced in code): {decision} — {reason}"
        )

        p = event.get("payload") if isinstance(event.get("payload"), dict) else event
        p = p or {}
        try:
            import notifier

            notifier.notify_pipeline_failure(human_report, decision, reason, p, fix)
        except Exception:
            logging.exception("pipeline_notify_failed")
        return human_report or None
    except Exception:
        logging.exception("pipeline_rca_failed")
        return None


def analyze_chat(message: str, conversation_id: str | None = None) -> dict | None:
    """Run the conversational ChatOps agent over a human message.

    Multi-turn: the caller passes back the ``conversation_id`` we return to keep
    the same Foundry conversation (and its memory). Returns
    ``{"reply": str, "conversation_id": str}`` or ``None`` on hard failure.
    """
    _pending_approval.set(None)
    try:
        reply, conv_id = _respond(_CHAT_NAME, (message or "")[:4000], conversation_id)
        out = {"reply": reply or "(no reply)", "conversation_id": conv_id}
        pending = _pending_approval.get()
        if pending:
            out["pending_approval"] = pending
        return out
    except Exception:
        logging.exception("agent_chat_failed")
        return None
