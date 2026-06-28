"""DevOps Commander — live observability tools for the SRE agents.

Read-only telemetry that turns the agents from "reasoning over the alert text"
into "reasoning over what the system is actually doing right now":

  * Azure Monitor platform metrics (CPU, network, disk) for the dev ERP VMs.
  * Log Analytics (Kusto) queries over the operational telemetry the Function
    records (incidents handled, executor actions, etc.).

Like the executor, this module holds NO secrets and reaches Azure only through
the Function's user-assigned managed identity, which is granted least-privilege
read roles: Monitoring Reader on the dev resource group (VM metrics) and Log
Analytics Reader on the workspace (Kusto queries). Production is never in scope:
the VM target map is reused from the executor, which only knows about "dev".
"""

from __future__ import annotations

import logging
import os
from datetime import timedelta
from functools import lru_cache

import executor  # reuse the dev-only target map (ENV_TARGETS)


# Friendly aliases -> Azure Monitor platform metric names that exist on a Linux
# VM with no extra agent. (Guest memory needs the Azure Monitor Agent, so it is
# intentionally omitted — we only expose metrics that are reliably present.)
_DEFAULT_METRIC = "Percentage CPU"
_METRIC_ALIASES = {
    "cpu": _DEFAULT_METRIC,
    "percentage cpu": _DEFAULT_METRIC,
    "network in": "Network In Total",
    "network out": "Network Out Total",
    "disk read": "Disk Read Bytes",
    "disk write": "Disk Write Bytes",
}


def is_enabled() -> bool:
    """True when the subscription is configured (same gate as the executor)."""
    return bool(os.environ.get("AZURE_SUBSCRIPTION_ID"))


def _vm_resource_id(host: str) -> str:
    """Build the ARM resource id for a dev VM ('app' or 'db')."""
    target = executor.ENV_TARGETS.get("dev", {})
    vm = target.get(host)
    if not vm:
        raise ValueError(f"unknown dev host '{host}' (expected 'app' or 'db')")
    subscription_id = os.environ["AZURE_SUBSCRIPTION_ID"]
    resource_group = target["resource_group"]
    return (
        f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}"
        f"/providers/Microsoft.Compute/virtualMachines/{vm}"
    )


@lru_cache(maxsize=1)
def _metrics_client():
    # Imported lazily so function indexing never pays for azure-monitor-query.
    from azure.identity import DefaultAzureCredential
    from azure.monitor.query import MetricsQueryClient

    return MetricsQueryClient(DefaultAzureCredential())


@lru_cache(maxsize=1)
def _logs_client():
    from azure.identity import DefaultAzureCredential
    from azure.monitor.query import LogsQueryClient

    return LogsQueryClient(DefaultAzureCredential())


def _bounded_hours(hours) -> int:
    """Coerce an arbitrary value to an int in 1..24 (injection-proof window)."""
    try:
        value = int(hours)
    except (TypeError, ValueError):
        value = 1
    return max(1, min(value, 24))


def vm_metric(host: str = "app", metric: str = _DEFAULT_METRIC, hours=1) -> str:
    """Summarize a dev VM platform metric (avg / peak / latest) over the window."""
    from azure.monitor.query import MetricAggregationType

    metric_name = _METRIC_ALIASES.get(
        (metric or "").strip().lower(), metric or _DEFAULT_METRIC
    )
    hours = _bounded_hours(hours)
    resource_id = _vm_resource_id(host)
    response = _metrics_client().query_resource(
        resource_id,
        metric_names=[metric_name],
        timespan=timedelta(hours=hours),
        granularity=timedelta(minutes=5),
        aggregations=[MetricAggregationType.AVERAGE, MetricAggregationType.MAXIMUM],
    )

    lines: list[str] = []
    for metric_obj in response.metrics:
        points = [
            p
            for ts in metric_obj.timeseries
            for p in ts.data
            if p.average is not None or p.maximum is not None
        ]
        if not points:
            lines.append(f"{metric_obj.name}: no data in the last {hours}h")
            continue
        averages = [p.average for p in points if p.average is not None]
        maxima = [p.maximum for p in points if p.maximum is not None]
        overall_avg = sum(averages) / len(averages) if averages else 0.0
        overall_max = max(maxima) if maxima else 0.0
        unit = getattr(metric_obj, "unit", "") or ""
        latest = points[-1]
        latest_val = latest.average if latest.average is not None else latest.maximum
        lines.append(
            f"{metric_obj.name} (last {hours}h): avg {overall_avg:.1f} {unit}, "
            f"peak {overall_max:.1f} {unit}, latest {latest_val:.1f} {unit}".strip()
        )
    return "\n".join(lines) or "(no metric data)"


def query_telemetry(kql: str, hours=1) -> str:
    """Run a read-only Kusto query against the Log Analytics workspace."""
    workspace_id = os.environ.get("LOG_ANALYTICS_WORKSPACE_ID")
    if not workspace_id:
        return "Operational telemetry query is not configured."
    if not (kql or "").strip():
        return "Provide a Kusto (KQL) query."

    from azure.monitor.query import LogsQueryStatus

    hours = _bounded_hours(hours)
    response = _logs_client().query_workspace(
        workspace_id, kql, timespan=timedelta(hours=hours)
    )
    if response.status == LogsQueryStatus.FAILURE:
        return f"Query failed: {getattr(response, 'partial_error', 'unknown error')}"

    tables = response.tables or getattr(response, "partial_data", None) or []
    if not tables or not tables[0].rows:
        return "(no rows)"
    table = tables[0]
    columns = list(table.columns)
    out = [" | ".join(columns)]
    for row in table.rows[:20]:
        out.append(" | ".join("" if v is None else str(v) for v in row))
    return "\n".join(out)


def incident_context(host: str = "app", hours: int = 1) -> str:
    """Fast, deterministic enrichment for the alert path: ground truth first.

    Establishes the ONE fact the agent must not guess — is the VM actually
    powered on — via the authoritative instance view, then adds a live CPU
    snapshot. Kept to two quick Azure calls so it never slows an alert ack.
    Returns "" when nothing could be gathered so the caller can skip enrichment.
    """
    if not is_enabled():
        return ""
    lines: list[str] = []
    try:
        state = vm_power_state(host)
        if state:
            vm = executor.ENV_TARGETS.get("dev", {}).get(host, host)
            verdict = "UP" if state.lower() == "running" else "DOWN — VM is not running"
            lines.append(
                f"Ground truth (authoritative) — Azure dev {host} VM ({vm}) "
                f"power state: {state} ({verdict})."
            )
    except Exception:
        logging.debug("incident_context_power_failed", exc_info=True)
    try:
        snapshot = vm_metric(host, _DEFAULT_METRIC, hours)
        if snapshot:
            lines.append("Live telemetry — " + snapshot)
    except Exception:
        logging.debug("incident_context_failed", exc_info=True)
    return "\n".join(lines)


def vm_power_state(host: str = "app") -> str:
    """Authoritative power state of a dev VM ('app'|'db') via the instance view.

    Returns a short code ('running', 'deallocated', 'stopped', ...) or "" when
    it cannot be determined. Fast (~1s) and read-only — this is the fact the
    agent must never infer from metric silence.
    """
    if not is_enabled():
        return ""
    try:
        target = executor.ENV_TARGETS.get("dev", {})
        vm = target.get(host)
        if not vm:
            return ""
        view = executor._compute_client().virtual_machines.instance_view(
            target["resource_group"], vm
        )
        for status in view.statuses or []:
            code = getattr(status, "code", "") or ""
            if code.startswith("PowerState/"):
                return code.split("/", 1)[1]
        return ""
    except Exception:
        logging.debug("vm_power_state_failed", exc_info=True)
        return ""
