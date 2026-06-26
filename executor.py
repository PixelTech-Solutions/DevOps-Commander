"""DevOps Commander — dev-only action executor (ChatOps step).

This module is the ONLY place that can run a command against the ERP servers,
and it is deliberately small, boring, and paranoid. The thinking agents never
hold credentials and never emit raw SQL or shell — they choose an action *name*
from a fixed allow-list and pass typed parameters. This module turns that into a
specific command and runs it on a development VM via Azure VM Run Command.

Where the safety actually lives (NOT in the prompt):
  1. Environment block — only "dev" exists in ENV_TARGETS. Any other value
     (notably "prod") raises before a single Azure call is made.
  2. Allow-list — only the actions in ACTIONS can run. Their commands are built
     from parameters that are coerced to int/enum, so nothing free-text from a
     user is ever interpolated into SQL or a shell line.
  3. Least privilege — the Function's managed identity is granted
     Microsoft.Compute/virtualMachines/runCommand/action scoped to the dev
     resource group only (see the Terraform role assignment). It physically
     cannot reach the production VMs.
  4. No secrets — the Run Command script runs as root on the VM and talks to
     MySQL over the local socket, so no DB password ever leaves the box.
  5. Audit — every attempt and outcome is logged to Application Insights.

Read-only actions run directly. Destructive actions (added later) additionally
require a signed, single-use approval token and go through the code gate.
"""

from __future__ import annotations

import json
import logging
import os
from functools import lru_cache

# --- Target map: ONLY development. Production is intentionally absent. --------
# Adding "prod" here would be the single change that exposes production, which
# is exactly why it lives in code review, not in a prompt or a request body.
ENV_TARGETS: dict[str, dict[str, str]] = {
    "dev": {
        "resource_group": "rg-erp-dev",
        "app": "vm-erp-dev-app",  # Spring Boot erp-backend (systemd) + nginx
        "db": "vm-erp-dev-db",    # MySQL 8, database "erpdb"
    },
}

ALLOWED_ENVS = tuple(ENV_TARGETS.keys())


class ActionError(Exception):
    """A request that the executor refuses or cannot carry out safely."""


def _q_int(params: dict, name: str, *, default=None, minimum=None, maximum=None) -> int:
    """Read a parameter and force it to a bounded int (injection-proof)."""
    raw = params.get(name, default)
    if raw is None:
        raise ActionError(f"missing required integer parameter '{name}'")
    try:
        value = int(raw)
    except (TypeError, ValueError):
        raise ActionError(f"parameter '{name}' must be an integer")
    if minimum is not None and value < minimum:
        raise ActionError(f"parameter '{name}' must be >= {minimum}")
    if maximum is not None and value > maximum:
        raise ActionError(f"parameter '{name}' must be <= {maximum}")
    return value


# --- The allow-list. Each action declares its target host role, whether it is
#     destructive, and a builder that returns the shell command to run. Builders
#     only ever interpolate already-validated integers. ------------------------
def _count_customers(_params: dict) -> str:
    return 'mysql erpdb -N -e "SELECT COUNT(*) AS customers FROM customers;"'


def _list_customers(params: dict) -> str:
    n = _q_int(params, "limit", default=10, minimum=1, maximum=50)
    return (
        f'mysql --table erpdb -e "SELECT id, name, email, phone '
        f'FROM customers ORDER BY id LIMIT {n};"'
    )


def _get_customer(params: dict) -> str:
    cid = _q_int(params, "id", minimum=1)
    return (
        f'mysql --table erpdb -e "SELECT id, name, email, phone, address, '
        f'created_at FROM customers WHERE id = {cid};"'
    )


def _service_status(_params: dict) -> str:
    return (
        "echo '== erp-backend =='; systemctl is-active erp-backend; "
        "systemctl status erp-backend --no-pager | head -n 15"
    )


def _recent_app_logs(params: dict) -> str:
    n = _q_int(params, "lines", default=30, minimum=1, maximum=200)
    return f"journalctl -u erp-backend -n {n} --no-pager"


def _disk_usage(_params: dict) -> str:
    return "df -h /"


ACTIONS: dict[str, dict] = {
    "count_customers": {
        "target": "db",
        "destructive": False,
        "description": "Count the rows in the customers table.",
        "build": _count_customers,
    },
    "list_customers": {
        "target": "db",
        "destructive": False,
        "description": "List customers (id, name, email, phone). Param: limit (1-50).",
        "build": _list_customers,
    },
    "get_customer": {
        "target": "db",
        "destructive": False,
        "description": "Show one customer by id. Param: id (>=1).",
        "build": _get_customer,
    },
    "service_status": {
        "target": "app",
        "destructive": False,
        "description": "Show whether the erp-backend service is running.",
        "build": _service_status,
    },
    "recent_app_logs": {
        "target": "app",
        "destructive": False,
        "description": "Show recent erp-backend journal logs. Param: lines (1-200).",
        "build": _recent_app_logs,
    },
    "disk_usage": {
        "target": "app",
        "destructive": False,
        "description": "Show root filesystem disk usage on the app server.",
        "build": _disk_usage,
    },
}


def list_actions() -> list[dict]:
    """A safe, public description of what the executor can do (no commands)."""
    return [
        {
            "name": name,
            "target": spec["target"],
            "destructive": spec["destructive"],
            "description": spec["description"],
        }
        for name, spec in sorted(ACTIONS.items())
    ]


def is_enabled() -> bool:
    """True when the executor has what it needs to reach Azure."""
    return bool(os.environ.get("AZURE_SUBSCRIPTION_ID"))


@lru_cache(maxsize=1)
def _compute_client():
    # Imported lazily so the rest of the app (and function indexing) never pays
    # for azure-mgmt-compute unless an action is actually invoked.
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.compute import ComputeManagementClient

    subscription_id = os.environ["AZURE_SUBSCRIPTION_ID"]
    return ComputeManagementClient(DefaultAzureCredential(), subscription_id)


def _run_on_vm(resource_group: str, vm_name: str, script: str) -> str:
    """Run a shell script as root on a VM via Azure action Run Command."""
    client = _compute_client()
    poller = client.virtual_machines.begin_run_command(
        resource_group_name=resource_group,
        vm_name=vm_name,
        parameters={"command_id": "RunShellScript", "script": [script]},
    )
    result = poller.result()
    messages = [s.message for s in (result.value or []) if getattr(s, "message", None)]
    return "\n".join(messages).strip() or "(no output)"


def run_action(action: str, env: str, params: dict | None = None) -> dict:
    """Validate and run an allow-listed action against a development VM.

    Returns a structured result dict. Raises ActionError for anything refused
    (unknown env/action, production, bad parameters). Read-only actions run
    immediately; destructive ones are rejected here until the approval path
    (token + gate) is wired in.
    """
    params = params or {}

    # 1. Environment gate — production and anything unknown stop here, in code.
    if env not in ENV_TARGETS:
        raise ActionError(
            f"environment '{env}' is not allowed; the executor only operates on "
            f"{', '.join(ALLOWED_ENVS)} (production is blocked)"
        )

    # 2. Allow-list gate.
    spec = ACTIONS.get(action)
    if spec is None:
        raise ActionError(f"unknown action '{action}'")

    # 3. Destructive actions are not runnable yet (approval path comes later).
    if spec["destructive"]:
        raise ActionError(
            f"action '{action}' is destructive and requires the approval flow "
            "(not yet enabled)"
        )

    target = ENV_TARGETS[env]
    vm_name = target[spec["target"]]
    resource_group = target["resource_group"]
    command = spec["build"](params)  # may raise ActionError on bad params

    audit = {
        "action": action,
        "env": env,
        "target": spec["target"],
        "vm": vm_name,
        "params": params,
    }
    logging.info("executor_attempt %s", json.dumps(audit, default=str))

    if not is_enabled():
        raise ActionError("executor is not configured (AZURE_SUBSCRIPTION_ID missing)")

    output = _run_on_vm(resource_group, vm_name, command)

    logging.info(
        "executor_result %s",
        json.dumps({**audit, "ok": True, "output_chars": len(output)}, default=str),
    )
    return {
        "ok": True,
        "action": action,
        "env": env,
        "target": spec["target"],
        "vm": vm_name,
        "output": output,
    }
