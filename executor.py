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
# MySQL runs as root via the credentials file ansible already places on the DB
# box (/root/.my.cnf, mode 0600), so no DB password ever lives in the Function.
# Run Command does not set $HOME, hence the explicit --defaults-file. Queries are
# wrapped in `timeout` so a stuck connection can never hold the per-VM lock.
_MYSQL = "timeout 20 mysql --defaults-file=/root/.my.cnf erpdb"


def _count_customers(_params: dict) -> str:
    return f'{_MYSQL} -N -e "SELECT COUNT(*) FROM customers;" 2>&1'


def _list_customers(params: dict) -> str:
    n = _q_int(params, "limit", default=10, minimum=1, maximum=50)
    return (
        f'{_MYSQL} --table -e "SELECT id, name, email, phone '
        f'FROM customers ORDER BY id LIMIT {n};" 2>&1'
    )


def _get_customer(params: dict) -> str:
    cid = _q_int(params, "id", minimum=1)
    return (
        f'{_MYSQL} --table -e "SELECT id, name, email, phone, address, '
        f'created_at FROM customers WHERE id = {cid};" 2>&1'
    )


def _service_status(_params: dict) -> str:
    return (
        "echo '== erp-backend =='; systemctl is-active erp-backend; "
        "systemctl status erp-backend --no-pager 2>&1 | head -n 15"
    )


def _recent_app_logs(params: dict) -> str:
    n = _q_int(params, "lines", default=30, minimum=1, maximum=200)
    return f"journalctl -u erp-backend -n {n} --no-pager 2>&1"


def _disk_usage(_params: dict) -> str:
    return "df -h / 2>&1"


# --- Destructive builders. Still parameterized with validated integers only;
#     these only run after a signed, single-use approval token is presented. ---
def _delete_customer(params: dict) -> str:
    cid = _q_int(params, "id", minimum=1)
    # SELECT ROW_COUNT() reports how many rows were removed (0 if no such id).
    # The orders.customer_id foreign key blocks deleting a customer who still
    # has orders; that error is captured via 2>&1 and surfaced to the caller.
    return (
        f'{_MYSQL} -e "DELETE FROM customers WHERE id = {cid}; '
        f'SELECT ROW_COUNT() AS deleted;" 2>&1'
    )


def _restart_service(_params: dict) -> str:
    return (
        "systemctl restart erp-backend; sleep 2; echo '== erp-backend =='; "
        "systemctl is-active erp-backend 2>&1"
    )


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
    "delete_customer": {
        "target": "db",
        "destructive": True,
        "description": "Delete one customer by id (blocked by FK if they have orders). Param: id (>=1).",
        "build": _delete_customer,
    },
    "restart_service": {
        "target": "app",
        "destructive": True,
        "description": "Restart the erp-backend service on the app server.",
        "build": _restart_service,
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
    from azure.core.exceptions import ResourceExistsError

    client = _compute_client()
    try:
        poller = client.virtual_machines.begin_run_command(
            resource_group_name=resource_group,
            vm_name=vm_name,
            parameters={"command_id": "RunShellScript", "script": [script]},
        )
        result = poller.result()
    except ResourceExistsError:
        # Run Command serializes one command per VM; a previous one is still
        # running. Surface a friendly, retryable message rather than a 500.
        raise ActionError(
            "another action is already running on this host; try again in a moment"
        )
    messages = [s.message for s in (result.value or []) if getattr(s, "message", None)]
    return "\n".join(messages).strip() or "(no output)"


def _validate(action: str, env: str, params: dict) -> tuple[dict, str]:
    """Run every safety gate without touching Azure. Returns (spec, command).

    Raises ActionError for a blocked environment, unknown action, or bad
    parameters. Building the command here also validates the parameters (the
    builders coerce them to bounded ints), so an invalid request is rejected
    before any token is issued or any VM is contacted.
    """
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
    # 3. Parameter validation happens inside the builder.
    command = spec["build"](params)
    return spec, command


def _execute(action: str, env: str, params: dict, spec: dict, command: str) -> dict:
    """Run an already-validated action on its development VM and audit it."""
    target = ENV_TARGETS[env]
    vm_name = target[spec["target"]]
    resource_group = target["resource_group"]

    audit = {
        "action": action,
        "env": env,
        "target": spec["target"],
        "vm": vm_name,
        "params": params,
        "destructive": spec["destructive"],
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


def _summarize(action: str, env: str, params: dict) -> str:
    """A plain-English description of what a destructive action will do."""
    if action == "delete_customer":
        return (
            f"This will permanently DELETE customer id={params.get('id')} on the "
            f"{env} database. This cannot be undone."
        )
    if action == "restart_service":
        return f"This will RESTART the erp-backend service on the {env} app server."
    return f"This will run '{action}' on {env}."


def run_action(action: str, env: str, params: dict | None = None) -> dict:
    """Run a read-only allow-listed action immediately.

    Destructive actions are refused here — they must go through
    ``request_action`` -> ``approve_and_run`` (the signed-token gate).
    """
    params = params or {}
    spec, command = _validate(action, env, params)
    if spec["destructive"]:
        raise ActionError(
            f"action '{action}' is destructive; request it to get an approval token"
        )
    return _execute(action, env, params, spec, command)


# ===========================================================================
# Two-step approval for destructive actions.
#
# A destructive request never executes. It returns a signed, single-use,
# short-lived token that a human must present to ``approve_and_run``. The
# signing key is derived from the shared secret (domain-separated, so it is not
# the same value used for request authentication) and single use is enforced by
# recording the token's nonce in Table Storage — a replay finds the row already
# there and is rejected.
# ===========================================================================
_TOKEN_TTL_SECONDS = 600
_NONCE_TABLE = "approvaltokens"


def _signing_key() -> bytes:
    import hashlib

    secret = os.environ.get("CHAT_SHARED_SECRET") or os.environ.get("ALERT_SHARED_SECRET", "")
    if not secret:
        raise ActionError("approval signing secret is not configured")
    return hashlib.sha256(f"approval-token-v1:{secret}".encode()).digest()


def _make_token(action: str, env: str, params: dict) -> tuple[str, dict]:
    import base64
    import hashlib
    import hmac
    import time
    import uuid

    payload = {
        "action": action,
        "env": env,
        "params": params,
        "nonce": uuid.uuid4().hex,
        "exp": int(time.time()) + _TOKEN_TTL_SECONDS,
    }
    raw = base64.urlsafe_b64encode(
        json.dumps(payload, separators=(",", ":")).encode()
    ).decode()
    sig = hmac.new(_signing_key(), raw.encode(), hashlib.sha256).hexdigest()
    return f"{raw}.{sig}", payload


def _verify_token(token: str) -> dict:
    import base64
    import hashlib
    import hmac
    import time

    raw, _, sig = (token or "").partition(".")
    if not raw or not sig:
        raise ActionError("malformed approval token")
    expected = hmac.new(_signing_key(), raw.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig):
        raise ActionError("invalid approval token signature")
    try:
        payload = json.loads(base64.urlsafe_b64decode(raw.encode()))
    except Exception:
        raise ActionError("corrupt approval token")
    if int(payload.get("exp", 0)) < int(time.time()):
        raise ActionError("approval token has expired; request the action again")
    return payload


def _consume_nonce(nonce: str) -> None:
    """Record a token's nonce so it can never be approved twice."""
    from datetime import datetime, timezone

    from azure.core.exceptions import ResourceExistsError
    from azure.data.tables import TableServiceClient

    conn = os.environ.get("AzureWebJobsStorage")
    if not conn:
        raise ActionError("approval store is not configured")
    service = TableServiceClient.from_connection_string(conn)
    table = service.create_table_if_not_exists(_NONCE_TABLE)
    try:
        table.create_entity(
            {
                "PartitionKey": "approval",
                "RowKey": nonce,
                "usedAt": datetime.now(timezone.utc).isoformat(),
            }
        )
    except ResourceExistsError:
        raise ActionError("this approval token has already been used")


def request_action(action: str, env: str, params: dict | None = None) -> dict:
    """Entry point for a caller. Read-only actions run now; destructive actions
    are validated and return an approval token instead of executing."""
    params = params or {}
    spec, command = _validate(action, env, params)
    if not spec["destructive"]:
        result = _execute(action, env, params, spec, command)
        result["requires_approval"] = False
        return result

    token, payload = _make_token(action, env, params)
    logging.info(
        "approval_requested %s",
        json.dumps(
            {"action": action, "env": env, "params": params, "nonce": payload["nonce"]},
            default=str,
        ),
    )
    return {
        "requires_approval": True,
        "action": action,
        "env": env,
        "params": params,
        "summary": _summarize(action, env, params),
        "token": token,
        "expires_in_seconds": _TOKEN_TTL_SECONDS,
    }


def approve_and_run(token: str) -> dict:
    """Verify a token, spend it (single use), and run the destructive action."""
    payload = _verify_token(token)
    action = payload["action"]
    env = payload["env"]
    params = payload.get("params", {})

    # Re-validate from scratch (defense in depth) before spending the token.
    spec, command = _validate(action, env, params)
    if not spec["destructive"]:
        raise ActionError("token is not for a destructive action")

    # Spend the nonce first: if this fails (reuse), nothing runs.
    _consume_nonce(payload["nonce"])
    logging.info(
        "approval_granted %s",
        json.dumps({"action": action, "env": env, "nonce": payload["nonce"]}, default=str),
    )
    return _execute(action, env, params, spec, command)
