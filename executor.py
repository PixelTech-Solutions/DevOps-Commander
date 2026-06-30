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
import re
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

# --- AWS development EC2 allow-list. Production instances are intentionally
#     absent, so the executor physically refuses to touch them — the same
#     "safety lives in code, not in a prompt" principle as ENV_TARGETS above.
#     The agent reaches AWS read-only through the MCP server; only this executor
#     (behind the approval-token gate) can change EC2 power state. -------------
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
AWS_DEV_INSTANCES: dict[str, str] = {
    "i-079e547101bf680a2": "ec2-erp-dev-db",
    "i-083032133276a6d9f": "ec2-erp-dev-app",
}
_EC2_ID_RE = re.compile(r"^i-[0-9a-f]{8,17}$")

# --- Azure development VM allow-list (control-plane power management). Like the
#     AWS instances above, production VMs are intentionally absent so the
#     executor physically refuses to start/stop/restart anything but dev. The
#     agent reads VM state read-only through MCP; only this executor (behind the
#     approval-token gate) can change Azure VM power state. --------------------
AZURE_DEV_VMS: dict[str, str] = {
    "vm-erp-dev-app": "rg-erp-dev",
    "vm-erp-dev-db": "rg-erp-dev",
}
_VM_NAME_RE = re.compile(r"^vm-erp-dev-(?:app|db)$")


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


# --- Cloud control-plane actions (AWS EC2 power management). Unlike the VM
#     actions above, these do NOT run a shell command on a host — they call the
#     AWS API through a dedicated, least-privilege IAM user whose key is scoped
#     to start/stop/reboot only the two development instances. The validator
#     refuses any non-dev instance id in code, before AWS is ever contacted. ---
def _validate_dev_instance(params: dict) -> str:
    iid = str(params.get("instance_id", "")).strip()
    if not _EC2_ID_RE.match(iid):
        raise ActionError(
            "parameter 'instance_id' must look like i-0123456789abcdef"
        )
    if iid not in AWS_DEV_INSTANCES:
        raise ActionError(
            f"instance {iid} is not a development instance; the executor only "
            f"manages dev EC2 (production is blocked)"
        )
    return iid


@lru_cache(maxsize=1)
def _ec2_client():
    # Imported lazily so the app (and function indexing) never pays for boto3
    # unless a cloud action is actually invoked.
    import boto3

    return boto3.client(
        "ec2",
        region_name=AWS_REGION,
        aws_access_key_id=os.environ["AWS_EXEC_ACCESS_KEY_ID"],
        aws_secret_access_key=os.environ["AWS_EXEC_SECRET_ACCESS_KEY"],
    )


def _stop_ec2(params: dict) -> str:
    iid = _validate_dev_instance(params)
    state = _ec2_client().stop_instances(InstanceIds=[iid])["StoppingInstances"][0]
    return (
        f"{AWS_DEV_INSTANCES[iid]} ({iid}): "
        f"{state['PreviousState']['Name']} -> {state['CurrentState']['Name']}"
    )


def _start_ec2(params: dict) -> str:
    iid = _validate_dev_instance(params)
    state = _ec2_client().start_instances(InstanceIds=[iid])["StartingInstances"][0]
    return (
        f"{AWS_DEV_INSTANCES[iid]} ({iid}): "
        f"{state['PreviousState']['Name']} -> {state['CurrentState']['Name']}"
    )


def _reboot_ec2(params: dict) -> str:
    iid = _validate_dev_instance(params)
    _ec2_client().reboot_instances(InstanceIds=[iid])
    return f"{AWS_DEV_INSTANCES[iid]} ({iid}): reboot requested"


def describe_dev_instances() -> list[dict]:
    """Deterministic, read-only listing of the managed dev EC2 instances.

    Returns each known dev instance (name + id) with its live power state, so a
    caller never has to guess a Name tag to find an instance id. Uses the same
    least-privilege exec key (which has ec2:DescribeInstances). Production
    instances are intentionally not in AWS_DEV_INSTANCES, so they never appear.
    """
    ids = list(AWS_DEV_INSTANCES.keys())
    states: dict[str, str] = {}
    try:
        resp = _ec2_client().describe_instances(InstanceIds=ids)
        for reservation in resp.get("Reservations", []):
            for inst in reservation.get("Instances", []):
                states[inst["InstanceId"]] = inst.get("State", {}).get("Name", "unknown")
    except Exception:  # pragma: no cover - report ids even if describe fails
        logging.exception("describe_dev_instances_failed")
    return [
        {"instance_id": iid, "name": name, "state": states.get(iid, "unknown")}
        for iid, name in AWS_DEV_INSTANCES.items()
    ]


# --- Azure VM control-plane actions. Like the EC2 actions, these call the Azure
#     control plane (not a shell on the host) through the Function managed
#     identity, whose custom role is scoped to start/stop/restart only the dev
#     VMs. The validator refuses any non-dev VM name in code, before Azure is
#     ever contacted. -----------------------------------------------------------
def _validate_dev_vm(params: dict) -> str:
    vm = str(params.get("vm", "")).strip()
    if not _VM_NAME_RE.match(vm) or vm not in AZURE_DEV_VMS:
        raise ActionError(
            f"VM '{vm}' is not a development VM; the executor only manages "
            f"{', '.join(AZURE_DEV_VMS)} (production is blocked)"
        )
    return vm


def _vm_power_state(vm: str) -> str:
    """Read back a VM's power state code, e.g. 'PowerState/running'."""
    try:
        view = _compute_client().virtual_machines.instance_view(
            AZURE_DEV_VMS[vm], vm
        )
        for status in view.statuses or []:
            code = getattr(status, "code", "") or ""
            if code.startswith("PowerState/"):
                return code
    except Exception:  # pragma: no cover - best effort read-back
        logging.exception("vm_power_state_failed %s", vm)
    return "PowerState/unknown"


def _azure_vm_op(vm: str, begin: str) -> str:
    client = _compute_client()
    rg = AZURE_DEV_VMS[vm]
    getattr(client.virtual_machines, begin)(rg, vm).result()
    return f"{vm}: {begin.removeprefix('begin_')} completed; {_vm_power_state(vm)}"


def _start_vm(params: dict) -> str:
    return _azure_vm_op(_validate_dev_vm(params), "begin_start")


def _stop_vm(params: dict) -> str:
    # Deallocate (not just power off) so the stopped VM stops billing compute.
    return _azure_vm_op(_validate_dev_vm(params), "begin_deallocate")


def _restart_vm(params: dict) -> str:
    return _azure_vm_op(_validate_dev_vm(params), "begin_restart")


def describe_dev_vms() -> list[dict]:
    """Deterministic, read-only listing of the managed dev Azure VMs + state."""
    rows = []
    for vm, rg in AZURE_DEV_VMS.items():
        rows.append({"vm": vm, "resource_group": rg, "state": _vm_power_state(vm)})
    return rows


# ===========================================================================
# GitHub CI/CD self-healing (the ONLY place repo writes happen).
#
# The thinking agent reads a failed run through the read-only GitHub MCP and
# proposes a fix change-set. That change-set is stored here (Table Storage) and
# emailed behind the approval gate. Only on a human Approve does this code:
#   1. create a new branch from the failing branch,
#   2. commit the proposed file(s),
#   3. open a Pull Request,
#   4. re-run the pipeline (workflow_dispatch on the new branch).
# Writes use a SEPARATE, write-scoped PAT (GITHUB_EXEC_TOKEN) — never the
# read-only MCP connection — and only against repos on GITHUB_REPO_ALLOWLIST.
# ===========================================================================
GITHUB_API = "https://api.github.com"
_PIPELINE_FIX_TABLE = "pipelinefixes"
# Table Storage caps a single string property at ~64 KiB; guard the change-set.
_MAX_FIX_BYTES = 60_000


def github_is_enabled() -> bool:
    """True when a write-scoped PAT is configured to apply pipeline fixes."""
    return bool(os.environ.get("GITHUB_EXEC_TOKEN"))


def _repo_allowlist() -> set[str]:
    raw = os.environ.get("GITHUB_REPO_ALLOWLIST", "")
    return {r.strip() for r in raw.split(",") if r.strip()}


def _fix_table():
    from azure.data.tables import TableServiceClient

    conn = os.environ.get("AzureWebJobsStorage")
    if not conn:
        raise ActionError("pipeline-fix store is not configured")
    service = TableServiceClient.from_connection_string(conn)
    return service.create_table_if_not_exists(_PIPELINE_FIX_TABLE)


def store_pipeline_fix(record: dict) -> str:
    """Persist a proposed fix change-set and return its id (the approval handle).

    The HMAC token can only carry a tiny payload, so the (potentially large)
    file contents live here and the token just references this id.
    """
    import uuid

    files_json = json.dumps(record.get("files") or [], default=str)
    if len(files_json.encode("utf-8")) > _MAX_FIX_BYTES:
        raise ActionError("proposed fix is too large to store safely")
    fix_id = uuid.uuid4().hex
    _fix_table().create_entity(
        {
            "PartitionKey": "fix",
            "RowKey": fix_id,
            "repo": str(record.get("repo") or ""),
            "base_branch": str(record.get("base_branch") or ""),
            "run_id": str(record.get("run_id") or ""),
            "run_url": str(record.get("run_url") or ""),
            "workflow_path": str(record.get("workflow_path") or ""),
            "summary": str(record.get("summary") or "")[:512],
            "files_json": files_json,
        }
    )
    return fix_id


def load_pipeline_fix(fix_id: str) -> dict:
    from azure.core.exceptions import ResourceNotFoundError

    try:
        entity = _fix_table().get_entity("fix", fix_id)
    except ResourceNotFoundError:
        raise ActionError("the proposed fix has expired or was already applied")
    try:
        files = json.loads(entity.get("files_json") or "[]")
    except Exception:
        files = []
    return {
        "repo": entity.get("repo") or "",
        "base_branch": entity.get("base_branch") or "",
        "run_id": entity.get("run_id") or "",
        "run_url": entity.get("run_url") or "",
        "workflow_path": entity.get("workflow_path") or "",
        "summary": entity.get("summary") or "",
        "files": files,
    }


def _gh_api(method: str, path: str, *, body: dict | None = None, allow_404: bool = False):
    """Call the GitHub REST API with the write PAT (stdlib only — no new deps)."""
    import urllib.error
    import urllib.request

    token = os.environ.get("GITHUB_EXEC_TOKEN", "")
    if not token:
        raise ActionError("GitHub executor is not configured (GITHUB_EXEC_TOKEN missing)")
    url = path if path.startswith("http") else f"{GITHUB_API}{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    req.add_header("User-Agent", "devops-commander")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            return resp.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as exc:
        if exc.code == 404 and allow_404:
            return 404, None
        detail = exc.read().decode("utf-8", errors="replace")[:300]
        raise ActionError(f"GitHub API {method} {path} failed ({exc.code}): {detail}")
    except urllib.error.URLError as exc:
        raise ActionError(f"GitHub API unreachable: {exc.reason}")


def _validate_pipeline_fix(params: dict) -> str:
    """Gate a pipeline fix without touching GitHub. Returns "" (no shell command).

    Refuses anything outside the repo allow-list or with an empty change-set —
    the same 'safety lives in code' principle as the VM/EC2 allow-lists.
    """
    fix_id = (params or {}).get("fix_id")
    if not fix_id:
        raise ActionError("missing fix id")
    repo = (params or {}).get("repo") or ""
    allow = _repo_allowlist()
    if not allow:
        raise ActionError("no repositories are allow-listed (GITHUB_REPO_ALLOWLIST)")
    if repo not in allow:
        raise ActionError(f"repository '{repo}' is not allow-listed for fixes")
    fix = load_pipeline_fix(fix_id)
    if fix.get("repo") and fix["repo"] != repo:
        raise ActionError("fix/repo mismatch")
    if not fix.get("files"):
        raise ActionError("the proposed fix has no file changes to apply")
    return ""


def _do_pipeline_fix(params: dict) -> str:
    """Apply a stored, approved fix: branch -> commit -> PR -> re-run."""
    import base64
    import time

    fix = load_pipeline_fix(params["fix_id"])
    repo = params.get("repo") or fix["repo"]
    if repo not in _repo_allowlist():
        raise ActionError(f"repository '{repo}' is not allow-listed for fixes")

    # Resolve the base branch (fall back to the repo default) and its tip sha.
    base_branch = fix.get("base_branch") or ""
    if not base_branch:
        _, info = _gh_api("GET", f"/repos/{repo}")
        base_branch = (info or {}).get("default_branch") or "main"
    _, ref = _gh_api("GET", f"/repos/{repo}/git/ref/heads/{base_branch}")
    base_sha = ref["object"]["sha"]

    # Create a uniquely-named fix branch off that tip.
    run_id = fix.get("run_id") or "manual"
    new_branch = f"commander/fix-{run_id}-{int(time.time())}"
    _gh_api(
        "POST",
        f"/repos/{repo}/git/refs",
        body={"ref": f"refs/heads/{new_branch}", "sha": base_sha},
    )

    # Commit each proposed file onto the new branch.
    changed = []
    for f in fix["files"]:
        path = f["path"].lstrip("/")
        content_b64 = base64.b64encode(f["content"].encode("utf-8")).decode()
        status, existing = _gh_api(
            "GET", f"/repos/{repo}/contents/{path}?ref={new_branch}", allow_404=True
        )
        body = {
            "message": f"fix(ci): {fix.get('summary') or 'automated pipeline fix'} [{path}]",
            "content": content_b64,
            "branch": new_branch,
        }
        if status != 404 and existing and existing.get("sha"):
            body["sha"] = existing["sha"]
        _gh_api("PUT", f"/repos/{repo}/contents/{path}", body=body)
        changed.append(path)

    # Open a Pull Request for human review of the applied fix.
    pr_body = (
        f"Automated CI/CD fix proposed by DevOps Commander and approved by a human.\n\n"
        f"**Summary:** {fix.get('summary') or '(none)'}\n"
        f"**Failed run:** {fix.get('run_url') or fix.get('run_id') or '(unknown)'}\n"
        f"**Files changed:** {', '.join(changed)}\n"
    )
    _, pr = _gh_api(
        "POST",
        f"/repos/{repo}/pulls",
        body={
            "title": (fix.get("summary") or "Automated pipeline fix")[:120],
            "head": new_branch,
            "base": base_branch,
            "body": pr_body,
        },
    )
    pr_num = pr.get("number")
    pr_url = pr.get("html_url")

    # Best-effort: re-run the pipeline on the fix branch via workflow_dispatch.
    rerun = "the PR's required checks will run automatically"
    wf = fix.get("workflow_path") or ""
    wf_file = wf.split("/")[-1] if wf else ""
    if wf_file:
        try:
            _gh_api(
                "POST",
                f"/repos/{repo}/actions/workflows/{wf_file}/dispatches",
                body={"ref": new_branch},
            )
            rerun = f"re-ran workflow '{wf_file}' on {new_branch}"
        except ActionError as exc:
            rerun = f"could not auto-dispatch ({exc}); the PR checks will still run"

    return (
        f"Opened PR #{pr_num} ({pr_url}) on branch {new_branch} with "
        f"{len(changed)} file change(s): {', '.join(changed)}. {rerun}."
    )


def _execute_github(action: str, env: str, params: dict, spec: dict) -> dict:
    """Run an already-validated GitHub pipeline-fix via the write PAT and audit it."""
    audit = {
        "action": action,
        "env": env,
        "target": "github",
        "params": params,
        "destructive": spec["destructive"],
    }
    logging.info("executor_attempt %s", json.dumps(audit, default=str))

    if not github_is_enabled():
        raise ActionError(
            "GitHub executor is not configured (GITHUB_EXEC_TOKEN missing)"
        )

    output = spec["run"](params)

    logging.info(
        "executor_result %s",
        json.dumps({**audit, "ok": True, "output_chars": len(output)}, default=str),
    )
    return {
        "ok": True,
        "action": action,
        "env": env,
        "target": "github",
        "output": output,
    }


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
    "stop_ec2": {
        "kind": "cloud",
        "env": "aws",
        "destructive": True,
        "description": "Stop a development EC2 instance. Param: instance_id (dev only).",
        "validate": _validate_dev_instance,
        "run": _stop_ec2,
    },
    "reboot_ec2": {
        "kind": "cloud",
        "env": "aws",
        "destructive": True,
        "description": "Reboot a development EC2 instance. Param: instance_id (dev only).",
        "validate": _validate_dev_instance,
        "run": _reboot_ec2,
    },
    "start_ec2": {
        "kind": "cloud",
        "env": "aws",
        "destructive": False,
        "description": "Start a stopped development EC2 instance. Param: instance_id (dev only).",
        "validate": _validate_dev_instance,
        "run": _start_ec2,
    },
    "start_vm": {
        "kind": "azurevm",
        "env": "dev",
        "destructive": True,
        "description": "Start a stopped/deallocated development Azure VM (restores service). Param: vm (dev only). Requires approval.",
        "validate": _validate_dev_vm,
        "run": _start_vm,
    },
    "stop_vm": {
        "kind": "azurevm",
        "env": "dev",
        "destructive": True,
        "description": "Deallocate (stop) a development Azure VM. Param: vm (dev only). Requires approval.",
        "validate": _validate_dev_vm,
        "run": _stop_vm,
    },
    "restart_vm": {
        "kind": "azurevm",
        "env": "dev",
        "destructive": True,
        "description": "Restart a development Azure VM. Param: vm (dev only). Requires approval.",
        "validate": _validate_dev_vm,
        "run": _restart_vm,
    },
    "fix_pipeline": {
        "kind": "github",
        "env": "github",
        "destructive": True,
        "description": "Apply an approved CI/CD fix: commit it to a new branch, open a PR, and re-run the pipeline. Params: fix_id, repo. Requires approval.",
        "validate": _validate_pipeline_fix,
        "run": _do_pipeline_fix,
    },
}


def list_actions() -> list[dict]:
    """A safe, public description of what the executor can do (no commands)."""
    return [
        {
            "name": name,
            "target": spec.get("target") or spec.get("env") or "cloud",
            "destructive": spec["destructive"],
            "description": spec["description"],
        }
        for name, spec in sorted(ACTIONS.items())
    ]


def is_enabled() -> bool:
    """True when the executor has what it needs to reach Azure."""
    return bool(os.environ.get("AZURE_SUBSCRIPTION_ID"))


def aws_is_enabled() -> bool:
    """True when the executor has a dedicated IAM key to manage dev EC2."""
    return bool(
        os.environ.get("AWS_EXEC_ACCESS_KEY_ID")
        and os.environ.get("AWS_EXEC_SECRET_ACCESS_KEY")
    )


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
    spec = ACTIONS.get(action)
    if spec is None:
        raise ActionError(f"unknown action '{action}'")
    # 2. Cloud control-plane actions validate their own (dev-only) target.
    if spec.get("kind") in ("cloud", "azurevm", "github"):
        if env != spec["env"]:
            raise ActionError(
                f"action '{action}' runs on '{spec['env']}', not '{env}'"
            )
        spec["validate"](params)
        return spec, None
    # 3. VM actions: environment + allow-list gates.
    if env not in ENV_TARGETS:
        raise ActionError(
            f"environment '{env}' is not allowed; the executor only operates on "
            f"{', '.join(ALLOWED_ENVS)} (production is blocked)"
        )
    # 4. Parameter validation happens inside the builder.
    command = spec["build"](params)
    return spec, command


def _execute(action: str, env: str, params: dict, spec: dict, command: str) -> dict:
    """Run an already-validated action and audit it."""
    if spec.get("kind") == "cloud":
        return _execute_cloud(action, env, params, spec)
    if spec.get("kind") == "azurevm":
        return _execute_azure_vm(action, env, params, spec)
    if spec.get("kind") == "github":
        return _execute_github(action, env, params, spec)

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


def _execute_cloud(action: str, env: str, params: dict, spec: dict) -> dict:
    """Run an already-validated AWS EC2 action via the scoped IAM key and audit it."""
    audit = {
        "action": action,
        "env": env,
        "target": spec.get("env"),
        "params": params,
        "destructive": spec["destructive"],
    }
    logging.info("executor_attempt %s", json.dumps(audit, default=str))

    if not aws_is_enabled():
        raise ActionError(
            "AWS executor is not configured (AWS_EXEC_ACCESS_KEY_ID missing)"
        )

    output = spec["run"](params)

    logging.info(
        "executor_result %s",
        json.dumps({**audit, "ok": True, "output_chars": len(output)}, default=str),
    )
    return {
        "ok": True,
        "action": action,
        "env": env,
        "target": spec.get("env"),
        "output": output,
    }


def _execute_azure_vm(action: str, env: str, params: dict, spec: dict) -> dict:
    """Run an already-validated Azure VM power action via the Function MI and audit it."""
    audit = {
        "action": action,
        "env": env,
        "target": "azurevm",
        "params": params,
        "destructive": spec["destructive"],
    }
    logging.info("executor_attempt %s", json.dumps(audit, default=str))

    if not is_enabled():
        raise ActionError("executor is not configured (AZURE_SUBSCRIPTION_ID missing)")

    output = spec["run"](params)

    logging.info(
        "executor_result %s",
        json.dumps({**audit, "ok": True, "output_chars": len(output)}, default=str),
    )
    return {
        "ok": True,
        "action": action,
        "env": env,
        "target": "azurevm",
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
    if action == "stop_ec2":
        iid = params.get("instance_id")
        name = AWS_DEV_INSTANCES.get(iid, iid)
        return (
            f"This will STOP the {env} EC2 instance {name} ({iid}). It will be "
            f"unreachable until it is started again."
        )
    if action == "reboot_ec2":
        iid = params.get("instance_id")
        name = AWS_DEV_INSTANCES.get(iid, iid)
        return f"This will REBOOT the {env} EC2 instance {name} ({iid})."
    if action == "start_vm":
        return (
            f"This will START the {env} Azure VM {params.get('vm')} to restore "
            f"service availability."
        )
    if action == "stop_vm":
        return (
            f"This will DEALLOCATE (stop) the {env} Azure VM {params.get('vm')}. "
            f"It will be unreachable until it is started again."
        )
    if action == "restart_vm":
        return f"This will RESTART the {env} Azure VM {params.get('vm')}."
    if action == "fix_pipeline":
        repo = params.get("repo") or "the repository"
        return (
            f"This will COMMIT the proposed fix to {repo} on a new branch, open a "
            f"Pull Request, and re-run the pipeline. Nothing merges automatically "
            f"— a human still reviews and merges the PR."
        )
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
