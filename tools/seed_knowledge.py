#!/usr/bin/env python3
"""Seed the `erp-knowledge` Azure AI Search index (Step 8 RAG knowledge base).

The diagnosis agent grounds its analysis in this index. It holds three kinds of
records, all drawn from `Resources/INFRA-INVENTORY.md` (the recorded source of
truth):

  * infra    -- the 4 ERP environments (Azure/AWS x dev/prod) with public and
                private IPs, SKUs, URLs, services, plus the DevOps Commander
                platform itself.
  * history  -- implementation history: provisioning, monitoring, the agent fleet.
  * incident -- past incidents and the gotchas we hit, with their resolutions.

Keyword (SIMPLE) search is used, so no embeddings/vectors are needed.

Run once, locally, after the Search service exists. Values come from the
Terraform outputs of DevOps-Commander-Infra:

    $env:SEARCH_ENDPOINT  = (terraform output -raw search_endpoint)
    $env:SEARCH_ADMIN_KEY = (terraform output -raw search_admin_key)
    python tools/seed_knowledge.py

Only the Python standard library is used, so there is nothing to install.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

API_VERSION = "2024-07-01"
INDEX_NAME = os.environ.get("SEARCH_INDEX", "erp-knowledge")
DOCS_CONTAINER = "knowledge-docs"   # B: uploaded company documents
LOGS_CONTAINER = "knowledge-logs"   # C: exported previous logs (JSON lines)

_STR = "Edm.String"

INDEX_DEFINITION = {
    "name": INDEX_NAME,
    "fields": [
        {"name": "id", "type": _STR, "key": True, "filterable": True},
        {"name": "doc_type", "type": _STR, "searchable": True, "filterable": True},
        {"name": "title", "type": _STR, "searchable": True},
        {"name": "cloud", "type": _STR, "searchable": True, "filterable": True},
        {"name": "env", "type": _STR, "searchable": True, "filterable": True},
        {"name": "service", "type": _STR, "searchable": True, "filterable": True},
        {"name": "host", "type": _STR, "searchable": True},
        {"name": "severity", "type": _STR, "filterable": True},
        {"name": "content", "type": _STR, "searchable": True},
        {"name": "source", "type": _STR, "searchable": True},
        {"name": "timestamp", "type": "Edm.DateTimeOffset", "filterable": True, "sortable": True},
    ],
}

# --- Infrastructure inventory (real IPs from Resources/INFRA-INVENTORY.md) ----
INFRA = [
    {
        "id": "infra-azure-dev",
        "title": "Azure dev environment (rg-erp-dev)",
        "cloud": "Azure", "env": "dev", "service": "erp-system",
        "host": "app 20.121.26.232 (private 10.0.1.4); db 40.87.21.255 (private 10.0.2.4)",
        "content": (
            "Azure dev ERP in resource group rg-erp-dev, region eastus. App VM vm-erp-dev-app "
            "(Standard_B1s) public 20.121.26.232 / private 10.0.1.4 runs Spring Boot erp-backend "
            "on :8080 behind nginx :80. DB VM vm-erp-dev-db (Standard_B1s) public 40.87.21.255 / "
            "private 10.0.2.4 runs MySQL 8 (database erpdb) on :3306, reachable only from the VNet. "
            "SSH user azureuser. URL http://20.121.26.232/ ; health http://20.121.26.232/actuator/health. "
            "Monitored by Grafana Cloud (host erp-azure-app-server-dev / erp-azure-db-server-dev)."
        ),
    },
    {
        "id": "infra-azure-prod",
        "title": "Azure prod environment (rg-erp-prod)",
        "cloud": "Azure", "env": "prod", "service": "erp-system",
        "host": "app 20.172.141.25 (private 10.0.1.4); db 172.173.152.48 (private 10.0.2.4)",
        "content": (
            "Azure prod ERP in resource group rg-erp-prod, region eastus. App VM vm-erp-prod-app "
            "(Standard_B2s) public 20.172.141.25 / private 10.0.1.4 runs Spring Boot erp-backend on "
            ":8080 behind nginx :80. DB VM vm-erp-prod-db (Standard_B2s) public 172.173.152.48 / private "
            "10.0.2.4 runs MySQL 8 (database erpdb) on :3306, reachable only from the VNet. SSH user "
            "azureuser. URL http://20.172.141.25/ ; health http://20.172.141.25/actuator/health. Active "
            "Spring profile prod (ddl-auto validate). Monitored by Datadog (host erp-azure-app-server-prod / "
            "erp-azure-db-server-prod)."
        ),
    },
    {
        "id": "infra-aws-dev",
        "title": "AWS dev environment (us-east-1)",
        "cloud": "AWS", "env": "dev", "service": "erp-system",
        "host": "app 100.58.249.226 (private 172.31.2.244); db 44.211.188.169 (private 172.31.1.227)",
        "content": (
            "AWS dev ERP in the default VPC, region us-east-1. App EC2 (t3.micro) public 100.58.249.226 / "
            "private 172.31.2.244 runs Spring Boot erp-backend on :8080 behind nginx :80. DB EC2 (t3.micro) "
            "public 44.211.188.169 / private 172.31.1.227 runs MySQL 8 (database erpdb) on :3306, reachable "
            "only from the VPC. SSH user ubuntu. URL http://100.58.249.226/ ; health "
            "http://100.58.249.226/actuator/health. Monitored by Grafana Cloud (host erp-aws-app-server-dev / "
            "erp-aws-db-server-dev)."
        ),
    },
    {
        "id": "infra-aws-prod",
        "title": "AWS prod environment (us-east-1)",
        "cloud": "AWS", "env": "prod", "service": "erp-system",
        "host": "app 3.228.22.2 (private 172.31.12.245); db 44.197.147.167 (private 172.31.8.39)",
        "content": (
            "AWS prod ERP in the default VPC, region us-east-1. App EC2 (t3.micro) public 3.228.22.2 / private "
            "172.31.12.245 runs Spring Boot erp-backend on :8080 behind nginx :80. DB EC2 (t3.micro) public "
            "44.197.147.167 / private 172.31.8.39 runs MySQL 8 (database erpdb) on :3306, reachable only from "
            "the VPC. SSH user ubuntu. URL http://3.228.22.2/ ; health http://3.228.22.2/actuator/health. "
            "Monitored by Datadog (host erp-aws-app-server-prod / erp-aws-db-server-prod)."
        ),
    },
    {
        "id": "infra-platform-stack",
        "title": "ERP application & data stack (all environments)",
        "cloud": "Azure+AWS", "env": "all", "service": "erp-system",
        "host": "app :80 nginx, :8080 backend; db :3306 MySQL (private only)",
        "content": (
            "Backend: Spring Boot 3.2.5 on Java 17, packaged as erp-system-1.0.0.jar, runs as systemd service "
            "erp-backend under user erp. Frontend: React 18 + Vite, served by nginx 1.18 from /var/www/erp; "
            "nginx proxies /api/ and /actuator/ to 127.0.0.1:8080. Database: MySQL 8, database name erpdb "
            "everywhere, app user erp_app@% with ALL on erpdb.*, tables customers/products/orders/order_items, "
            "bind-address 0.0.0.0:3306 reachable only from the private CIDR. Ports: 22 SSH, 80 nginx, 8080 "
            "backend (debug), 3306 MySQL (private only), 443 reserved (no TLS yet)."
        ),
    },
    {
        "id": "infra-devops-commander",
        "title": "DevOps Commander platform (agent fleet + alert receiver)",
        "cloud": "Azure", "env": "prod", "service": "devops-commander",
        "host": "func-devops-commander-prod-4bsnhc.azurewebsites.net",
        "content": (
            "Azure-native control plane for the agents. Resource group rg-devops-commander-prod, region eastus. "
            "Function App func-devops-commander-prod-4bsnhc (Python 3.11, Linux Y1 Consumption) receives Datadog/"
            "Grafana webhooks at POST /api/alert (header X-Alert-Token) and exposes GET /api/health. User-assigned "
            "identity id-devops-commander-prod authenticates keyless to GPT-4o. Foundry (AIServices) resource "
            "devops-commanderv1 in resource group devops-commander hosts project devops-commander with model "
            "deployment gpt-4o. App Insights appi-devops-commander-prod. The agent fleet (coordinator + diagnosis + "
            "remediation + risk) runs server-side on the Foundry project."
        ),
    },
]

# --- Implementation history --------------------------------------------------
HISTORY = [
    {
        "id": "history-provisioning",
        "title": "Infrastructure provisioning history",
        "cloud": "Azure+AWS", "env": "all", "service": "erp-system",
        "host": "",
        "content": (
            "All 4 ERP environments were provisioned with Terraform via the reusable workflow "
            "PixelTech-Solutions/Terraform terraform.yml (Azure via OIDC, AWS via access keys). Azure dev and prod "
            "and AWS dev and prod all applied OK (AWS needed a security-group name fix because names cannot start "
            "with sg-). Terraform state lives in azurerm storage account stpixeltechstate, container tfstate, RG "
            "rg-terraform-state, key pattern erp-system/<cloud>/<env>/terraform.tfstate. App config is applied by "
            "Ansible (ERP_System deploy-ansible.yml: resolve -> build -> configure-database -> deploy-application -> "
            "smoke-test)."
        ),
    },
    {
        "id": "history-monitoring",
        "title": "Monitoring and alerting setup",
        "cloud": "Azure+AWS", "env": "all", "service": "monitoring",
        "host": "",
        "content": (
            "Datadog (site us5.datadoghq.com, agent v7) covers production; Grafana Cloud (region prod-ap-southeast-1, "
            "grafana-agent + node-exporter on :9100) covers development. Both push from the VMs, no inbound ports. "
            "Hosts follow erp-<cloud>-<role>-<env>; metrics carry labels env, cloud, service=erp-system, role. Alert "
            "rules: prod-backend-down and prod-5xx-spike (Datadog), dev-backend-down and dev-error-log-spike "
            "(Grafana). Alerts originally went to webhook.site and now POST to the DevOps Commander /api/alert "
            "endpoint, which hands off to the agent fleet."
        ),
    },
    {
        "id": "history-agents",
        "title": "DevOps Commander agent fleet history",
        "cloud": "Azure", "env": "prod", "service": "devops-commander",
        "host": "",
        "content": (
            "Step 5 added the first Foundry agent plus the alert webhook. Step 6 introduced the Connected Agents "
            "pattern: a coordinator (devops-commander-coordinator) delegates to specialists devops-commander-rca "
            "(diagnosis) and devops-commander-remediation. Step 7 added devops-commander-risk, an independent "
            "reviewer, plus a deterministic code-side human-in-the-loop gate that holds any destructive, "
            "high/critical, or needs-human action for a human. Auth is keyless via the Function App managed identity "
            "(Foundry User role); no API keys are stored. Step 8 grounds the diagnosis agent in this Azure AI Search "
            "knowledge base."
        ),
    },
]

# --- Past incidents and captured gotchas -------------------------------------
INCIDENTS = [
    {
        "id": "inc-ssh-banner",
        "title": "SSH 'connection timed out during banner exchange'",
        "cloud": "Azure", "env": "prod", "service": "app-server", "severity": "high",
        "content": (
            "Symptom: SSH hangs with 'Connection timed out during banner exchange' even though TCP/22 connects. "
            "Root cause: sshd is hung or the VM is out of memory or disk. Resolution: use the Azure Serial Console "
            "(portal -> VM -> Help -> Serial console) to log in out-of-band, then free disk/memory or restart sshd."
        ),
    },
    {
        "id": "inc-mysql-bind-restart",
        "title": "MySQL bind-address change needs a restart",
        "cloud": "Azure+AWS", "env": "all", "service": "mysql", "severity": "high",
        "content": (
            "Symptom: app cannot reach MySQL after a config change. Root cause: changing MySQL bind-address requires "
            "a service restart, and Ansible skips handlers when a play fails partway. Resolution: set "
            "force_handlers: true and add an explicit 'ss -tlnH sport = :3306' check so db.yml self-heals and the "
            "restart actually happens."
        ),
    },
    {
        "id": "inc-prod-ddl-validate",
        "title": "Prod backend fails to start (ddl-auto validate)",
        "cloud": "Azure+AWS", "env": "prod", "service": "erp-backend", "severity": "high",
        "content": (
            "Symptom: prod backend won't start or errors on schema validation. Root cause: the prod profile uses "
            "ddl-auto: validate, so the schema must already exist; the dev/H2 happy path hides this. Resolution: "
            "import db/schema.sql (via ansible db.yml) before starting erp-backend in prod."
        ),
    },
    {
        "id": "inc-hibernate-enum",
        "title": "Hibernate enum mapped to native MySQL ENUM",
        "cloud": "Azure+AWS", "env": "all", "service": "erp-backend", "severity": "medium",
        "content": (
            "Symptom: schema validation / insert errors on the orders table OrderStatus column. Root cause: "
            "Hibernate maps the OrderStatus enum to a native MySQL ENUM, but the schema uses VARCHAR(20). "
            "Resolution: annotate the field with @JdbcTypeCode(SqlTypes.VARCHAR) and @Column(length=20)."
        ),
    },
    {
        "id": "inc-aws-sg-name",
        "title": "AWS security group name cannot start with sg-",
        "cloud": "AWS", "env": "all", "service": "network", "severity": "low",
        "content": (
            "Symptom: Terraform apply fails creating the security group. Root cause: AWS reserves the sg- prefix for "
            "security group IDs, so a name cannot start with sg-. Resolution: name groups <prefix>-app-sg and "
            "<prefix>-db-sg."
        ),
    },
    {
        "id": "inc-func-404-deps",
        "title": "Function App returns 404 (no functions discovered)",
        "cloud": "Azure", "env": "prod", "service": "devops-commander", "severity": "high",
        "content": (
            "Symptom: every endpoint on the Function App returns 404 and no functions are discovered. Root cause: "
            "Linux Consumption (Y1) with RBAC/run-from-package deploys bypass Kudu/Oryx, so requirements.txt is not "
            "installed remotely and the Python worker can't import azure-functions. Resolution: in the deploy "
            "workflow run 'pip install -r requirements.txt --target=.python_packages/lib/site-packages' before "
            "publishing the zip."
        ),
    },
    {
        "id": "inc-grafana-loki-url",
        "title": "Grafana Cloud Loki push URL missing path",
        "cloud": "Azure+AWS", "env": "dev", "service": "monitoring", "severity": "low",
        "content": (
            "Symptom: logs never arrive in Grafana Cloud Loki. Root cause: the Cloud UI only shows the base URL; the "
            "Loki push URL must end with /loki/api/v1/push. Note Grafana Cloud has two different numeric basic-auth "
            "users, one for Prometheus (Mimir) and one for Loki. Resolution: append the path and use the correct "
            "per-service user."
        ),
    },
    {
        "id": "inc-mysql-conn-pool",
        "title": "MySQL prod unreachable - connection pool exhausted",
        "cloud": "Azure", "env": "prod", "service": "mysql", "severity": "critical",
        "content": (
            "Symptom: app returns 'too many connections', health checks fail, database connectivity alerts fire. "
            "Root cause: the connection pool was exhausted after a traffic spike and idle connections were never "
            "recycled. Resolution: raise max_connections, set a sane pool TTL in the app, and restart MySQL to clear "
            "stuck connections (human-approved)."
        ),
    },
    {
        "id": "inc-nginx-502-oom",
        "title": "nginx 502 Bad Gateway - backend OOM",
        "cloud": "AWS", "env": "prod", "service": "nginx", "severity": "high",
        "content": (
            "Symptom: intermittent 502s; nginx logs show 'upstream prematurely closed connection'. Root cause: the "
            "Spring Boot backend was OOM-killed and stopped accepting requests. Resolution: raise the JVM/container "
            "memory, fix the leak, and restart erp-backend (human-approved)."
        ),
    },
    {
        "id": "inc-disk-full-logs",
        "title": "Disk full on the application server",
        "cloud": "Azure", "env": "prod", "service": "app-server", "severity": "medium",
        "content": (
            "Symptom: writes fail with 'No space left on device'; background jobs stop. Root cause: nginx and "
            "application logs were never rotated and filled the data disk. Resolution: enable logrotate with "
            "compression and retention and ship verbose logs off-box."
        ),
    },
    {
        "id": "inc-latency-missing-index",
        "title": "High API latency after a release",
        "cloud": "AWS", "env": "prod", "service": "erp-backend", "severity": "high",
        "content": (
            "Symptom: p95 latency jumped from ~120ms to ~3s right after a deploy; MySQL shows full table scans. Root "
            "cause: a schema migration dropped a composite index a hot query depended on. Resolution: recreate the "
            "index and add a CI check for dropped indexes."
        ),
    },
    {
        "id": "inc-tls-cert-expired",
        "title": "TLS certificate expired at the edge",
        "cloud": "Azure", "env": "prod", "service": "edge-tls", "severity": "high",
        "content": (
            "Symptom: browsers show NET::ERR_CERT_DATE_INVALID and API clients reject the connection. Root cause: "
            "the automated certificate renewal job failed silently. Resolution: renew the certificate, fix the "
            "renewal job, and add an expiry alert 30 days out."
        ),
    },
]


def _docs() -> list[dict]:
    out: list[dict] = []
    for d in INFRA:
        out.append({"doc_type": "infra", "severity": "", **d})
    for d in HISTORY:
        out.append({"doc_type": "history", "severity": "", **d})
    for d in INCIDENTS:
        out.append({"doc_type": "incident", "host": "", **d})
    return out


def _request(method: str, url: str, key: str, body: dict | None) -> None:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    req.add_header("api-key", key)
    try:
        with urllib.request.urlopen(req) as resp:
            print(f"  {method} {resp.status} {resp.reason}")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")
        print(f"  {method} FAILED {exc.code}: {detail}", file=sys.stderr)
        raise


def _seed_blob_indexers(endpoint: str, key: str, conn: str) -> None:
    """Create the data sources + indexers for company docs (B) and logs (C).

    Both indexers write into the same `erp-knowledge` index. Re-running is
    idempotent (PUT replaces the definition); a final run kicks off ingestion.
    """
    # B -- company documents (text extraction from the uploaded files).
    print("Configuring company-docs indexer (B)...")
    _request("PUT", f"{endpoint}/datasources/erp-docs-ds?api-version={API_VERSION}", key, {
        "name": "erp-docs-ds",
        "type": "azureblob",
        "credentials": {"connectionString": conn},
        "container": {"name": DOCS_CONTAINER},
    })
    _request("PUT", f"{endpoint}/indexers/erp-docs-indexer?api-version={API_VERSION}", key, {
        "name": "erp-docs-indexer",
        "dataSourceName": "erp-docs-ds",
        "targetIndexName": INDEX_NAME,
        "parameters": {"configuration": {"dataToExtract": "contentAndMetadata"}},
        "fieldMappings": [
            {"sourceFieldName": "metadata_storage_path", "targetFieldName": "id",
             "mappingFunction": {"name": "base64Encode"}},
            {"sourceFieldName": "metadata_storage_name", "targetFieldName": "title"},
            {"sourceFieldName": "metadata_storage_name", "targetFieldName": "source"},
        ],
    })
    _request("POST", f"{endpoint}/indexers/erp-docs-indexer/run?api-version={API_VERSION}", key, None)

    # C -- previous logs (one JSON object per line; fields map by name).
    print("Configuring previous-logs indexer (C)...")
    _request("PUT", f"{endpoint}/datasources/erp-logs-ds?api-version={API_VERSION}", key, {
        "name": "erp-logs-ds",
        "type": "azureblob",
        "credentials": {"connectionString": conn},
        "container": {"name": LOGS_CONTAINER},
    })
    _request("PUT", f"{endpoint}/indexers/erp-logs-indexer?api-version={API_VERSION}", key, {
        "name": "erp-logs-indexer",
        "dataSourceName": "erp-logs-ds",
        "targetIndexName": INDEX_NAME,
        "parameters": {"configuration": {"parsingMode": "jsonLines"}},
    })
    _request("POST", f"{endpoint}/indexers/erp-logs-indexer/run?api-version={API_VERSION}", key, None)


def main() -> int:
    endpoint = os.environ.get("SEARCH_ENDPOINT", "").rstrip("/")
    key = os.environ.get("SEARCH_ADMIN_KEY", "")
    if not endpoint or not key:
        print("Set SEARCH_ENDPOINT and SEARCH_ADMIN_KEY first.", file=sys.stderr)
        return 2

    print(f"Creating/updating index '{INDEX_NAME}'...")
    _request(
        "PUT",
        f"{endpoint}/indexes/{INDEX_NAME}?api-version={API_VERSION}",
        key,
        INDEX_DEFINITION,
    )

    docs = _docs()
    print(f"Uploading {len(docs)} knowledge records...")
    payload = {"value": [{"@search.action": "mergeOrUpload", **doc} for doc in docs]}
    _request(
        "POST",
        f"{endpoint}/indexes/{INDEX_NAME}/docs/index?api-version={API_VERSION}",
        key,
        payload,
    )

    conn = os.environ.get("KNOWLEDGE_STORAGE_CONNECTION_STRING")
    if conn:
        _seed_blob_indexers(endpoint, key, conn)
    else:
        print("KNOWLEDGE_STORAGE_CONNECTION_STRING not set; skipping blob indexers (B/C).")

    print("Done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
