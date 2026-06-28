#!/usr/bin/env python3
"""Seed the `erp-knowledge` Azure AI Search index (Step 8 RAG knowledge base).

The diagnosis agent grounds its analysis in this index. It holds three kinds of
records:

  * infra    -- the ERP environments (Azure/AWS x dev/prod) with public and
                private IPs, SKUs, URLs, services, plus the DevOps Commander
                platform itself.
  * history  -- implementation history: provisioning, monitoring, the agent fleet.
  * incident -- past incidents and the gotchas we hit, with their resolutions.

Keyword (SIMPLE) search is used, so no embeddings/vectors are needed.

The actual records (which contain real IPs, hostnames and account names) live in
an **untracked** JSON file so nothing sensitive is committed:

    tools/knowledge_data.local.json   (gitignored)

Copy `tools/knowledge_data.example.json` to that path and fill in your real
inventory, or point `KNOWLEDGE_DATA_FILE` at your own file.

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

# Untracked file holding the real infra/history/incident records. Override with
# KNOWLEDGE_DATA_FILE; defaults to tools/knowledge_data.local.json next to this
# script (which is gitignored).
KNOWLEDGE_DATA_FILE = os.environ.get("KNOWLEDGE_DATA_FILE") or os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "knowledge_data.local.json"
)

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


def _load_inventory() -> dict:
    """Load the infra/history/incident records from the untracked local JSON.

    The real inventory (IPs, hostnames, account names) is never committed. Copy
    tools/knowledge_data.example.json to tools/knowledge_data.local.json and
    fill it in, or set KNOWLEDGE_DATA_FILE.
    """
    if not os.path.exists(KNOWLEDGE_DATA_FILE):
        sys.exit(
            f"Knowledge data file not found: {KNOWLEDGE_DATA_FILE}\n"
            "Copy tools/knowledge_data.example.json to "
            "tools/knowledge_data.local.json and fill in your real inventory "
            "(or set KNOWLEDGE_DATA_FILE)."
        )
    with open(KNOWLEDGE_DATA_FILE, encoding="utf-8") as fh:
        return json.load(fh)


def _docs() -> list[dict]:
    data = _load_inventory()
    out: list[dict] = []
    for d in data.get("infra", []):
        out.append({"doc_type": "infra", "severity": "", **d})
    for d in data.get("history", []):
        out.append({"doc_type": "history", "severity": "", **d})
    for d in data.get("incidents", []):
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
