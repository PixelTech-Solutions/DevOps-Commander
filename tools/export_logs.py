#!/usr/bin/env python3
"""Export previous logs from Application Insights to NDJSON for the RAG index (C).

Each line is one JSON object whose keys already match the `erp-knowledge` index
schema, so the JSON-lines blob indexer maps them by name (no field mappings).

Run locally (uses the az CLI you're already logged into), then upload the file
to the knowledge-logs container:

    $env:APPINSIGHTS_APP_ID = "7c5db983-0911-453c-8419-0482d2938637"
    python tools/export_logs.py            # writes knowledge-logs.jsonl
    az storage blob upload --account-name <storage> --container-name knowledge-logs \
        --name knowledge-logs.jsonl --file knowledge-logs.jsonl --auth-mode login --overwrite

Only the Python standard library + the az CLI are used.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

APP_ID = os.environ.get("APPINSIGHTS_APP_ID", "")
DAYS = os.environ.get("LOG_DAYS", "30")
OUT = os.environ.get("LOG_OUT", "knowledge-logs.jsonl")

# Shape the rows to the index schema directly in KQL: id/doc_type/title/content/
# severity/source/timestamp. Function logs prefixed alert_/agent_ are the useful
# operational history; everything else is noise.
KQL = (
    "traces "
    f"| where timestamp > ago({DAYS}d) "
    "| where message startswith 'alert_' or message startswith 'agent_' "
    "| project id=itemId, doc_type='log', title=operation_Name, content=message, "
    "severity=tostring(severityLevel), source='app-insights', timestamp "
    "| order by timestamp desc "
    "| take 300"
)


def main() -> int:
    if not APP_ID:
        print("Set APPINSIGHTS_APP_ID first.", file=sys.stderr)
        return 2

    result = subprocess.run(
        ["az", "monitor", "app-insights", "query",
         "--app", APP_ID, "--analytics-query", KQL, "-o", "json"],
        capture_output=True, text=True, shell=(os.name == "nt"),
    )
    if result.returncode != 0:
        print(result.stderr, file=sys.stderr)
        return result.returncode

    table = json.loads(result.stdout)["tables"][0]
    cols = [c["name"] for c in table["columns"]]
    rows = table["rows"]

    written = 0
    with open(OUT, "w", encoding="utf-8") as f:
        for row in rows:
            record = dict(zip(cols, row))
            # Drop rows without a key or body.
            if not record.get("id") or not record.get("content"):
                continue
            f.write(json.dumps(record, default=str) + "\n")
            written += 1

    print(f"Wrote {written} log records to {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
