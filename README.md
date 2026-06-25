# DevOps Commander — Function App (alert receiver)

Single Python Function App that ingests alert webhooks from Datadog (prod) and Grafana Cloud (dev) and writes them to Application Insights. Becomes the entry point of the agent orchestrator in Step 7.

## Endpoints

| Method | Route          | Purpose                                                    |
|--------|----------------|------------------------------------------------------------|
| POST   | `/api/alert`   | Webhook sink. Requires header `X-Alert-Token: <secret>`.   |
| GET    | `/api/health`  | Liveness probe (no auth).                                  |

## How to deploy

Infrastructure lives in `Project/DevOps-Commander-Infra/`. First run that repo's `Provision DevOps-Commander (Azure)` workflow to create the Function App, then come back here and:

1. Copy the `function_app_name` Terraform output → set as repo Variable `FUNCTION_APP_NAME` in this repo.
2. Run the `Deploy Function (Alert Receiver)` workflow here (workflow_dispatch).
3. After deploy, hit `GET https://<function_app_name>.azurewebsites.net/api/health` — should return `{"status":"ok"}`.

## How to wire Datadog / Grafana

Both tools must send the shared-secret header. Retrieve it from:
**Azure Portal → Function App → Settings → Environment variables → `ALERT_SHARED_SECRET` → Show value.**

### Datadog Webhooks integration

- Integrations → Webhooks → New
- URL: `https://<function_app_name>.azurewebsites.net/api/alert`
- Custom headers (JSON):
  ```json
  { "X-Alert-Token": "<paste secret here>" }
  ```

### Grafana Cloud contact point

- Alerts & IRM → Alerting → Contact points → Add
- Integration: Webhook
- URL: same as above
- HTTP Method: POST
- Authorization Header — Custom header: name `X-Alert-Token`, value `<paste secret>`

## Local dev

```powershell
cp local.settings.json.example local.settings.json
func start
```

Test:

```powershell
curl -X POST http://localhost:7071/api/alert `
     -H "Content-Type: application/json" `
     -H "X-Alert-Token: change-me-locally" `
     -d '{"alert":"test"}'
```

## App Insights query

```kusto
traces
| where timestamp > ago(1h)
| where message startswith "alert_received "
| extend payload = parse_json(substring(message, strlen("alert_received ")))
| project timestamp, source = tostring(payload.source), alert = payload.payload
| order by timestamp desc
```
