"""GPT-4o root-cause analysis for incoming alerts.

Keyless: authenticates to Azure OpenAI (Foundry) with the Function App's
user-assigned managed identity via DefaultAzureCredential. No API key is
read or stored. AZURE_CLIENT_ID (set as an app setting) tells the credential
which user-assigned identity to use.
"""

from __future__ import annotations

import json
import logging
import os
from functools import lru_cache

from azure.identity import DefaultAzureCredential, get_bearer_token_provider
from openai import AzureOpenAI

# Token audience for Azure Cognitive Services / Azure OpenAI data-plane calls.
_SCOPE = "https://cognitiveservices.azure.com/.default"

_SYSTEM_PROMPT = (
    "You are DevOps Commander, an SRE incident assistant for a multi-cloud ERP "
    "system running on Azure and AWS. Given a single monitoring alert, reply with "
    "exactly three short lines:\n"
    "Root cause: <one sentence, most likely cause>\n"
    "Severity: <low|medium|high|critical>\n"
    "Next command: <one concrete diagnostic command to run>\n"
    "Be concise and concrete. If the alert is ambiguous, state the one extra "
    "signal you would check."
)


def _base_endpoint(raw: str) -> str:
    """Normalise the configured endpoint to the base the AzureOpenAI client wants.

    The app setting may carry the OpenAI v1 surface
    (``https://<res>.services.ai.azure.com/openai/v1``); the AzureOpenAI client
    expects just the account base, so strip any ``/openai`` suffix.
    """
    value = (raw or "").rstrip("/")
    for suffix in ("/openai/v1", "/openai"):
        if value.endswith(suffix):
            value = value[: -len(suffix)]
    return value.rstrip("/")


@lru_cache(maxsize=1)
def _client() -> AzureOpenAI:
    endpoint = _base_endpoint(os.environ["AZURE_OPENAI_ENDPOINT"])
    api_version = os.environ.get("AZURE_OPENAI_API_VERSION", "2024-10-21")
    token_provider = get_bearer_token_provider(DefaultAzureCredential(), _SCOPE)
    return AzureOpenAI(
        azure_endpoint=endpoint,
        api_version=api_version,
        azure_ad_token_provider=token_provider,
    )


def is_enabled() -> bool:
    """True when the Azure OpenAI endpoint is configured."""
    return bool(os.environ.get("AZURE_OPENAI_ENDPOINT"))


def _build_user_message(event: dict) -> str:
    source = event.get("source", "unknown")
    payload = event.get("payload")
    body = json.dumps(payload, default=str)[:4000]
    return f"Alert source: {source}\nAlert payload:\n{body}"


def analyze_alert(event: dict) -> str | None:
    """Return GPT-4o's root-cause analysis for an alert, or None on failure.

    Best-effort: any error is logged and swallowed so the caller can still
    acknowledge the webhook.
    """
    deployment = os.environ.get("AZURE_OPENAI_DEPLOYMENT", "gpt-4o")
    try:
        resp = _client().chat.completions.create(
            model=deployment,
            temperature=0.2,
            max_tokens=300,
            messages=[
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": _build_user_message(event)},
            ],
        )
        return resp.choices[0].message.content
    except Exception:
        logging.exception("gpt4o_rca_failed")
        return None
