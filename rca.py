"""Root-cause analysis via the Azure AI Foundry Agent Service.

This is the first agent of the DevOps Commander fleet. It uses the GA Foundry
Agent Service (a persistent agent + threads + runs) through the
azure-ai-projects SDK, authenticated keyless with the Function App's
user-assigned managed identity (granted the Foundry User role on the project).
No API key is read or stored. AZURE_CLIENT_ID (an app setting) tells the
credential which user-assigned identity to use.

A single persistent agent ("devops-commander-rca") is created once and reused
across invocations. Each alert gets its own thread (one incident = one
conversation) so analyses never bleed into each other.
"""

from __future__ import annotations

import json
import logging
import os
from functools import lru_cache

from azure.ai.agents.models import ListSortOrder, MessageRole
from azure.ai.projects import AIProjectClient
from azure.identity import DefaultAzureCredential

_AGENT_NAME = "devops-commander-rca"

_INSTRUCTIONS = (
    "You are DevOps Commander, an SRE incident assistant for a multi-cloud ERP "
    "system running on Azure and AWS. Given a single monitoring alert, reply with "
    "exactly three short lines:\n"
    "Root cause: <one sentence, most likely cause>\n"
    "Severity: <low|medium|high|critical>\n"
    "Next command: <one concrete diagnostic command to run>\n"
    "Be concise and concrete. If the alert is ambiguous, state the one extra "
    "signal you would check."
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


@lru_cache(maxsize=1)
def _agent_id() -> str:
    """Return the RCA agent's id, creating it once if it doesn't exist.

    Reuses an agent with our well-known name when present so repeated cold
    starts don't pile up duplicate agents in the project.
    """
    client = _client()
    for agent in client.agents.list_agents():
        if agent.name == _AGENT_NAME:
            return agent.id
    model = os.environ.get("AZURE_OPENAI_DEPLOYMENT", "gpt-4o")
    created = client.agents.create_agent(
        model=model,
        name=_AGENT_NAME,
        instructions=_INSTRUCTIONS,
    )
    return created.id


def _build_user_message(event: dict) -> str:
    source = event.get("source", "unknown")
    payload = event.get("payload")
    body = json.dumps(payload, default=str)[:4000]
    return f"Alert source: {source}\nAlert payload:\n{body}"


def _extract_answer(messages) -> str | None:
    """Return the text of the most recent assistant message, or None."""
    answer = None
    for message in messages:
        if message.role != MessageRole.AGENT:
            continue
        for content in message.content:
            text = getattr(content, "text", None)
            value = getattr(text, "value", None) if text else None
            if value:
                answer = value
    return answer


def analyze_alert(event: dict) -> str | None:
    """Run the RCA agent over an alert and return its analysis, or None.

    Best-effort: any error is logged and swallowed so the caller can still
    acknowledge the webhook.
    """
    try:
        client = _client()
        agent_id = _agent_id()
        thread = client.agents.threads.create()
        try:
            client.agents.messages.create(
                thread_id=thread.id,
                role="user",
                content=_build_user_message(event),
            )
            run = client.agents.runs.create_and_process(
                thread_id=thread.id,
                agent_id=agent_id,
            )
            if run.status == "failed":
                logging.error("agent_run_failed %s", getattr(run, "last_error", None))
                return None
            messages = client.agents.messages.list(
                thread_id=thread.id,
                order=ListSortOrder.ASCENDING,
            )
            return _extract_answer(messages)
        finally:
            # One incident = one thread; clean it up so the project stays tidy.
            try:
                client.agents.threads.delete(thread.id)
            except Exception:
                logging.debug("thread_cleanup_failed", exc_info=True)
    except Exception:
        logging.exception("agent_rca_failed")
        return None
