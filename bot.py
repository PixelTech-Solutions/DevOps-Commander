"""Bot Framework wiring for the DevOps Commander Web Chat front end.

A thin Bot Framework endpoint that forwards Web Chat messages to the same
coordinator brain used by ``/api/chat`` (``rca.analyze_chat``) and streams the
reply back to the channel. Authentication is *secretless*: the bot runs as the
Function App's user-assigned managed identity
(``MicrosoftAppType=UserAssignedMSI``), so there is no app password to store or
rotate. The modern ``CloudAdapter`` stack is used because the legacy
``BotFrameworkAdapter`` only understands password credentials.
"""

from __future__ import annotations

import logging
import os
import re

from botbuilder.core import (
    ActivityHandler,
    CardFactory,
    MessageFactory,
    TurnContext,
)
from botbuilder.integration.aiohttp import (
    CloudAdapter,
    ConfigurationBotFrameworkAuthentication,
)
from botbuilder.schema import Activity, ChannelAccount


# --- Destructive-intent detection (deterministic; the LLM never touches the
#     destructive path). When a user clearly asks to restart the service or
#     delete a customer, the bot itself mints the signed approval token and
#     shows an approval card. "The model proposes; the code disposes." ---
_RESTART_RE = re.compile(r"\brestart(?:ing|s|ed)?\b", re.I)
_SERVICE_RE = re.compile(r"\b(?:erp[-_ ]?backend|backend|service|server|app)\b", re.I)
_DELETE_RE = re.compile(r"\b(?:delete|remove|drop)\b", re.I)
_CUSTOMER_ID_RE = re.compile(r"customer\D*(\d+)", re.I)


def _detect_destructive(text: str) -> tuple[str, dict] | None:
    """Map an explicit destructive request to (action, params), else None.

    Only matches when intent is unambiguous; everything else falls through to
    the chat coordinator. Returning a match never executes anything — it just
    triggers the approval card, which still requires a human button click.
    """
    if _RESTART_RE.search(text) and _SERVICE_RE.search(text):
        return "restart_service", {}
    if _DELETE_RE.search(text) and "customer" in text.lower():
        match = _CUSTOMER_ID_RE.search(text)
        if match:
            return "delete_customer", {"id": int(match.group(1))}
    return None


def _approval_card(result: dict):
    """Build an Adaptive Card (Approve/Reject) from a ``request_action`` result.

    The signed, single-use token rides inside the Approve button's submit data,
    so clicking Approve simply hands the same token to ``approve_and_run`` — the
    card is a friendly front door to the existing token gate, nothing more.
    """
    summary = result.get("summary") or "This action requires approval."
    token = result.get("token") or ""
    mins = max(1, int(result.get("expires_in_seconds") or 600) // 60)
    card = {
        "type": "AdaptiveCard",
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "version": "1.4",
        "body": [
            {
                "type": "TextBlock",
                "text": "\u26a0\ufe0f Approval required",
                "weight": "Bolder",
                "size": "Medium",
                "color": "Warning",
                "wrap": True,
            },
            {"type": "TextBlock", "text": summary, "wrap": True},
            {
                "type": "TextBlock",
                "text": f"A human must approve this. The request expires in {mins} min.",
                "isSubtle": True,
                "spacing": "Small",
                "wrap": True,
            },
        ],
        "actions": [
            {
                "type": "Action.Submit",
                "title": "\u2705 Approve",
                "data": {"kind": "approval", "decision": "approve", "token": token},
            },
            {
                "type": "Action.Submit",
                "title": "\u274c Reject",
                "data": {"kind": "approval", "decision": "reject"},
            },
        ],
    }
    return CardFactory.adaptive_card(card)


class _BotConfig:
    """Bot Framework settings, read from Function app settings.

    For a user-assigned managed-identity bot, ``APP_ID`` is the identity's
    client id and ``APP_PASSWORD`` stays blank. ``AZURE_CLIENT_ID`` is already
    set for the same identity, so it is used as the fallback.
    """

    APP_ID = os.environ.get("MicrosoftAppId") or os.environ.get("AZURE_CLIENT_ID", "")
    APP_PASSWORD = os.environ.get("MicrosoftAppPassword", "")
    APP_TYPE = os.environ.get("MicrosoftAppType", "UserAssignedMSI")
    APP_TENANTID = os.environ.get("MicrosoftAppTenantId", "")


class _FunctionsCloudAdapter(CloudAdapter):
    """A CloudAdapter usable from an Azure Function (no aiohttp web server).

    ``CloudAdapter.process_activity(auth_header, activity, logic)`` works without
    an aiohttp request object, so the Function route can call it directly.
    """

    def __init__(self) -> None:
        super().__init__(ConfigurationBotFrameworkAuthentication(_BotConfig()))


async def _on_error(context: TurnContext, error: Exception) -> None:
    logging.exception("bot_turn_error %s", error)
    try:
        await context.send_activity(
            "Sorry, something went wrong handling that message."
        )
    except Exception:  # pragma: no cover - best effort
        logging.exception("bot_turn_error_send_failed")


class CommanderBot(ActivityHandler):
    """Forwards each user turn to the chat coordinator and replies with its answer.

    Web Chat keeps one Bot Framework conversation per browser session; we map
    that conversation id to the Foundry thread id (``conversation_id``) so the
    assistant keeps context across turns. The map is in-memory, which is fine
    for a single-instance demo front end.
    """

    def __init__(self) -> None:
        self._threads: dict[str, str] = {}

    async def on_message_activity(self, turn_context: TurnContext):
        activity = turn_context.activity

        # A tapped Approve/Reject button arrives as a message activity whose
        # ``value`` carries our submit data (text is usually empty).
        value = activity.value
        if isinstance(value, dict) and value.get("kind") == "approval":
            await self._handle_approval(turn_context, value)
            return

        text = (activity.text or "").strip()
        if not text:
            return

        # An explicit destructive request never reaches the LLM: the bot mints
        # the signed token and replies with an approval card instead.
        try:
            import executor

            if executor.is_enabled():
                detected = _detect_destructive(text)
                if detected:
                    await self._offer_approval(turn_context, *detected)
                    return
        except Exception:
            logging.exception("bot_destructive_detect_failed")

        await self._forward_to_agent(turn_context, text)

    async def _forward_to_agent(self, turn_context: TurnContext, text: str):
        """Send a non-destructive turn to the chat coordinator and reply."""
        convo = turn_context.activity.conversation
        convo_id = convo.id if convo else None
        thread_id = self._threads.get(convo_id) if convo_id else None

        reply = "Chat is temporarily unavailable. Please try again."
        try:
            import rca

            result = rca.analyze_chat(text, thread_id)
            if result:
                reply = result.get("reply") or reply
                new_thread = result.get("conversation_id")
                if convo_id and new_thread:
                    self._threads[convo_id] = new_thread
        except Exception:
            logging.exception("bot_chat_unavailable")

        await turn_context.send_activity(MessageFactory.text(reply))

    async def _offer_approval(
        self, turn_context: TurnContext, action: str, params: dict
    ):
        """Mint a single-use token for a destructive action and show the card."""
        import executor

        try:
            result = executor.request_action(action, "dev", params)
        except executor.ActionError as exc:
            await turn_context.send_activity(
                MessageFactory.text(f"I can't do that: {exc}")
            )
            return

        if result.get("requires_approval"):
            await turn_context.send_activity(
                MessageFactory.attachment(_approval_card(result))
            )
            return

        # Not actually destructive (allow-list changed): just report output.
        await turn_context.send_activity(
            MessageFactory.text(result.get("output") or "Done.")
        )

    async def _handle_approval(self, turn_context: TurnContext, value: dict):
        """Spend a token (Approve) or discard it (Reject) from a button tap."""
        if value.get("decision") == "reject":
            await turn_context.send_activity(
                MessageFactory.text("\u274c Cancelled \u2014 no action was taken.")
            )
            return

        token = value.get("token") or ""
        if not token:
            await turn_context.send_activity(
                MessageFactory.text(
                    "That approval is missing its token. Please request the "
                    "action again."
                )
            )
            return

        import executor

        try:
            result = executor.approve_and_run(token)
        except executor.ActionError as exc:
            await turn_context.send_activity(MessageFactory.text(f"\u274c {exc}"))
            return
        except Exception:
            logging.exception("bot_approve_failed")
            await turn_context.send_activity(
                MessageFactory.text("\u274c Approval failed unexpectedly.")
            )
            return

        output = (result.get("output") or "").strip() if isinstance(result, dict) else ""
        message = "\u2705 Approved and executed."
        if output:
            message = f"{message}\n\n{output}"
        await turn_context.send_activity(MessageFactory.text(message))

    async def on_members_added_activity(
        self, members_added: list[ChannelAccount], turn_context: TurnContext
    ):
        for member in members_added:
            if member.id != turn_context.activity.recipient.id:
                await turn_context.send_activity(
                    MessageFactory.text(
                        "Hi, I'm DevOps Commander. Ask me about ERP alerts, "
                        "service health, or what actions you can run on the dev "
                        "environment."
                    )
                )


_ADAPTER: _FunctionsCloudAdapter | None = None
_BOT: CommanderBot | None = None


def _get_adapter() -> _FunctionsCloudAdapter:
    global _ADAPTER
    if _ADAPTER is None:
        adapter = _FunctionsCloudAdapter()
        adapter.on_turn_error = _on_error
        _ADAPTER = adapter
    return _ADAPTER


def _get_bot() -> CommanderBot:
    global _BOT
    if _BOT is None:
        _BOT = CommanderBot()
    return _BOT


async def process(body: dict, auth_header: str):
    """Run one inbound Activity through the adapter.

    Returns an ``InvokeResponse`` (for invoke activities) or ``None`` for plain
    messages. Raises ``PermissionError`` if the request fails authentication.
    """
    activity = Activity().deserialize(body)
    adapter = _get_adapter()
    bot = _get_bot()
    return await adapter.process_activity(auth_header, activity, bot.on_turn)
