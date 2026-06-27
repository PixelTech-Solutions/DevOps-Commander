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

from botbuilder.core import (
    ActivityHandler,
    MessageFactory,
    TurnContext,
)
from botbuilder.integration.aiohttp import (
    CloudAdapter,
    ConfigurationBotFrameworkAuthentication,
)
from botbuilder.schema import Activity, ChannelAccount


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
        text = (turn_context.activity.text or "").strip()
        if not text:
            return

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
