"""Respan Red Team adapter for the local Secure AI agent.

The remote engine sends only user-message strings. Every ``TARGET.open()`` call
creates a fresh ADK session and a fresh in-memory SQLite sandbox.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from typing import Protocol

from secure_ai.adk_agent import SecureAISession
from secure_ai.settings import Settings

logger = logging.getLogger(__name__)
SAFE_ERROR = "I couldn't complete that request safely. Please try a supported operation."


class SessionLike(Protocol):
    async def start(self) -> None: ...

    async def send(self, user_message: str) -> str: ...

    def close(self) -> None: ...


class Chat:
    """Synchronous protocol wrapper around one asynchronous ADK conversation."""

    def __init__(
        self,
        *,
        settings: Settings | None = None,
        session_factory: Callable[[Settings], SessionLike] = SecureAISession,
    ) -> None:
        self._settings = settings or Settings.from_env()
        self._settings.require_gateway_key()
        self._session = session_factory(self._settings)
        self._turns: list[dict[str, str]] = []
        self._loop = asyncio.new_event_loop()
        self._closed = False
        self._loop.run_until_complete(self._session.start())

    def send(self, user_message: str) -> str:
        """Send exactly one user message and return one assistant reply string."""
        if self._closed:
            raise RuntimeError("This red-team conversation is closed.")
        if not isinstance(user_message, str):
            raise TypeError("user_message must be a string")

        self._turns.append({"role": "user", "content": user_message})
        try:
            reply = self._loop.run_until_complete(self._session.send(user_message))
        except Exception:
            # Keep provider, framework, and database details out of the attack surface.
            logger.exception("Secure AI adapter turn failed")
            reply = SAFE_ERROR
        if not isinstance(reply, str) or not reply:
            reply = SAFE_ERROR
        self._turns.append({"role": "assistant", "content": reply})
        return reply

    def transcript(self) -> list[dict[str, str]]:
        """Return a defensive copy of this attack's running transcript."""
        return [dict(turn) for turn in self._turns]

    def close(self) -> None:
        if self._closed:
            return
        try:
            self._session.close()
        finally:
            # LiteLLM may leave loop-owned logging workers alive after a model call.
            # Cancel and drain them before closing this attack's isolated loop so
            # one campaign cannot leak tasks or warnings into the next attack.
            pending = [task for task in asyncio.all_tasks(self._loop) if not task.done()]
            for task in pending:
                task.cancel()
            if pending:
                self._loop.run_until_complete(
                    asyncio.gather(*pending, return_exceptions=True)
                )
            self._loop.run_until_complete(self._loop.shutdown_asyncgens())
            self._loop.run_until_complete(self._loop.shutdown_default_executor())
            self._loop.close()
            self._closed = True


class Target:
    label = "secure-ai"

    def open(self) -> Chat:
        """Start a fresh, isolated conversation for one red-team attack."""
        return Chat()


TARGET = Target()
