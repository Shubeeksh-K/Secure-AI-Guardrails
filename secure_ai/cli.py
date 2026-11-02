"""Local interactive runner for Secure AI."""

from __future__ import annotations

import asyncio

from secure_ai.adk_agent import SecureAISession
from secure_ai.settings import Settings


async def _chat() -> None:
    settings = Settings.from_env()
    settings.require_gateway_key()
    session = SecureAISession(settings)
    await session.start()
    print("Secure AI is ready. Type 'exit' to stop.")
    try:
        while True:
            message = input("You: ").strip()
            if message.casefold() in {"exit", "quit"}:
                break
            if not message:
                continue
            reply = await session.send(message)
            print(f"Secure AI: {reply}")
    finally:
        session.close()


def main() -> None:
    """Console-script entry point for `secure-ai`."""
    asyncio.run(_chat())


if __name__ == "__main__":
    main()
