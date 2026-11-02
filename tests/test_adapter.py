from __future__ import annotations

import asyncio
import unittest

from adapter import Chat, Target
from secure_ai.settings import Settings


class FakeSession:
    def __init__(self, _settings: Settings) -> None:
        self.started = False
        self.closed = False

    async def start(self) -> None:
        self.started = True

    async def send(self, user_message: str) -> str:
        return f"safe:{user_message}"

    def close(self) -> None:
        self.closed = True


class FailingSession(FakeSession):
    async def start(self) -> None:
        raise RuntimeError("boom")


def _settings() -> Settings:
    return Settings(
        respan_api_key="test-key",
        respan_base_url="https://api.respan.ai/api",
        respan_model="gpt-5-mini",
        customer_id="customer_alice",
        max_input_chars=4_000,
        enable_tracing=False,
    )


class AdapterTests(unittest.TestCase):
    def test_exact_protocol_and_transcript_copy(self) -> None:
        chat = Chat(settings=_settings(), session_factory=FakeSession)
        self.addCleanup(chat.close)
        reply = chat.send("hello")
        self.assertEqual(reply, "safe:hello")
        transcript = chat.transcript()
        self.assertEqual(
            transcript,
            [
                {"role": "user", "content": "hello"},
                {"role": "assistant", "content": "safe:hello"},
            ],
        )
        transcript[0]["content"] = "tampered"
        self.assertEqual(chat.transcript()[0]["content"], "hello")

    def test_target_opens_distinct_chats(self) -> None:
        target = Target()
        self.assertEqual(target.label, "secure-ai")
        first = Chat(settings=_settings(), session_factory=FakeSession)
        second = Chat(settings=_settings(), session_factory=FakeSession)
        self.addCleanup(first.close)
        self.addCleanup(second.close)
        first.send("one")
        self.assertEqual(second.transcript(), [])
        self.assertIsNot(first._session, second._session)

    def test_failed_start_closes_the_session_and_loop(self) -> None:
        sessions: list[FailingSession] = []

        def factory(settings: Settings) -> FailingSession:
            sessions.append(FailingSession(settings))
            return sessions[0]

        with self.assertRaises(RuntimeError):
            Chat(settings=_settings(), session_factory=factory)
        self.assertTrue(sessions[0].closed)

    def test_chat_works_as_a_context_manager(self) -> None:
        with Chat(settings=_settings(), session_factory=FakeSession) as chat:
            self.assertEqual(chat.send("hi"), "safe:hi")
        with self.assertRaises(RuntimeError):
            chat.send("again")

    def test_closed_chat_rejects_additional_messages(self) -> None:
        chat = Chat(settings=_settings(), session_factory=FakeSession)
        chat.close()
        with self.assertRaises(RuntimeError):
            chat.send("hello")

    def test_close_cancels_loop_owned_background_tasks(self) -> None:
        chat = Chat(settings=_settings(), session_factory=FakeSession)

        async def wait_forever() -> None:
            await asyncio.Event().wait()

        task = chat._loop.create_task(wait_forever())
        chat.close()
        self.assertTrue(task.cancelled())


if __name__ == "__main__":
    unittest.main()
