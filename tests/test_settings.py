from __future__ import annotations

import os
import unittest
from unittest import mock

from secure_ai.settings import Settings


class SettingsTests(unittest.TestCase):
    def _load(self, **env: str) -> Settings:
        with (
            mock.patch.dict(os.environ, env, clear=True),
            mock.patch("secure_ai.settings.load_dotenv"),
        ):
            return Settings.from_env()

    def test_defaults(self) -> None:
        settings = self._load()
        self.assertEqual(settings.customer_id, "customer_alice")
        self.assertEqual(settings.max_input_chars, 4_000)
        self.assertTrue(settings.enable_tracing)

    def test_rejects_non_numeric_and_out_of_range_limits(self) -> None:
        for bad in ("abc", "5", "999999"):
            with self.assertRaises(ValueError):
                self._load(SECURE_AI_MAX_INPUT_CHARS=bad)

    def test_rejects_malformed_customer_id(self) -> None:
        with self.assertRaises(ValueError):
            self._load(SECURE_AI_CUSTOMER_ID="Alice; DROP")

    def test_require_gateway_key(self) -> None:
        with self.assertRaises(RuntimeError):
            self._load().require_gateway_key()
        self._load(RESPAN_API_KEY="k").require_gateway_key()


if __name__ == "__main__":
    unittest.main()
