"""Environment-backed application settings."""

from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv


def _value(name: str, default: str = "") -> str:
    value = os.getenv(name, "").strip()
    return value or default


def _boolean(name: str, default: bool) -> bool:
    value = _value(name)
    if not value:
        return default
    return value.casefold() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    respan_api_key: str
    respan_base_url: str
    respan_model: str
    customer_id: str
    max_input_chars: int
    enable_tracing: bool

    @classmethod
    def from_env(cls) -> Settings:
        load_dotenv()
        max_input = int(_value("SECURE_AI_MAX_INPUT_CHARS", "4000"))
        if not 100 <= max_input <= 20_000:
            raise ValueError("SECURE_AI_MAX_INPUT_CHARS must be between 100 and 20000")
        return cls(
            respan_api_key=_value("RESPAN_API_KEY"),
            respan_base_url=_value("RESPAN_BASE_URL", "https://api.respan.ai/api").rstrip("/"),
            respan_model=_value("RESPAN_MODEL", "gpt-5-mini"),
            customer_id=_value("SECURE_AI_CUSTOMER_ID", "customer_alice"),
            max_input_chars=max_input,
            enable_tracing=_boolean("SECURE_AI_ENABLE_TRACING", True),
        )

    def require_gateway_key(self) -> None:
        if not self.respan_api_key:
            raise RuntimeError(
                "RESPAN_API_KEY is missing. Add it to .env before running the agent."
            )
