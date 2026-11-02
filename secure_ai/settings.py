"""Environment-backed application settings."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

from dotenv import load_dotenv

_CUSTOMER_ID = re.compile(r"^[a-z][a-z0-9_]{2,63}$")


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
    """Validated runtime configuration, loaded once from the environment (and `.env`)."""

    respan_api_key: str
    respan_base_url: str
    respan_model: str
    customer_id: str
    max_input_chars: int
    enable_tracing: bool

    @classmethod
    def from_env(cls) -> Settings:
        """Read and validate settings; raise `ValueError` on malformed values."""
        load_dotenv()
        try:
            max_input = int(_value("SECURE_AI_MAX_INPUT_CHARS", "4000"))
        except ValueError:
            raise ValueError("SECURE_AI_MAX_INPUT_CHARS must be an integer") from None
        if not 100 <= max_input <= 20_000:
            raise ValueError("SECURE_AI_MAX_INPUT_CHARS must be between 100 and 20000")
        customer_id = _value("SECURE_AI_CUSTOMER_ID", "customer_alice")
        if not _CUSTOMER_ID.fullmatch(customer_id):
            raise ValueError("SECURE_AI_CUSTOMER_ID must be a lowercase identifier")
        return cls(
            respan_api_key=_value("RESPAN_API_KEY"),
            respan_base_url=_value("RESPAN_BASE_URL", "https://api.respan.ai/api").rstrip("/"),
            respan_model=_value("RESPAN_MODEL", "gpt-5-mini"),
            customer_id=customer_id,
            max_input_chars=max_input,
            enable_tracing=_boolean("SECURE_AI_ENABLE_TRACING", True),
        )

    def require_gateway_key(self) -> None:
        """Raise `RuntimeError` when no gateway key is configured (needed for any model call)."""
        if not self.respan_api_key:
            raise RuntimeError(
                "RESPAN_API_KEY is missing. Add it to .env before running the agent."
            )
