"""Deterministic input, tool, and output guardrails for the ADK lifecycle."""

from __future__ import annotations

import json
import re
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from google.adk.agents.callback_context import CallbackContext
from google.adk.models.llm_request import LlmRequest
from google.adk.models.llm_response import LlmResponse
from google.adk.tools.base_tool import BaseTool
from google.adk.tools.tool_context import ToolContext
from google.genai import types

from secure_ai.patterns import (
    BASE64_BLOCK,
    CONFUSABLES,
    EXTERNAL_SINK,
    INPUT_PATTERNS,
    MARKUP_SINK,
    MAX_TOOL_ARGS_BYTES,
    PROMPT_FINGERPRINTS,
    PROTECTED_ARGUMENTS,
    PROTECTED_RESULT_KEYS,
    SECRET_PATTERNS,
    TENANT_IDENTIFIER,
)

SAFE_REFUSAL = (
    "I can help with store policies, your orders, returns, and support tickets, "
    "but I can't help with that request."
)


@dataclass(frozen=True)
class GuardDecision:
    """Outcome of inspecting user text: `allowed` is False when any flag was raised."""

    allowed: bool
    flags: tuple[str, ...] = ()


def _normalize(text: str) -> str:
    """Fold look-alike forms and drop invisible characters that defeat pattern matching."""
    folded = unicodedata.normalize("NFKC", text).translate(CONFUSABLES)
    return "".join(ch for ch in folded if unicodedata.category(ch) != "Cf")


def _squash(text: str) -> str:
    """Reduce text to lowercase alphanumerics so spaced or punctuated copies still match."""
    return re.sub(r"[^a-z0-9]", "", text.casefold())


def inspect_user_text(text: str, max_chars: int) -> GuardDecision:
    """Flag oversized, injection-like, secret-seeking, or exfiltration-seeking user text.

    The length limit applies to the raw text; every pattern runs on the normalized text so
    invisible characters and homoglyphs cannot hide an attack. Raising any flag means the
    request is refused before the model sees it.
    """
    flags: list[str] = []
    if len(text) > max_chars:
        flags.append("input_too_large")
    text = _normalize(text)
    for name, pattern in INPUT_PATTERNS:
        if pattern.search(text):
            flags.append(name)
    if BASE64_BLOCK.search(text):
        flags.append("encoded_payload")
    return GuardDecision(not flags, tuple(flags))


def output_is_safe(text: str, canary: str) -> bool:
    """Return False when a model reply leaks the canary, the prompt, secrets, or a data sink.

    The canary is also compared with whitespace and punctuation removed, so a model coaxed
    into emitting it spaced out ("C-A-N-A-R-Y...") is still caught.
    """
    text = _normalize(text)
    if canary and (canary in text or _squash(canary) in _squash(text)):
        return False
    lowered = text.casefold()
    if any(fingerprint in lowered for fingerprint in PROMPT_FINGERPRINTS):
        return False
    if EXTERNAL_SINK.search(text) or MARKUP_SINK.search(text) or TENANT_IDENTIFIER.search(text):
        return False
    return not any(pattern.search(text) for pattern in SECRET_PATTERNS)


def _content_text(content: types.Content | None) -> str:
    """Concatenate the text parts of a message, ignoring function calls and responses."""
    if content is None:
        return ""
    return "".join(part.text or "" for part in content.parts or [] if part.text)


def _replacement_response(text: str) -> LlmResponse:
    """Build a model response that substitutes `text` for whatever would have been sent."""
    return LlmResponse(content=types.Content(role="model", parts=[types.Part(text=text)]))


def build_before_model_callback(
    max_input_chars: int,
) -> Callable[[CallbackContext, LlmRequest], LlmResponse | None]:
    """Create the ADK `before_model_callback` that refuses unsafe user input.

    Returning a response from the callback short-circuits the model call, so a blocked
    request never reaches the model. After a tool call the newest "user" content is the
    function response (no text), which inspects as empty; the original message was already
    checked on the first model call of the turn.
    """

    def before_model(_context: CallbackContext, request: LlmRequest) -> LlmResponse | None:
        latest_user_text = ""
        for content in reversed(request.contents):
            if content.role == "user":
                latest_user_text = _content_text(content)
                break
        decision = inspect_user_text(latest_user_text, max_input_chars)
        if not decision.allowed:
            return _replacement_response(SAFE_REFUSAL)
        return None

    return before_model


def build_after_model_callback(
    canary: str,
) -> Callable[[CallbackContext, LlmResponse], LlmResponse | None]:
    """Create the ADK `after_model_callback` that replaces unsafe model replies."""

    def after_model(_context: CallbackContext, response: LlmResponse) -> LlmResponse | None:
        text = _content_text(response.content)
        if not output_is_safe(text, canary):
            return _replacement_response(SAFE_REFUSAL)
        return None

    return after_model


def before_tool(
    tool: BaseTool, args: dict[str, Any], context: ToolContext
) -> dict[str, Any] | None:
    """Reject tool calls that pass server-owned arguments or oversized payloads.

    Returning a dict skips the tool and hands that dict to the model as the result.
    """
    protected = PROTECTED_ARGUMENTS.intersection(args)
    encoded_size = len(json.dumps(args, default=str))
    if protected or encoded_size > MAX_TOOL_ARGS_BYTES:
        context.custom_metadata["security_tool_blocked"] = True
        return {
            "ok": False,
            "code": "TOOL_ARGUMENTS_REJECTED",
            "message": "That operation is not available.",
        }
    context.custom_metadata["security_tool_name"] = tool.name
    return None


def _contains_protected_key(value: Any) -> bool:
    """Search nested dicts and lists for any key the model must never see."""
    if isinstance(value, dict):
        if PROTECTED_RESULT_KEYS.intersection(value):
            return True
        return any(_contains_protected_key(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_protected_key(item) for item in value)
    return False


def after_tool(
    _tool: BaseTool,
    _args: dict[str, Any],
    context: ToolContext,
    response: dict[str, Any],
) -> dict[str, Any] | None:
    """Replace any tool result containing a protected field with a generic redaction."""
    if _contains_protected_key(response):
        context.custom_metadata["security_tool_result_blocked"] = True
        return {
            "ok": False,
            "code": "TOOL_RESULT_REDACTED",
            "message": "The operation completed, but its result cannot be displayed.",
        }
    return None


def on_tool_error(
    tool: BaseTool,
    _args: dict[str, Any],
    context: ToolContext,
    _error: Exception,
) -> dict[str, Any]:
    """Fail closed on a tool exception without exposing its message to the model or user."""
    context.custom_metadata["security_tool_error"] = tool.name
    return {
        "ok": False,
        "code": "TOOL_ERROR",
        "message": "The operation could not be completed safely.",
    }
