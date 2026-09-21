"""Deterministic input, tool, and output guardrails for the ADK lifecycle."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from google.adk.agents.callback_context import CallbackContext
from google.adk.models.llm_request import LlmRequest
from google.adk.models.llm_response import LlmResponse
from google.adk.tools.base_tool import BaseTool
from google.adk.tools.tool_context import ToolContext
from google.genai import types

SAFE_REFUSAL = (
    "I can help with store policies, your orders, returns, and support tickets, "
    "but I can't help with that request."
)

_INPUT_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "instruction_override",
        re.compile(
            r"\b(ignore|disregard|override)\b.{0,40}\b(instruction|prompt|rule)s?\b", re.I | re.S
        ),
    ),
    (
        "prompt_extraction",
        re.compile(
            r"\b(reveal|show|print|repeat|dump)\b.{0,50}\b(system|developer|hidden|internal)\s+(prompt|instruction|message)s?\b",
            re.I | re.S,
        ),
    ),
    (
        "secret_extraction",
        re.compile(
            r"\b(reveal|show|print|dump|give)\b.{0,40}\b(api[ _-]?key|credential|secret|token)s?\b",
            re.I | re.S,
        ),
    ),
    (
        "role_forgery",
        re.compile(r"<\/?(?:system|developer|tool)>|\[(?:system|developer|tool)\]", re.I),
    ),
    ("fake_tool_result", re.compile(r"\b(?:tool|function)\s+(?:result|output|response)\s*:", re.I)),
)

_BASE64_BLOCK = re.compile(r"(?:[A-Za-z0-9+/]{120,}={0,2})")
_SECRET_PATTERNS = (
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\b(?:api[_-]?key|secret|password)\s*[:=]\s*[^\s,;]{8,}", re.I),
    re.compile(r"\bBearer\s+[A-Za-z0-9._~-]{16,}\b", re.I),
)
_PROTECTED_ARGUMENTS = {"customer_id", "user_id", "session_id", "api_key", "model"}
_PROTECTED_RESULT_KEYS = {"customer_id", "customer_note", "api_key", "secret", "password"}


@dataclass(frozen=True)
class GuardDecision:
    allowed: bool
    flags: tuple[str, ...] = ()


def inspect_user_text(text: str, max_chars: int) -> GuardDecision:
    flags: list[str] = []
    if len(text) > max_chars:
        flags.append("input_too_large")
    for name, pattern in _INPUT_PATTERNS:
        if pattern.search(text):
            flags.append(name)
    if _BASE64_BLOCK.search(text):
        flags.append("encoded_payload")
    return GuardDecision(not flags, tuple(flags))


def output_is_safe(text: str, canary: str) -> bool:
    if canary and canary in text:
        return False
    return not any(pattern.search(text) for pattern in _SECRET_PATTERNS)


def _content_text(content: types.Content | None) -> str:
    if content is None:
        return ""
    return "".join(part.text or "" for part in content.parts or [] if part.text)


def _replacement_response(text: str) -> LlmResponse:
    return LlmResponse(content=types.Content(role="model", parts=[types.Part(text=text)]))


def build_before_model_callback(max_input_chars: int):
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


def build_after_model_callback(canary: str):
    def after_model(_context: CallbackContext, response: LlmResponse) -> LlmResponse | None:
        text = _content_text(response.content)
        if not output_is_safe(text, canary):
            return _replacement_response(SAFE_REFUSAL)
        return None

    return after_model


def before_tool(
    tool: BaseTool, args: dict[str, Any], context: ToolContext
) -> dict[str, Any] | None:
    protected = _PROTECTED_ARGUMENTS.intersection(args)
    encoded_size = len(json.dumps(args, default=str))
    if protected or encoded_size > 2_000:
        context.custom_metadata["security_tool_blocked"] = True
        return {
            "ok": False,
            "code": "TOOL_ARGUMENTS_REJECTED",
            "message": "That operation is not available.",
        }
    context.custom_metadata["security_tool_name"] = tool.name
    return None


def _contains_protected_key(value: Any) -> bool:
    if isinstance(value, dict):
        if _PROTECTED_RESULT_KEYS.intersection(value):
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
    context.custom_metadata["security_tool_error"] = tool.name
    return {
        "ok": False,
        "code": "TOOL_ERROR",
        "message": "The operation could not be completed safely.",
    }
