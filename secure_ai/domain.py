"""Domain types shared by the database, policy engine, and agent tools."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class WorkflowState(StrEnum):
    """Where the conversation is in the two-step return flow (server-owned, never model input)."""

    GENERAL = "general"
    RETURN_PROPOSED = "return_proposed"
    RETURN_CREATED = "return_created"


class ToolName(StrEnum):
    """Every operation the policy engine knows how to authorize."""

    SEARCH_POLICIES = "search_policies"
    LIST_MY_ORDERS = "list_my_orders"
    GET_ORDER = "get_order"
    CHECK_RETURN_ELIGIBILITY = "check_return_eligibility"
    PROPOSE_RETURN = "propose_return"
    CONFIRM_RETURN = "confirm_return"
    CANCEL_RETURN = "cancel_return"
    CREATE_SUPPORT_TICKET = "create_support_ticket"


@dataclass(frozen=True)
class ToolResult:
    """Uniform tool outcome: `code` is a stable machine-readable string, `message` is safe text."""

    ok: bool
    code: str
    message: str
    data: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to the dict shape returned to the model; `data` is omitted when absent."""
        result: dict[str, Any] = {
            "ok": self.ok,
            "code": self.code,
            "message": self.message,
        }
        if self.data is not None:
            result["data"] = self.data
        return result


@dataclass(frozen=True)
class PendingReturn:
    """A prepared but unconfirmed return.

    `action_id` doubles as the database idempotency key, so one proposal can create at most
    one return. `created_turn` lets the policy engine require a later turn and expire it.
    """

    action_id: str
    order_id: str
    reason: str
    created_turn: int
