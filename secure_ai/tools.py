"""Security-aware tools exposed to the Google ADK agent."""

from __future__ import annotations

import re
import secrets
from datetime import UTC, datetime

from secure_ai.db import SQLiteStore
from secure_ai.domain import PendingReturn, ToolName, ToolResult, WorkflowState
from secure_ai.security import PolicyEngine, PolicyViolation, SecurityContext

ORDER_STATUSES = {"processing", "shipped", "delivered", "cancelled"}
TICKET_CATEGORIES = {"delivery", "damaged_item", "return", "other"}
RETURN_WINDOW_DAYS = 30
ID_PATTERN = re.compile(r"^[a-z][a-z0-9_]{2,63}$")


class SecureTools:
    """The only code allowed to read or change customer data on the agent's behalf.

    Every public method takes the server-owned `SecurityContext` first, authorizes through
    the policy engine, validates model-supplied values, and returns a `ToolResult` dict.
    Failures use generic messages so the model cannot learn why a lookup failed (for
    example, whether an order belongs to someone else).
    """

    def __init__(self, store: SQLiteStore, policy: PolicyEngine | None = None) -> None:
        self.store = store
        self.policy = policy or PolicyEngine()

    @staticmethod
    def _failure(code: str, message: str) -> dict:
        return ToolResult(False, code, message).to_dict()

    @staticmethod
    def _success(code: str, message: str, data: dict | None = None) -> dict:
        return ToolResult(True, code, message, data).to_dict()

    def _authorize(self, context: SecurityContext, tool: ToolName) -> dict | None:
        """Run the policy engine; return a generic failure dict on violation, else None."""
        try:
            self.policy.authorize(context, tool)
        except PolicyViolation as exc:
            return self._failure(exc.code, "That operation is not available.")
        return None

    @staticmethod
    def _valid_id(value: str) -> bool:
        """Check identifier shape before it is used in any lookup."""
        return bool(ID_PATTERN.fullmatch(value))

    @staticmethod
    def _clean_text(value: str, *, minimum: int, maximum: int) -> str | None:
        """Collapse whitespace and enforce length and no control characters; None if invalid."""
        normalized = " ".join(value.split())
        if not minimum <= len(normalized) <= maximum:
            return None
        if any(ord(character) < 32 for character in normalized):
            return None
        return normalized

    def search_policies(self, context: SecurityContext, query: str) -> dict:
        """Search trusted store policies by keyword (2-120 characters)."""
        if denied := self._authorize(context, ToolName.SEARCH_POLICIES):
            return denied
        clean_query = self._clean_text(query, minimum=2, maximum=120)
        if clean_query is None:
            return self._failure("INVALID_QUERY", "Use a short policy search query.")
        matches = self.store.search_policies(clean_query)
        return self._success("POLICIES_FOUND", "Trusted policies retrieved.", {"policies": matches})

    def list_my_orders(self, context: SecurityContext, status: str | None = None) -> dict:
        """List the authenticated customer's orders, optionally filtered by status."""
        if denied := self._authorize(context, ToolName.LIST_MY_ORDERS):
            return denied
        if status is not None and status not in ORDER_STATUSES:
            return self._failure("INVALID_STATUS", "The requested order status is invalid.")
        orders = self.store.list_orders(context.customer_id, status)
        return self._success("ORDERS_FOUND", "Authorized orders retrieved.", {"orders": orders})

    def get_order(self, context: SecurityContext, order_id: str) -> dict:
        """Return one order owned by the customer; unknown and foreign IDs look identical."""
        if denied := self._authorize(context, ToolName.GET_ORDER):
            return denied
        if not self._valid_id(order_id):
            return self._failure("ORDER_NOT_FOUND", "That order was not found.")
        order = self.store.get_order(context.customer_id, order_id)
        if order is None:
            # Do not disclose whether the identifier exists for a different customer.
            return self._failure("ORDER_NOT_FOUND", "That order was not found.")
        return self._success("ORDER_FOUND", "Authorized order retrieved.", {"order": order})

    def check_return_eligibility(self, context: SecurityContext, order_id: str) -> dict:
        """Report whether an owned order can be returned and why or why not."""
        if denied := self._authorize(context, ToolName.CHECK_RETURN_ELIGIBILITY):
            return denied
        if not self._valid_id(order_id):
            return self._failure("ORDER_NOT_FOUND", "That order was not found.")
        order = self.store.get_order(context.customer_id, order_id)
        if order is None:
            return self._failure("ORDER_NOT_FOUND", "That order was not found.")

        eligible, reason = self._eligibility(context.customer_id, order)
        return self._success(
            "ELIGIBILITY_CHECKED",
            "Return eligibility checked.",
            {"order_id": order_id, "eligible": eligible, "reason": reason},
        )

    def _eligibility(self, customer_id: str, order: dict) -> tuple[bool, str]:
        """Apply the business rules: delivered, not final sale, no active return, within window."""
        if order["status"] != "delivered":
            return False, "Only delivered orders are eligible for return."
        if order["final_sale"]:
            return False, "Final-sale items are not eligible for return."
        if self.store.active_return_for_order(customer_id, order["order_id"]):
            return False, "An active return already exists for this order."
        delivered_at = datetime.fromisoformat(order["delivered_at"])
        age_days = (datetime.now(UTC) - delivered_at).days
        if age_days > RETURN_WINDOW_DAYS:
            return False, f"The {RETURN_WINDOW_DAYS}-day return window has closed."
        return True, f"The order is within the {RETURN_WINDOW_DAYS}-day return window."

    def propose_return(self, context: SecurityContext, order_id: str, reason: str) -> dict:
        """Prepare a return and store it as pending; nothing is written to the database.

        The customer must confirm in a later turn (see `confirm_return`)."""
        if denied := self._authorize(context, ToolName.PROPOSE_RETURN):
            return denied
        clean_reason = self._clean_text(reason, minimum=3, maximum=240)
        if clean_reason is None:
            return self._failure("INVALID_REASON", "Provide a short return reason.")
        if not self._valid_id(order_id):
            return self._failure("ORDER_NOT_FOUND", "That order was not found.")
        order = self.store.get_order(context.customer_id, order_id)
        if order is None:
            return self._failure("ORDER_NOT_FOUND", "That order was not found.")
        eligible, eligibility_reason = self._eligibility(context.customer_id, order)
        if not eligible:
            return self._failure("RETURN_NOT_ELIGIBLE", eligibility_reason)

        action = PendingReturn(
            action_id=f"act_{secrets.token_hex(12)}",
            order_id=order_id,
            reason=clean_reason,
            created_turn=context.turn_index,
        )
        context.pending_return = action
        context.workflow_state = WorkflowState.RETURN_PROPOSED
        return self._success(
            "RETURN_PROPOSED",
            "Return prepared. Ask the customer to confirm in a new message.",
            {"order_id": order_id, "item_name": order["item_name"], "confirmation_required": True},
        )

    def confirm_return(self, context: SecurityContext, confirmation: str) -> dict:
        """Create the pending return if `confirmation` is an explicit confirmation.

        `confirmation` is the customer's literal latest message supplied by the server, never
        text composed by the model. Eligibility is re-checked because state may have changed
        since the proposal."""
        if denied := self._authorize(context, ToolName.CONFIRM_RETURN):
            return denied
        # Exact phrases only: "sure" or "I guess" must not authorize a state change.
        accepted_confirmations = {"confirm", "confirmed", "yes, confirm", "yes confirm"}
        if confirmation.strip().casefold() not in accepted_confirmations:
            return self._failure(
                "EXPLICIT_CONFIRMATION_REQUIRED", "Explicit confirmation is required."
            )

        pending = context.pending_return
        if pending is None:  # Defensive: PolicyEngine already rejects this state.
            return self._failure("NO_PENDING_RETURN", "That operation is not available.")
        order = self.store.get_order(context.customer_id, pending.order_id)
        if order is None:
            return self._failure("ORDER_NOT_FOUND", "That order was not found.")
        eligible, reason = self._eligibility(context.customer_id, order)
        if not eligible:
            return self._failure("RETURN_NOT_ELIGIBLE", reason)

        return_id = f"ret_{secrets.token_hex(8)}"
        result = self.store.create_return(
            return_id=return_id,
            customer_id=context.customer_id,
            order_id=pending.order_id,
            reason=pending.reason,
            idempotency_key=pending.action_id,
        )
        context.used_action_ids.add(pending.action_id)
        context.pending_return = None
        context.workflow_state = WorkflowState.RETURN_CREATED
        return self._success("RETURN_CREATED", "Return request created.", result)

    def cancel_return(self, context: SecurityContext, return_id: str) -> dict:
        """Cancel an active return the customer owns. Not currently exposed to the agent."""
        if denied := self._authorize(context, ToolName.CANCEL_RETURN):
            return denied
        if not self._valid_id(return_id):
            return self._failure("RETURN_NOT_FOUND", "That return request was not found.")
        cancelled = self.store.cancel_return(context.customer_id, return_id)
        if not cancelled:
            return self._failure("RETURN_NOT_FOUND", "That return request was not found.")
        return self._success(
            "RETURN_CANCELLED", "Return request cancelled.", {"return_id": return_id}
        )

    def create_support_ticket(
        self,
        context: SecurityContext,
        category: str,
        description: str,
        order_id: str | None = None,
    ) -> dict:
        """Create a ticket with a valid category and description, optionally for an owned order."""
        if denied := self._authorize(context, ToolName.CREATE_SUPPORT_TICKET):
            return denied
        if category not in TICKET_CATEGORIES:
            return self._failure("INVALID_CATEGORY", "That ticket category is invalid.")
        clean_description = self._clean_text(description, minimum=5, maximum=500)
        if clean_description is None:
            return self._failure("INVALID_DESCRIPTION", "Provide a concise support description.")
        if order_id is not None and (
            not self._valid_id(order_id)
            or self.store.get_order(context.customer_id, order_id) is None
        ):
            return self._failure("ORDER_NOT_FOUND", "That order was not found.")

        ticket_id = f"tkt_{secrets.token_hex(8)}"
        result = self.store.create_ticket(
            ticket_id=ticket_id,
            customer_id=context.customer_id,
            order_id=order_id,
            category=category,
            description=clean_description,
        )
        return self._success("TICKET_CREATED", "Support ticket created.", result)
