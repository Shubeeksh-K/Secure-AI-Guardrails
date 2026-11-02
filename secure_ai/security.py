"""Deterministic security context and tool policy enforcement."""

from __future__ import annotations

from dataclasses import dataclass, field

from secure_ai.domain import PendingReturn, ToolName, WorkflowState


class PolicyViolation(Exception):
    """Raised internally when an agent operation crosses a policy boundary."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass
class SecurityContext:
    """Server-owned state. None of these fields may come from model tool arguments."""

    customer_id: str
    session_id: str
    turn_index: int = 0
    workflow_state: WorkflowState = WorkflowState.GENERAL
    pending_return: PendingReturn | None = None
    calls_this_turn: int = 0
    mutations_this_turn: int = 0
    used_action_ids: set[str] = field(default_factory=set)

    def begin_turn(self) -> None:
        """Advance the turn counter and reset the per-turn budgets."""
        self.turn_index += 1
        self.calls_this_turn = 0
        self.mutations_this_turn = 0


class PolicyEngine:
    """Deterministic gate that every tool call must pass before doing any work.

    Attempts are counted before validation succeeds, so a failed or malformed call still
    consumes budget. That stops a compromised model from probing with unlimited retries.
    """

    MAX_TOOL_CALLS_PER_TURN = 3
    MAX_MUTATIONS_PER_TURN = 1
    # A stale "confirm" many turns later is unlikely to refer to what the customer was shown.
    MAX_CONFIRMATION_AGE_TURNS = 2

    _MUTATING_TOOLS = {
        ToolName.CONFIRM_RETURN,
        ToolName.CANCEL_RETURN,
        ToolName.CREATE_SUPPORT_TICKET,
    }

    def authorize(self, context: SecurityContext, tool: ToolName) -> None:
        """Allow the call or raise `PolicyViolation` with a stable code.

        Checks, in order: server identity present, per-turn call budget, per-turn mutation
        budget, then (for `confirm_return`) a pending proposal that was made in an earlier
        turn, has not expired, and has not already been used.
        """
        if not context.customer_id or not context.session_id:
            raise PolicyViolation("MISSING_SECURITY_CONTEXT")

        if context.calls_this_turn >= self.MAX_TOOL_CALLS_PER_TURN:
            raise PolicyViolation("TOOL_BUDGET_EXCEEDED")

        is_mutation = tool in self._MUTATING_TOOLS
        if is_mutation and context.mutations_this_turn >= self.MAX_MUTATIONS_PER_TURN:
            raise PolicyViolation("MUTATION_BUDGET_EXCEEDED")

        if tool is ToolName.CONFIRM_RETURN:
            pending = context.pending_return
            if context.workflow_state is not WorkflowState.RETURN_PROPOSED or pending is None:
                raise PolicyViolation("NO_PENDING_RETURN")
            if pending.created_turn >= context.turn_index:
                raise PolicyViolation("CONFIRMATION_REQUIRES_NEW_TURN")
            if context.turn_index - pending.created_turn > self.MAX_CONFIRMATION_AGE_TURNS:
                context.pending_return = None
                context.workflow_state = WorkflowState.GENERAL
                raise PolicyViolation("CONFIRMATION_EXPIRED")
            if pending.action_id in context.used_action_ids:
                raise PolicyViolation("ACTION_ALREADY_USED")

        context.calls_this_turn += 1
        if is_mutation:
            context.mutations_this_turn += 1
