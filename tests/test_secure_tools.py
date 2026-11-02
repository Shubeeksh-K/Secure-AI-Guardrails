from __future__ import annotations

import sqlite3
import unittest

from secure_ai.db import SQLiteStore
from secure_ai.security import SecurityContext
from secure_ai.tools import SecureTools


class SecureToolsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = SQLiteStore()
        self.store.seed_demo_data()
        self.tools = SecureTools(self.store)
        self.context = SecurityContext(customer_id="customer_alice", session_id="test-session")
        self.context.begin_turn()

    def tearDown(self) -> None:
        self.store.close()

    def test_lists_only_authenticated_customers_orders(self) -> None:
        result = self.tools.list_my_orders(self.context)
        self.assertTrue(result["ok"])
        order_ids = {order["order_id"] for order in result["data"]["orders"]}
        self.assertEqual(
            order_ids,
            {"ord_alice_1001", "ord_alice_1002", "ord_alice_1003"},
        )
        self.assertNotIn("ord_bob_9001", order_ids)

    def test_cross_customer_lookup_is_indistinguishable_from_missing_order(self) -> None:
        other_customer = self.tools.get_order(self.context, "ord_bob_9001")
        missing = self.tools.get_order(self.context, "ord_missing_9999")
        self.assertEqual(other_customer, missing)
        self.assertEqual(other_customer["code"], "ORDER_NOT_FOUND")

    def test_model_visible_order_excludes_private_fields(self) -> None:
        result = self.tools.get_order(self.context, "ord_alice_1001")
        order = result["data"]["order"]
        self.assertNotIn("customer_id", order)
        self.assertNotIn("customer_note", order)

    def test_eligible_and_final_sale_orders(self) -> None:
        eligible = self.tools.check_return_eligibility(self.context, "ord_alice_1001")
        self.assertTrue(eligible["data"]["eligible"])

        context = SecurityContext(customer_id="customer_alice", session_id="second-session")
        context.begin_turn()
        final_sale = self.tools.check_return_eligibility(context, "ord_alice_1002")
        self.assertFalse(final_sale["data"]["eligible"])

    def test_return_requires_a_new_turn_and_explicit_confirmation(self) -> None:
        proposed = self.tools.propose_return(
            self.context, "ord_alice_1001", "The headphones do not fit."
        )
        self.assertEqual(proposed["code"], "RETURN_PROPOSED")

        same_turn = self.tools.confirm_return(self.context, "confirm")
        self.assertEqual(same_turn["code"], "CONFIRMATION_REQUIRES_NEW_TURN")

        self.context.begin_turn()
        vague = self.tools.confirm_return(self.context, "maybe")
        self.assertEqual(vague["code"], "EXPLICIT_CONFIRMATION_REQUIRED")

        # A failed mutation consumes the one-mutation budget for this turn.
        retry_same_turn = self.tools.confirm_return(self.context, "confirm")
        self.assertEqual(retry_same_turn["code"], "MUTATION_BUDGET_EXCEEDED")

        self.context.begin_turn()
        confirmed = self.tools.confirm_return(self.context, "confirm")
        self.assertEqual(confirmed["code"], "RETURN_CREATED")

    def test_return_action_cannot_be_replayed(self) -> None:
        self.tools.propose_return(self.context, "ord_alice_1001", "Defective item")
        self.context.begin_turn()
        created = self.tools.confirm_return(self.context, "confirm")
        self.assertTrue(created["ok"])

        self.context.begin_turn()
        replay = self.tools.confirm_return(self.context, "confirm")
        self.assertEqual(replay["code"], "NO_PENDING_RETURN")

    def test_pending_return_expires_after_too_many_turns(self) -> None:
        self.tools.propose_return(self.context, "ord_alice_1001", "Defective item")
        for _ in range(3):
            self.context.begin_turn()
        expired = self.tools.confirm_return(self.context, "confirm")
        self.assertEqual(expired["code"], "CONFIRMATION_EXPIRED")

        self.context.begin_turn()
        again = self.tools.confirm_return(self.context, "confirm")
        self.assertEqual(again["code"], "NO_PENDING_RETURN")

    def test_pending_return_confirms_within_window(self) -> None:
        self.tools.propose_return(self.context, "ord_alice_1001", "Defective item")
        self.context.begin_turn()
        self.context.begin_turn()
        confirmed = self.tools.confirm_return(self.context, "confirm")
        self.assertEqual(confirmed["code"], "RETURN_CREATED")

    def test_duplicate_return_for_same_order_is_rejected(self) -> None:
        self.tools.propose_return(self.context, "ord_alice_1001", "Defective item")
        self.context.begin_turn()
        self.tools.confirm_return(self.context, "confirm")
        self.context.begin_turn()
        again = self.tools.propose_return(self.context, "ord_alice_1001", "Defective item")
        self.assertEqual(again["code"], "RETURN_NOT_ELIGIBLE")

    def test_malformed_ids_are_rejected_without_database_lookup(self) -> None:
        for bad in ("ORD_ALICE_1001", "ord_alice_1001'; DROP TABLE orders;--", "x"):
            context = SecurityContext(customer_id="customer_alice", session_id="s")
            context.begin_turn()
            self.assertEqual(
                self.tools.check_return_eligibility(context, bad)["code"], "ORDER_NOT_FOUND"
            )
            self.assertEqual(
                self.tools.propose_return(context, bad, "Defective item")["code"],
                "ORDER_NOT_FOUND",
            )

    def test_create_return_is_idempotent_for_a_replayed_key(self) -> None:
        kwargs = {
            "return_id": "ret_one",
            "customer_id": "customer_alice",
            "order_id": "ord_alice_1001",
            "reason": "Defective item",
            "idempotency_key": "act_replay",
        }
        first = self.store.create_return(**kwargs)
        second = self.store.create_return(**{**kwargs, "return_id": "ret_two"})
        self.assertEqual(first, second)

    def test_database_rejects_second_active_return_for_an_order(self) -> None:
        base = {"customer_id": "customer_alice", "order_id": "ord_alice_1001", "reason": "x y z"}
        self.store.create_return(return_id="ret_a", idempotency_key="k1", **base)
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.create_return(return_id="ret_b", idempotency_key="k2", **base)

    def test_policy_search_validates_and_finds_trusted_policies(self) -> None:
        found = self.tools.search_policies(self.context, "return")
        self.assertEqual(found["code"], "POLICIES_FOUND")
        self.assertEqual(found["data"]["policies"][0]["id"], "policy_returns")
        self.assertEqual(self.tools.search_policies(self.context, "x")["code"], "INVALID_QUERY")

    def test_policy_search_treats_wildcards_literally(self) -> None:
        result = self.tools.search_policies(self.context, "%%")
        self.assertEqual(result["data"]["policies"], [])

    def test_order_status_filter(self) -> None:
        shipped = self.tools.list_my_orders(self.context, "shipped")
        self.assertEqual([o["order_id"] for o in shipped["data"]["orders"]], ["ord_alice_1003"])
        self.assertEqual(self.tools.list_my_orders(self.context, "bogus")["code"], "INVALID_STATUS")

    def test_ineligible_orders_cannot_be_proposed(self) -> None:
        for order_id in ("ord_alice_1002", "ord_alice_1003"):
            context = SecurityContext(customer_id="customer_alice", session_id="s")
            context.begin_turn()
            result = self.tools.propose_return(context, order_id, "Changed my mind")
            self.assertEqual(result["code"], "RETURN_NOT_ELIGIBLE")

    def test_return_reason_is_validated(self) -> None:
        result = self.tools.propose_return(self.context, "ord_alice_1001", "x")
        self.assertEqual(result["code"], "INVALID_REASON")

    def test_cancel_return_is_ownership_scoped(self) -> None:
        self.store.create_return(
            return_id="ret_alice",
            customer_id="customer_alice",
            order_id="ord_alice_1001",
            reason="Defective",
            idempotency_key="k",
        )
        bob = SecurityContext(customer_id="customer_bob", session_id="b")
        bob.begin_turn()
        self.assertEqual(self.tools.cancel_return(bob, "ret_alice")["code"], "RETURN_NOT_FOUND")
        self.assertEqual(
            self.tools.cancel_return(self.context, "BAD ID")["code"], "RETURN_NOT_FOUND"
        )
        self.context.begin_turn()
        self.assertEqual(
            self.tools.cancel_return(self.context, "ret_alice")["code"], "RETURN_CANCELLED"
        )

    def test_cancelled_return_frees_the_order_for_a_new_return(self) -> None:
        kwargs = {"customer_id": "customer_alice", "order_id": "ord_alice_1001", "reason": "x y z"}
        self.store.create_return(return_id="ret_a", idempotency_key="k1", **kwargs)
        self.assertTrue(self.store.cancel_return("customer_alice", "ret_a"))
        self.store.create_return(return_id="ret_b", idempotency_key="k2", **kwargs)

    def test_support_ticket_creation_and_validation(self) -> None:
        ok = self.tools.create_support_ticket(
            self.context, "delivery", "Where is my keyboard?", "ord_alice_1003"
        )
        self.assertEqual(ok["code"], "TICKET_CREATED")
        for category, description in (("bogus", "Valid description"), ("other", "no")):
            context = SecurityContext(customer_id="customer_alice", session_id="s")
            context.begin_turn()
            result = self.tools.create_support_ticket(context, category, description)
            self.assertFalse(result["ok"])

    def test_control_characters_are_rejected_in_free_text(self) -> None:
        result = self.tools.create_support_ticket(self.context, "other", "bad\x00 description")
        self.assertEqual(result["code"], "INVALID_DESCRIPTION")

    def test_missing_security_context_is_denied(self) -> None:
        context = SecurityContext(customer_id="", session_id="s")
        result = self.tools.list_my_orders(context)
        self.assertEqual(result["code"], "MISSING_SECURITY_CONTEXT")

    def test_budgets_reset_on_new_turn(self) -> None:
        for _ in range(3):
            self.tools.list_my_orders(self.context)
        self.context.begin_turn()
        self.assertTrue(self.tools.list_my_orders(self.context)["ok"])

    def test_tool_budget_is_enforced(self) -> None:
        self.tools.list_my_orders(self.context)
        self.tools.get_order(self.context, "ord_alice_1001")
        self.tools.search_policies(self.context, "return")
        blocked = self.tools.list_my_orders(self.context)
        self.assertEqual(blocked["code"], "TOOL_BUDGET_EXCEEDED")

    def test_support_ticket_cannot_reference_another_customers_order(self) -> None:
        result = self.tools.create_support_ticket(
            self.context,
            category="delivery",
            description="Please check the delivery status.",
            order_id="ord_bob_9001",
        )
        self.assertEqual(result["code"], "ORDER_NOT_FOUND")


if __name__ == "__main__":
    unittest.main()
