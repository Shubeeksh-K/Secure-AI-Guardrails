from __future__ import annotations

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
