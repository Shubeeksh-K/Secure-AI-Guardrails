from __future__ import annotations

import inspect
import unittest

from secure_ai.adk_agent import AgentResources, build_agent
from secure_ai.db import SQLiteStore
from secure_ai.security import SecurityContext
from secure_ai.settings import Settings
from secure_ai.tools import SecureTools


class AgentConstructionTests(unittest.TestCase):
    def test_agent_has_only_expected_tools(self) -> None:
        store = SQLiteStore()
        self.addCleanup(store.close)
        store.seed_demo_data()
        resources = AgentResources(
            store=store,
            tools=SecureTools(store),
            context=SecurityContext("customer_alice", "test-session"),
        )
        settings = Settings(
            respan_api_key="test-key",
            respan_base_url="https://api.respan.ai/api",
            respan_model="gpt-5-mini",
            customer_id="customer_alice",
            max_input_chars=4_000,
            enable_tracing=False,
        )
        agent = build_agent(settings, resources, "test-canary")
        names = {tool.name if hasattr(tool, "name") else tool.__name__ for tool in agent.tools}
        self.assertEqual(
            names,
            {
                "search_policies",
                "list_my_orders",
                "get_order",
                "check_return_eligibility",
                "propose_return",
                "confirm_return",
                "create_support_ticket",
            },
        )
        self.assertTrue(agent.disallow_transfer_to_parent)
        self.assertTrue(agent.disallow_transfer_to_peers)

        confirm_tool = next(tool for tool in agent.tools if tool.__name__ == "confirm_return")
        self.assertEqual(list(inspect.signature(confirm_tool).parameters), ["tool_context"])


if __name__ == "__main__":
    unittest.main()
