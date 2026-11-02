"""SQLite sandbox with ownership-scoped data access methods."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS customers (
    id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS orders (
    id TEXT PRIMARY KEY,
    customer_id TEXT NOT NULL REFERENCES customers(id),
    item_name TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('processing', 'shipped', 'delivered', 'cancelled')),
    amount_cents INTEGER NOT NULL CHECK(amount_cents >= 0),
    delivered_at TEXT,
    final_sale INTEGER NOT NULL DEFAULT 0 CHECK(final_sale IN (0, 1)),
    customer_note TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS policies (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    trusted INTEGER NOT NULL DEFAULT 1 CHECK(trusted IN (0, 1))
);

CREATE TABLE IF NOT EXISTS return_requests (
    id TEXT PRIMARY KEY,
    order_id TEXT NOT NULL REFERENCES orders(id),
    customer_id TEXT NOT NULL REFERENCES customers(id),
    reason TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('created', 'cancelled')),
    idempotency_key TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS one_active_return_per_order
    ON return_requests(order_id) WHERE status = 'created';

CREATE TABLE IF NOT EXISTS support_tickets (
    id TEXT PRIMARY KEY,
    customer_id TEXT NOT NULL REFERENCES customers(id),
    order_id TEXT REFERENCES orders(id),
    category TEXT NOT NULL,
    description TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""


class SQLiteStore:
    """Small sandbox store. All customer data reads require server-owned customer_id."""

    def __init__(self, path: str | Path = ":memory:") -> None:
        self.connection = sqlite3.connect(str(path))
        self.connection.row_factory = sqlite3.Row
        self.connection.executescript(SCHEMA)

    def close(self) -> None:
        """Close the connection; an in-memory database is discarded with it."""
        self.connection.close()

    def seed_demo_data(self) -> None:
        """Insert fictional customers, orders, and policies. Safe to call more than once."""
        now = datetime.now(UTC)
        rows = [
            (
                "ord_alice_1001",
                "customer_alice",
                "Noise-cancelling headphones",
                "delivered",
                12999,
                (now - timedelta(days=8)).isoformat(),
                0,
                "Leave at reception.",
            ),
            (
                "ord_alice_1002",
                "customer_alice",
                "Limited-edition mug",
                "delivered",
                2400,
                (now - timedelta(days=5)).isoformat(),
                1,
                "Gift order.",
            ),
            (
                "ord_alice_1003",
                "customer_alice",
                "Mechanical keyboard",
                "shipped",
                8900,
                None,
                0,
                "",
            ),
            (
                "ord_bob_9001",
                "customer_bob",
                "4K monitor",
                "delivered",
                34900,
                (now - timedelta(days=4)).isoformat(),
                0,
                "PRIVATE: call Bob at 555-0109.",
            ),
        ]
        policies = [
            (
                "policy_returns",
                "Returns",
                (
                    "Most delivered items can be returned within 30 days. "
                    "Final-sale items are not eligible."
                ),
                1,
            ),
            (
                "policy_refunds",
                "Refunds",
                "Approved refunds are sent to the original payment method after inspection.",
                1,
            ),
            (
                "policy_shipping",
                "Shipping",
                "Shipment tracking becomes available after an order leaves the warehouse.",
                1,
            ),
        ]
        with self.connection:
            self.connection.executemany(
                "INSERT OR IGNORE INTO customers(id, display_name) VALUES (?, ?)",
                [("customer_alice", "Alice"), ("customer_bob", "Bob")],
            )
            self.connection.executemany(
                """
                INSERT OR IGNORE INTO orders(
                    id, customer_id, item_name, status, amount_cents,
                    delivered_at, final_sale, customer_note
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )
            self.connection.executemany(
                "INSERT OR IGNORE INTO policies(id, title, body, trusted) VALUES (?, ?, ?, ?)",
                policies,
            )

    @staticmethod
    def _public_order(row: sqlite3.Row) -> dict[str, Any]:
        # Deliberately excludes customer_id and customer_note from model-visible output.
        return {
            "order_id": row["id"],
            "item_name": row["item_name"],
            "status": row["status"],
            "amount_cents": row["amount_cents"],
            "delivered_at": row["delivered_at"],
            "final_sale": bool(row["final_sale"]),
        }

    def list_orders(self, customer_id: str, status: str | None = None) -> list[dict[str, Any]]:
        """Return the customer's orders in model-safe form, optionally filtered by status."""
        if status is None:
            rows = self.connection.execute(
                "SELECT * FROM orders WHERE customer_id = ? ORDER BY id", (customer_id,)
            ).fetchall()
        else:
            rows = self.connection.execute(
                "SELECT * FROM orders WHERE customer_id = ? AND status = ? ORDER BY id",
                (customer_id, status),
            ).fetchall()
        return [self._public_order(row) for row in rows]

    def get_order(self, customer_id: str, order_id: str) -> dict[str, Any] | None:
        """Return one order only if it belongs to `customer_id`; otherwise None."""
        row = self.connection.execute(
            "SELECT * FROM orders WHERE customer_id = ? AND id = ?", (customer_id, order_id)
        ).fetchone()
        return self._public_order(row) if row else None

    def search_policies(self, query: str, limit: int = 3) -> list[dict[str, str]]:
        """Keyword-search trusted policies; `%` and `_` in the query match literally."""
        escaped = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        pattern = f"%{escaped}%"
        rows = self.connection.execute(
            """
            SELECT id, title, body FROM policies
            WHERE trusted = 1 AND (title LIKE ? ESCAPE '\\' OR body LIKE ? ESCAPE '\\')
            ORDER BY id LIMIT ?
            """,
            (pattern, pattern, limit),
        ).fetchall()
        return [dict(row) for row in rows]

    def active_return_for_order(self, customer_id: str, order_id: str) -> dict[str, Any] | None:
        """Return the order's non-cancelled return request, if any."""
        row = self.connection.execute(
            """
            SELECT id, order_id, reason, status, created_at FROM return_requests
            WHERE customer_id = ? AND order_id = ? AND status = 'created'
            """,
            (customer_id, order_id),
        ).fetchone()
        return dict(row) if row else None

    def create_return(
        self,
        *,
        return_id: str,
        customer_id: str,
        order_id: str,
        reason: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Insert a return, or return the existing one if `idempotency_key` was already used.

        A unique index additionally forbids two active returns for the same order, so a
        race between two confirmations raises `sqlite3.IntegrityError` instead of duplicating.
        """
        existing = self.connection.execute(
            """
            SELECT id, order_id, status, created_at FROM return_requests
            WHERE idempotency_key = ? AND customer_id = ?
            """,
            (idempotency_key, customer_id),
        ).fetchone()
        if existing:
            return {
                "return_id": existing["id"],
                "order_id": existing["order_id"],
                "status": existing["status"],
                "created_at": existing["created_at"],
            }
        created_at = datetime.now(UTC).isoformat()
        with self.connection:
            self.connection.execute(
                """
                INSERT INTO return_requests(
                    id, order_id, customer_id, reason, status, idempotency_key, created_at
                ) VALUES (?, ?, ?, ?, 'created', ?, ?)
                """,
                (return_id, order_id, customer_id, reason, idempotency_key, created_at),
            )
        return {
            "return_id": return_id,
            "order_id": order_id,
            "status": "created",
            "created_at": created_at,
        }

    def cancel_return(self, customer_id: str, return_id: str) -> bool:
        """Cancel an active return owned by the customer; True only if a row changed."""
        with self.connection:
            cursor = self.connection.execute(
                """
                UPDATE return_requests SET status = 'cancelled'
                WHERE id = ? AND customer_id = ? AND status = 'created'
                """,
                (return_id, customer_id),
            )
        return cursor.rowcount == 1

    def create_ticket(
        self,
        *,
        ticket_id: str,
        customer_id: str,
        order_id: str | None,
        category: str,
        description: str,
    ) -> dict[str, Any]:
        """Insert a support ticket. Callers must already have validated ownership of `order_id`."""
        created_at = datetime.now(UTC).isoformat()
        with self.connection:
            self.connection.execute(
                """
                INSERT INTO support_tickets(
                    id, customer_id, order_id, category, description, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (ticket_id, customer_id, order_id, category, description, created_at),
            )
        return {"ticket_id": ticket_id, "status": "created", "created_at": created_at}
