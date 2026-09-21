# Secure AI architecture

Secure AI uses defense in depth. Google ADK orchestrates the model and lifecycle callbacks, while application-owned Python code enforces authorization, data access, state transitions, and side effects.

## Trust boundaries

```mermaid
flowchart TB
    subgraph Untrusted
        U[User text]
        M[LLM output and tool arguments]
    end

    subgraph Orchestration[Google ADK orchestration]
        I[1. System contract]
        C[2. Server-owned identity and security context]
        G1[3. Input guardrail]
        A[ADK agent]
        G2[4. Tool-call argument guardrail]
        G3[5. Policy engine and action budgets]
        G4[6. Tool input validation]
        G5[7. Tool-result guardrail]
        G6[8. Output guardrail]
    end

    subgraph Trusted[Trusted application boundary]
        T[Ownership-scoped tools]
        D[(Per-session SQLite database)]
    end

    U --> G1 --> A
    I --> A
    C --> A
    A --> M --> G2 --> G3 --> G4 --> T --> D
    D --> T --> G5 --> A --> G6 --> U
```

The model never receives authority merely because it produced a valid-looking function call. A server-created `SecurityContext` supplies identity, limits each turn to three tool calls and one mutation, and stores pending confirmation state. Tool methods independently validate schemas, ownership, allowed state transitions, and idempotency before touching the database.

## Consequential-action workflow

```mermaid
sequenceDiagram
    actor User
    participant Agent as ADK agent
    participant Policy as Deterministic policy engine
    participant DB as SQLite store

    User->>Agent: "Return order ord_alice_1"
    Agent->>Policy: propose_return(order_id, reason)
    Policy->>DB: verify ownership and eligibility
    DB-->>Policy: safe order facts
    Policy-->>Agent: proposal + expiring confirmation token
    Agent-->>User: Ask for explicit confirmation
    User->>Agent: "Confirm"
    Agent->>Policy: confirm_return()
    Policy->>Policy: verify later turn, exact intent, token, and mutation budget
    Policy->>DB: idempotent return creation
    DB-->>Agent: safe result
    Agent-->>User: Confirm completed action
```

## Responsibility split

| Component | Responsibility |
| --- | --- |
| Google ADK | Conversation loop, function-tool wiring, sessions, and lifecycle callback hooks |
| Respan | Gateway model routing, ADK tracing, and adversarial assessment |
| Secure AI guardrails | Input/tool/result/output inspection and fail-closed responses |
| Security context | Server-owned identity, per-turn budgets, and confirmation state |
| Secure tools | Validation, authorization, ownership filtering, and idempotency |
| SQLite store | Isolated fictional commerce data and transactional state |

## Known limits

- The database and ADK session service are intentionally in memory for safe local demos.
- Pattern-based filters supplement—but do not replace—the deterministic authorization boundary.
- The prototype has no end-user authentication layer; the demo identity is server configuration.
- A strong red-team result is evidence for the tested attack set, not proof that the system is unbreakable.
