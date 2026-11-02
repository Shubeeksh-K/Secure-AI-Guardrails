# Contributing

Thanks for helping improve Secure AI. This is a prototype that uses fictional data; please keep it that way.

## Setup

```bash
uv sync --frozen
make check        # ruff lint + format check + tests with a coverage gate
```

Optional: `uv run pre-commit install` to run the linters before each commit.

## Guidelines

- Authorization, identity, and side effects belong in deterministic code (`secure_ai/tools.py`, `security.py`, `db.py`); detection patterns live in `secure_ai/patterns.py`, never in the prompt. Model output and tool arguments are untrusted.
- A change to a guardrail or policy needs a test that fails without it. `tests/test_e2e_fake_llm.py` runs the real ADK pipeline against a scripted model without network access.
- Do not commit `.env`, API keys, raw red-team reports, or real customer data.
- Every public class, function, and method needs a docstring (enforced by Ruff `D1`); state the contract and any security assumption. Explain the *why* of a regex or limit in a comment next to it.
- Keep README and docs claims in step with what the tests prove.

## Reporting vulnerabilities

Follow [SECURITY.md](SECURITY.md); do not open a public issue with an exploit.
