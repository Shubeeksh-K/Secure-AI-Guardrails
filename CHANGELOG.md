# Changelog

## Unreleased

### Security
- Pending return confirmations now expire two turns after the proposal.
- Guardrails normalize Unicode (NFKC) and strip invisible characters before matching.
- Order IDs are validated in every tool before any database lookup.
- The database enforces one active return per order; replaying an idempotency key returns the original result.

- Output guard now also blocks bare-domain and protocol-relative links, markdown/HTML sinks, spaced-out canaries, system-prompt fragments, and tenant identifiers.
- Input guard covers more override/extraction phrasings, spaced-out text, short base64 blobs, and Cyrillic/Greek homoglyphs.

### Changed
- `SECURE_AI_CUSTOMER_ID` and `SECURE_AI_MAX_INPUT_CHARS` are validated with clear errors.
- `Chat` and `SecureAISession` support context managers and clean up when startup fails.
- CI runs lint, format check, and tests on Python 3.12 and 3.13; Dependabot added.

### Added
- MIT `LICENSE`.

### Documentation
- Docstrings on all public APIs (enforced in CI via Ruff `D1`); `guardrails.py` regexes rewritten from fragments with an example and rationale per pattern, behavior unchanged.

### Tests
- Guardrail callbacks, settings, and end-to-end ADK runs with a scripted model.
- Coverage gate (88%) via pytest-cov; `Makefile`, pre-commit config, and CONTRIBUTING added.
