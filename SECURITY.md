# Security policy

## Scope and threat model

Secure AI is a local hackathon prototype that uses fictional commerce data. Its primary threats are prompt injection, system-prompt or secret disclosure, cross-customer data access, forged tool arguments/results, and excessive agent authority.

The trusted boundary is deterministic application code. Model text, user text, and model-generated tool arguments are treated as untrusted. See [the architecture notes](docs/ARCHITECTURE.md) for the controls and current limitations.

## Reporting a vulnerability

Please do not open a public issue containing an exploit, credential, or sensitive transcript. Use the repository's **Security → Report a vulnerability** flow (GitHub private vulnerability reporting) and include:

- the affected component and version or commit
- a minimal reproduction with fictional data
- expected and observed behavior
- impact and suggested mitigation, if known

Do not test against accounts, data, or infrastructure you do not own or have permission to assess.

## Secrets

Never commit `.env`, API keys, raw production traces, or unreviewed red-team reports. If a key is exposed, revoke it at the provider before removing it from Git history.
