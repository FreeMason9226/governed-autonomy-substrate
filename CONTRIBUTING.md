# Contributing to Governed Autonomy Substrate

Thank you for your interest in contributing. GAS is working toward becoming the
ecosystem standard for governed AI agent execution. Every contribution — code,
spec clarification, or integration — moves that goal forward.

## Quick Start

```bash
git clone https://github.com/<your-org>/governed-autonomy-substrate
cd governed-autonomy-substrate
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest
```

All tests must pass before submitting a pull request.

## Development Standards

### Code
- Python ≥ 3.11
- Type annotations on all public interfaces (`mypy --strict` clean)
- `ruff` for linting — run `ruff check src/ tests/` before committing
- No new runtime dependencies without an RFC (see below)

### Tests
- Every new behavior needs a test in `tests/`
- Concurrency, replay recovery, and boundary invariants are first-class concerns
- If your change affects the wire format, add or update a conformance vector in
  `tests/conformance/vectors/`

### Wire Format Changes
Any change to the GAA wire format, replay frame schema, or policy definition
schema is a **protocol change** and requires an RFC. See [RFC Process](#rfc-process).

## RFC Process

1. Copy `docs/rfc/template.md` to `docs/rfc/NNNN-short-title.md`
2. Fill in: motivation, proposed change, wire format diff, backward compatibility,
   conformance test impact
3. Open a pull request with the RFC document only — no implementation yet
4. The RFC must be open for at least **7 days** for community review
5. Once merged, the implementation PR can be opened referencing the RFC number

## Conformance Tests

The `tests/conformance/` directory contains language-agnostic test vectors
(JSON inputs → expected outputs). These are the source of truth for any
alternative implementation of the GAS protocol.

If you are implementing GAS in another language, run these vectors against
your implementation and open a PR adding your implementation to
`docs/implementations.md`.

## Integration Contributions

Framework adapters (MCP Gateway, LangChain, AutoGen, etc.) live in separate
repositories under the `governed-autonomy` GitHub organization. Open an issue
here first to coordinate.

## Commit Style

Use [Conventional Commits](https://www.conventionalcommits.org/):

```text
feat: add PostgreSQL nonce repository adapter
fix: reject GAA with past expiry during barrier check
spec: clarify canonical JSON sorting rules in SPEC.md
rfc: add RFC-0003 for GAA wire format versioning
```

## Code of Conduct

Be constructive, precise, and professional. This is infrastructure for safety
systems — rigor is kindness here.
