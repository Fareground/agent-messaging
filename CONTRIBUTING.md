# Contributing to AMP

Thanks for helping build the Agent Messaging Protocol.

## Development

Requires Python 3.11+.

```bash
python -m venv .venv
.venv/bin/pip install -e '.[dev]'          # core + dev + http extras
.venv/bin/python -m pytest                 # full suite
.venv/bin/ruff check src tests             # lint
.venv/bin/ruff format src tests            # format (line length 100)
```

## Ground rules

- **Boring cryptography only.** Use audited primitives from `cryptography`
  (pyca). Do not invent crypto. New security-relevant behavior needs a test
  that demonstrates both the accept and the reject path.
- **Core stays dependency-light.** Only `pydantic` and `cryptography` in the
  core; web bits live behind the `[http]` extra and lazy imports.
- **Wire compatibility.** The wire format (`amp` version, envelope fields,
  canonical JSON) is a contract. Changes that affect bytes-on-the-wire must
  bump the protocol version and update `tests/test_wire_vectors.py` golden
  vectors. A second-language (TypeScript) implementation is planned — keep the
  canonicalization and signing deterministic and documented.
- **Many small files, high cohesion.** Match the existing layering
  (identity / envelope / session / policy / transport / node).
- **Every change runs green:** `pytest` + `ruff` before you open a PR.

## Commits

- Follow [Conventional Commits](https://www.conventionalcommits.org/):
  `type: summary`, where `type` is one of `feat`, `fix`, `refactor`, `docs`,
  `test`, `chore`, `perf`, or `ci`. Keep the summary imperative and under ~72
  characters; put detail in the body.
- **No AI/assistant co-author attribution.** Commits must not add
  `Co-authored-by` trailers or "Generated with" lines for AI assistants. Author
  your own commits.

## Reporting security issues

See `SECURITY.md` — do not open a public issue for a vulnerability.

## Architecture

Read `docs/BLUEPRINT.md` first. It carries the design, the layer boundaries,
the threat model, and the roadmap.
