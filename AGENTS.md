# JoinMarket Refactor Guidelines

## Overview
Modern, secure implementation of JoinMarket components using Python 3.14+, Pydantic v2, and AsyncIO.

## Key Constraints
- **Python**: 3.14+ required. Strict type hinting (Mypy) mandated.
- **Database**: No BerkeleyDB. Use direct RPC or Mempool API.
- **Privacy**: Tor integration is core architecture.

## Commands
- **Test**: `pytest` (all) or `pytest path/to/test.py` (single).
- **Lint/Format**: `pre-commit run --all-files` (Recommended).
  - Manual: `ruff check .` / `ruff format .` / `mypy .`
- **Docker**: `docker-compose up -d` (use `--profile taker` for taker bots).

## Code Style
- **Formatting**: Line length 100. Follow Ruff defaults.
- **Typing**: `disallow_untyped_defs = true`. Use `typing` module or modern `|` syntax.
- **Imports**: Sorted (Stdlib → Third-party → Local). `from __future__ import annotations`.
- **Naming**: `snake_case` for functions/vars, `PascalCase` for classes/models.
- **Error Handling**: Use descriptive custom exceptions (inheriting from `Exception`).

## Project Structure
Monorepo with `src/` layout. Root `pytest.ini` handles global tests.
Components: `jmcore` (Lib), `directory_server`, `jmwallet`, `maker`, `taker`, `orderbook_watcher`.

## References

https://github.com/JoinMarket-Org/joinmarket-clientserver/ -> reference implementation (legacy)
https://github.com/JoinMarket-Org/JoinMarket-Docs -> protocol documentation
