"""Foundry PoC Demo: a minimal, faithful implementation of the Foundry security
harness spec, built to run a controlled experiment against an agentic baseline.

Roles implemented as modules: indexer, detector, triager, reporter, orchestrator.
Substrate: config, store (SQLite + JSONL provenance), budget, fingerprint, llm.
"""

__version__ = "0.1.0"
