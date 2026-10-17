"""Aegis Agent Vault — capability-bounded AI agents for banking (BFSI).

A single-plugin prototype for the Google AI Hackathon: a banking AI agent
that *provably cannot* execute unauthorized actions. Reuses the Aegis core
(ReferenceMonitor, signed attestations, semantic gateway) with zero external
dependencies.

Run the demo:      python -m agent_vault.demo
Run the server:    python -m agent_vault.server
Smoke test:        python -m agent_vault.smoke_test
"""
from __future__ import annotations

import sys
from pathlib import Path

# Make the sibling `src` package importable without an install step, so the
# prototype runs straight from a checkout (CI/Docker install it via pip).
_SRC = Path(__file__).resolve().parents[1] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from .contract import CONTRACT_ID, CONTRACT_JSON  # noqa: E402
from .vault import AgentVault, VaultResult  # noqa: E402

__all__ = ["AgentVault", "CONTRACT_ID", "CONTRACT_JSON", "VaultResult"]
