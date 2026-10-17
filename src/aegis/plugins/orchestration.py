"""Agent orchestration registry: enforce the tier's `max_agents` budget.

The tier declares `max_agents` (1 for solo, 25 for business, unlimited for
enterprise/regulated). This registry is the enforcement point: it tracks
registered agents and fails closed when a tier's agent budget is exceeded.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Mapping


class AgentLimitExceeded(ValueError):
    """Raised when registering an agent would exceed the tier budget."""


@dataclass
class AgentRegistry:
    """In-memory agent ledger with a hard `max_agents` cap."""

    max_agents: int | None = None
    _agents: dict[str, str] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock,
                                  repr=False, compare=False)

    def register(self, agent_id: str, role: str = "reader") -> str:
        with self._lock:
            is_new = agent_id not in self._agents
            if (is_new and self.max_agents is not None
                    and len(self._agents) >= self.max_agents):
                raise AgentLimitExceeded(
                    f"agent budget {self.max_agents} exceeded; cannot "
                    f"register {agent_id!r}")
            self._agents[agent_id] = role
            return agent_id

    def unregister(self, agent_id: str) -> None:
        with self._lock:
            self._agents.pop(agent_id, None)

    def count(self) -> int:
        with self._lock:
            return len(self._agents)

    def agents(self) -> Mapping[str, str]:
        with self._lock:
            return dict(self._agents)


__all__ = ["AgentLimitExceeded", "AgentRegistry"]
