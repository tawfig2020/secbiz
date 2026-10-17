"""Data-driven vertical loader: clarifies the code-vs-config boundary.

The built-in packs (`bfsi`, `healthcare`, `government`) are **code** because
they ship custom detector classes (SWIFT manipulation, PHI exfiltration,
classified-taint) that cannot be expressed as JSON. Third-party verticals
that only need *policy* (contracts, egress patterns, compliance mappings,
threat signatures) are **data** and load through `vertical_from_dict` /
`load_vertical_json` with no code change.

A vertical config is a JSON/dict:

    {
      "name": "insurance",
      "tagline": "P&C insurance vertical",
      "detectors": ["phi_exfiltration"],          # optional, by registry name
      "contracts": [
        {"contract_id": "aegis.insurance.claims.v1",
         "permitted_actions": [{"action": "read_claim",
                                "constraints": {"requires_human_approval": true}}],
         "prohibited_actions": ["pay_claim"]}
      ],
      "egress_pii": [{"label": "policy_number",
                      "pattern": "POL-\\\\d{6}", "severity": 0.9}],
      "compliance_map": [
        {"framework": "NAIC", "reference": "Model 668",
         "requirement": "access control", "aegis_coverage": "ReferenceMonitor"}
      ],
      "threat_signatures": ["override the claims adjuster"],
      "intel_feeds": ["FS-ISAC"],
      "metadata": {"latency_budget_ms": 500, "latency_policy": "degrade_to_fast_path"}
    }
"""
from __future__ import annotations

import json
import re
from typing import Any, Callable, Mapping

from aegis.capability_bounded.capability_contract import CapabilityContract
from aegis.semantic_gateway.detectors.base import Detection, ScanContext
from aegis.verticals.pack import ComplianceControl, VerticalPack

# Detector factories addressable by name from a data-driven vertical.
_DETECTOR_REGISTRY: dict[str, Callable[[], Any]] = {}


def register_detector(name: str, factory: Callable[[], Any]) -> None:
    """Expose a detector factory to data-driven verticals."""
    _DETECTOR_REGISTRY[name] = factory


class RegexDetector:
    """A declarative detector: one regex, one score, one evidence label.

    Lets a third-party vertical ship a simple sector detector as data
    (`regex_detectors` in the policy file) without writing Python.
    """

    def __init__(self, name: str, pattern: str, score: float,
                 evidence: str) -> None:
        self.name = name
        self._re = re.compile(pattern, re.IGNORECASE)
        self._score = float(score)
        self._evidence = evidence

    def scan(self, text: str, ctx: ScanContext) -> Detection:
        canon = ctx.canonical or text
        if self._re.search(canon):
            return Detection(self.name, min(self._score, 1.0),
                             [self._evidence])
        return Detection(self.name, 0.0, [])


def _contracts(entries: list[dict]) -> tuple[CapabilityContract, ...]:
    return tuple(CapabilityContract.from_dict(e) for e in entries)


def _patterns(entries: list[dict]) -> tuple[tuple[str, re.Pattern, float], ...]:
    out = []
    for e in entries:
        out.append((e["label"], re.compile(e["pattern"]),
                    float(e.get("severity", 1.0))))
    return tuple(out)


def _compliance(entries: list[dict]) -> tuple[ComplianceControl, ...]:
    return tuple(
        ComplianceControl(framework=e["framework"], reference=e["reference"],
                          requirement=e["requirement"],
                          aegis_coverage=e["aegis_coverage"])
        for e in entries)


def vertical_from_dict(config: Mapping[str, Any]) -> VerticalPack:
    """Build a VerticalPack from a config mapping (no code required).

    Detectors come from two declarative sources:
      - `detectors`: names registered via `register_detector` (built-ins).
      - `regex_detectors`: inline `{name, pattern, score, evidence}` entries.
    """
    detectors = tuple(
        _DETECTOR_REGISTRY[name] for name in config.get("detectors", [])
        if name in _DETECTOR_REGISTRY)
    regex_detectors = tuple(
        lambda e=e: RegexDetector(e["name"], e["pattern"],
                                  e.get("score", 0.5),
                                  e.get("evidence", e["name"]))
        for e in config.get("regex_detectors", []))
    return VerticalPack(
        name=config["name"],
        tagline=config.get("tagline", ""),
        detectors=detectors + regex_detectors,
        contracts=_contracts(config.get("contracts", [])),
        egress_pii=_patterns(config.get("egress_pii", [])),
        egress_secrets=_patterns(config.get("egress_secrets", [])),
        compliance_map=_compliance(config.get("compliance_map", [])),
        threat_signatures=tuple(config.get("threat_signatures", [])),
        intel_feeds=tuple(config.get("intel_feeds", [])),
        metadata=dict(config.get("metadata", {})),
    )


def load_vertical_json(path: str) -> VerticalPack:
    """Load a data-driven vertical from a JSON file."""
    with open(path, encoding="utf-8") as f:
        return vertical_from_dict(json.load(f))


# Alias: a "policy file" is the third-party vertical contract.
load_vertical_policy = load_vertical_json


__all__ = [
    "RegexDetector",
    "load_vertical_json",
    "load_vertical_policy",
    "register_detector",
    "vertical_from_dict",
]
