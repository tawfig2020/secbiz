"""Enterprise/Regulated tier service (Phase 4).

Adds the premium trust layer on top of the Business tier:

  KMS signer        -> attestations signed by a key that never leaves hardware
  Merkle log        -> append-only transparency log with inclusion proofs
  Feed connectors   -> live FS-ISAC / H-ISAC / CISA signature ingestion
  Semantic judge    -> Gemini classifier backend (llm_judge tier flag)

EnterpriseService subclasses BusinessService, so it also inherits the
dashboard, HARD self-improvement, and compliance-report surfaces.
"""
from __future__ import annotations

from typing import Any, Mapping

from ..core.merkle import InclusionProof, MerkleLog
from ..dashboard import EventBus
from ..semantic_gateway.classifier import GeminiClassifier
from .business import BusinessService
from .feeds import FeedConnector, FeedSource
from .kms import KmsSigner
from .manifest import PluginManifest
from .registry import PluginRegistry, ResolvedPlugin
from .tier import ENTERPRISE


class EnterpriseService(BusinessService):
    """Trust layer: KMS-signed attestations + Merkle log + live feeds."""

    def __init__(self, plugin: ResolvedPlugin,
                 feed_source: FeedSource | None = None) -> None:
        super().__init__(plugin)
        self._merkle = MerkleLog()
        self._feeds = FeedConnector(plugin.gateway, source=feed_source)

    # -- transparency log -------------------------------------------------
    def _sync_merkle(self) -> None:
        """Append any attestations minted since the last sync."""
        attestations = self.plugin.monitor.attestation_log
        while len(self._merkle) < len(attestations):
            att = attestations[len(self._merkle)]
            self._merkle.append(att.signature.encode())

    def attestation_count(self) -> int:
        self._sync_merkle()
        return len(self._merkle)

    def attestation_root(self) -> str:
        self._sync_merkle()
        return self._merkle.root().hex()

    def inclusion_proof(self, index: int) -> dict[str, Any]:
        self._sync_merkle()
        return self._merkle.proof(index).to_dict()

    def verify_proof(self, proof: Mapping[str, Any], root_hex: str) -> bool:
        return self._merkle.verify(
            InclusionProof.from_dict(proof), bytes.fromhex(root_hex))

    # -- threat-intel feeds ----------------------------------------------
    def poll_feeds(self, feeds: tuple[str, ...] = ("FS-ISAC", "H-ISAC", "CISA")
                   ) -> dict[str, int]:
        return self._feeds.poll(feeds)

    # -- managed onboarding ----------------------------------------------
    @classmethod
    def onboard(cls, registry: PluginRegistry,
                verticals: tuple[str, ...] = (),
                limits: Mapping[str, int] | None = None,
                bus: EventBus | None = None,
                kms_client=None, feed_source: FeedSource | None = None,
                gemini_client=None) -> "EnterpriseService":
        """Provision an ENTERPRISE plugin with KMS signer + semantic judge."""
        signer = KmsSigner(kms_client) if kms_client is not None else None
        classifier = (GeminiClassifier(gemini_client)
                      if gemini_client is not None else None)
        plugin = registry.resolve(
            PluginManifest(tier=ENTERPRISE, verticals=verticals,
                           limits=dict(limits or {})),
            event_bus=bus or EventBus(),
            classifier=classifier,
            signer=signer)
        return cls(plugin, feed_source=feed_source)


__all__ = ["EnterpriseService"]
