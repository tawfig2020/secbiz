"""HARD: Harness-based Autonomous Runtime Defense Evolution (spec 6.3/9.2).

Implements the spec's continuous evolution loop:

    DEPLOY -> OBSERVE -> ANALYZE -> LEARN -> EVOLVE -> VALIDATE -> DEPLOY

  Deploy    - current defense artifacts serve production traffic
  Observe   - adversarial suite + failure traces (production analog)
  Analyze   - cluster failures, rank weakest detectors
  Learn     - distill candidate signature phrases from bypass traces
  Evolve    - teach the sequence-alignment detector the new phrases;
              recommend contract hardening (new prohibited actions)
  Validate  - re-run regression; keep evolution only if security improved
              without degrading benign utility (else rollback)

Human oversight per spec 9.1: contract changes are *recommended*, not
auto-applied -- people decide which consequential changes require approval.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from aegis.evaluation.adversarial_suite import (
    AdversarialCorpus,
    generate_corpus,
    split_corpus,
)
from aegis.evaluation.corpus_registry import CorpusRegistry
from aegis.evaluation.regression_runner import (
    RegressionReport,
    run_regression,
)
from aegis.self_improvement.failure_trace_analyzer import (
    FailureTraceAnalyzer,
)
from aegis.semantic_gateway import SemanticGateway


@dataclass
class HardReport:
    cycles: int = 0
    bypass_before: float = 0.0           # seen (TRAIN) bypass rate
    bypass_after: float = 0.0
    heldout_bypass_before: float = 0.0   # VALIDATION bypass rate
    heldout_bypass_after: float = 0.0
    learned_signatures: list[str] = field(default_factory=list)
    phases_completed: list[str] = field(default_factory=list)
    contract_recommendations: list[str] = field(default_factory=list)
    accepted: bool = False
    baseline: RegressionReport | None = None
    final: RegressionReport | None = None
    heldout_baseline: RegressionReport | None = None
    heldout_final: RegressionReport | None = None

    @property
    def generalization_gap(self) -> float:
        """held_out bypass minus seen bypass after evolution — the only
        number that tells a customer whether Aegis catches attacks it has
        never seen."""
        return round(self.heldout_bypass_after - self.bypass_after, 4)


PHASES = ("deploy", "observe", "analyze", "learn", "evolve", "validate")


class HardFramework:
    def __init__(self, gateway: SemanticGateway, suite=None,
                 analyzer: FailureTraceAnalyzer | None = None,
                 fuzzer=None, corpus: AdversarialCorpus | None = None,
                 validation_suite=None,
                 registry: CorpusRegistry | None = None) -> None:
        """`fuzzer` is an optional AdaptiveFuzzer; its freshly discovered
        bypasses are merged into the Observe phase's failure traces.

        Validation is held-out by construction: signatures evolve on the
        TRAIN set and are accepted/rejected on the disjoint VALIDATION
        set. `suite` may be a plain list (split deterministically via the
        registry) or an explicit AdversarialCorpus; `validation_suite`
        overrides the held-out side when `suite` is a list."""
        self.gateway = gateway
        self.registry = registry or CorpusRegistry()
        if corpus is None:
            if suite is None:
                corpus = generate_corpus(registry=self.registry)
            elif validation_suite is not None:
                corpus = AdversarialCorpus(
                    train=tuple(s for s in suite if s.expect_block),
                    validation=tuple(
                        s for s in validation_suite if s.expect_block),
                    benign=tuple(
                        {s.id: s for s in
                         [*suite, *validation_suite]
                         if not s.expect_block}.values()))
            else:
                corpus = split_corpus(list(suite), self.registry)
        self.corpus = corpus
        self.suite = corpus.train_suite()      # legacy handle
        self.analyzer = analyzer or FailureTraceAnalyzer()
        self.fuzzer = fuzzer

    def _benign_payloads(self) -> list[str]:
        return [s.payload for s in self.suite if not s.expect_block]

    def cycle(self, max_signatures: int = 6) -> HardReport:
        report = HardReport()
        detector = self.gateway.sequence_detector
        snapshot = detector.snapshot() if detector else []

        # -- DEPLOY: artifacts currently serving ---------------------------
        report.phases_completed.append("deploy")

        # -- OBSERVE: run the TRAIN suite (+ adaptive fuzzer) ----------------
        baseline = run_regression(self.gateway, self.corpus.train_suite())
        heldout_base = run_regression(self.gateway,
                                      self.corpus.heldout_suite())
        if self.fuzzer is not None:
            fuzz = self.fuzzer.evolve(generations=3, population=40)
            baseline.failure_traces = (baseline.failure_traces
                                       + fuzz.bypasses)
        report.baseline = baseline
        report.heldout_baseline = heldout_base
        report.bypass_before = baseline.metrics.bypass_rate
        report.heldout_bypass_before = heldout_base.metrics.bypass_rate
        report.cycles = 1
        report.phases_completed.append("observe")
        if not baseline.failure_traces or detector is None:
            report.final = baseline
            report.heldout_final = heldout_base
            report.bypass_after = report.bypass_before
            report.heldout_bypass_after = report.heldout_bypass_before
            report.accepted = False
            return report

        # -- ANALYZE: cluster failures, rank weak detectors ----------------
        analysis = self.analyzer.analyze(baseline.failure_traces,
                                         self._benign_payloads())
        report.phases_completed.append("analyze")

        # -- LEARN: distill candidate signatures ---------------------------
        candidates = analysis.candidate_phrases[:max_signatures]
        report.phases_completed.append("learn")

        # -- EVOLVE: new detector signatures + contract recommendations ----
        for phrase in candidates:
            detector.learn_signature(phrase, weight=0.8)  # type: ignore[union-attr]
            report.learned_signatures.append(phrase)
        report.contract_recommendations = self._recommend_contract(
            baseline.failure_traces)
        report.phases_completed.append("evolve")

        # -- VALIDATE: accept only if TRAIN improved AND the held-out set  --
        # -- did not regress (evolved signatures must generalize) ----------
        final = run_regression(self.gateway, self.corpus.train_suite())
        heldout = run_regression(self.gateway, self.corpus.heldout_suite())
        report.final = final
        report.heldout_final = heldout
        report.bypass_after = final.metrics.bypass_rate
        report.heldout_bypass_after = heldout.metrics.bypass_rate

        improved = final.metrics.bypass_rate < baseline.metrics.bypass_rate
        heldout_ok = (heldout.metrics.bypass_rate
                      <= heldout_base.metrics.bypass_rate + 1e-9)
        fp_ok = (final.metrics.fp_rate <= baseline.metrics.fp_rate + 0.01
                 and heldout.metrics.fp_rate
                 <= heldout_base.metrics.fp_rate + 0.01)
        report.accepted = improved and heldout_ok and fp_ok
        if not report.accepted and detector:
            detector.restore(snapshot)           # rollback failed evolution
            report.learned_signatures = []
            report.contract_recommendations = []
            report.bypass_after = report.bypass_before
            report.heldout_bypass_after = report.heldout_bypass_before
        report.phases_completed.append("validate")
        return report

    @staticmethod
    def _recommend_contract(traces: list[dict]) -> list[str]:
        """Capability contracts auto-update *recommendations* (spec 9.2):
        new attack patterns seen by the Red-side suite that name a concrete
        action (`call <action>`, `invoke <action>`) are surfaced for a human
        to add to prohibited_actions -- never auto-applied."""
        recs: list[str] = []
        for t in traces:
            if t.get("category") != "capability_bypass":
                continue
            for word in t.get("payload", "").lower().split():
                if word.startswith(("execute_", "export_", "modify_",
                                    "delete_", "wire_")):
                    if word not in recs:
                        recs.append(word)
        return recs[:8]
