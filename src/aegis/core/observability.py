"""Observability primitives (stdlib-only): structured logs, correlation IDs,
and Prometheus-style metrics.

The dashboard is a *consumer* of telemetry; this module is the *producer*.
Three pieces, all dependency-free:

  * `JsonFormatter`     — one JSON object per log line (machine-parseable).
  * `Correlation`       — a contextvar that propagates a request id through
                          gateway.scan() -> monitor.evaluate() -> executor.
  * `MetricsRegistry`   — counters / gauges / histograms with a Prometheus
                          text exposition format (no scraping server needed).

Usage:

    from aegis.core.observability import Correlation, metrics

    with Correlation("req-123"):
        metrics.counter("gateway_scan_total", {"verdict": "BLOCK"}).inc()
"""
from __future__ import annotations

import contextvars
import json
import logging
import secrets
import threading
from typing import Any


# --------------------------------------------------------------- logging
class JsonFormatter(logging.Formatter):
    """Render each record as a single JSON line with stable keys."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "correlation_id": Correlation.get(),
        }
        extra = getattr(record, "extra_fields", None)
        if isinstance(extra, dict):
            payload.update(extra)
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str, ensure_ascii=True)


def configure_logging(level: int = logging.INFO) -> None:
    """Install the JSON formatter on the root logger (idempotent)."""
    root = logging.getLogger()
    if any(isinstance(h.formatter, JsonFormatter) for h in root.handlers):
        return
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    root.addHandler(handler)
    root.setLevel(level)


# --------------------------------------------------------- correlation id
class Correlation:
    """Thread/async-safe correlation id via a contextvar."""

    _ctx: contextvars.ContextVar[str | None] = contextvars.ContextVar(
        "aegis_correlation_id", default=None)

    def __init__(self, correlation_id: str | None = None) -> None:
        self._id = correlation_id or secrets.token_hex(8)
        self._token: contextvars.Token | None = None

    def __enter__(self) -> "Correlation":
        self._token = self._ctx.set(self._id)
        return self

    def __exit__(self, *exc) -> None:
        if self._token is not None:
            self._ctx.reset(self._token)
            self._token = None

    @classmethod
    def get(cls) -> str | None:
        return cls._ctx.get()

    @classmethod
    def set(cls, correlation_id: str) -> None:
        cls._ctx.set(correlation_id)


# ----------------------------------------------------------------- metrics
class _Counter:
    def __init__(self) -> None:
        self._value = 0.0
        self._lock = threading.Lock()

    def inc(self, amount: float = 1.0) -> None:
        with self._lock:
            self._value += amount

    def value(self) -> float:
        with self._lock:
            return self._value


class _Gauge:
    def __init__(self) -> None:
        self._value = 0.0
        self._lock = threading.Lock()

    def set(self, value: float) -> None:
        with self._lock:
            self._value = value

    def inc(self, amount: float = 1.0) -> None:
        with self._lock:
            self._value += amount

    def value(self) -> float:
        with self._lock:
            return self._value


class _Histogram:
    def __init__(self, buckets: tuple[float, ...]) -> None:
        self._buckets = buckets
        self._counts = [0] * len(buckets)
        self._sum = 0.0
        self._count = 0
        self._lock = threading.Lock()

    def observe(self, value: float) -> None:
        with self._lock:
            self._sum += value
            self._count += 1
            for i, b in enumerate(self._buckets):
                if value <= b:
                    self._counts[i] += 1
                    break

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {"buckets": list(self._buckets),
                    "counts": list(self._counts),
                    "sum": self._sum, "count": self._count}


class MetricsRegistry:
    """Thread-safe, in-process metric store with Prometheus exposition."""

    def __init__(self) -> None:
        self._counters: dict[tuple[str, tuple[tuple[str, str], ...]], _Counter] = {}
        self._gauges: dict[tuple[str, tuple[tuple[str, str], ...]], _Gauge] = {}
        self._histograms: dict[tuple[str, tuple[tuple[str, str], ...]], _Histogram] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _key(name: str, labels: dict[str, str] | None):
        return (name, tuple(sorted((labels or {}).items())))

    def counter(self, name: str, labels: dict[str, str] | None = None) -> _Counter:
        key = self._key(name, labels)
        with self._lock:
            return self._counters.setdefault(key, _Counter())

    def gauge(self, name: str, labels: dict[str, str] | None = None) -> _Gauge:
        key = self._key(name, labels)
        with self._lock:
            return self._gauges.setdefault(key, _Gauge())

    def histogram(self, name: str, buckets: tuple[float, ...],
                  labels: dict[str, str] | None = None) -> _Histogram:
        key = self._key(name, labels)
        with self._lock:
            return self._histograms.setdefault(key, _Histogram(buckets))

    def render(self) -> str:
        """Prometheus text exposition format (0.0.4)."""
        lines: list[str] = []
        with self._lock:
            for (name, labels), c in sorted(self._counters.items()):
                lines.append(f"# TYPE {name} counter")
                lines.append(f"{name}{self._fmt_labels(labels)} {c.value()}")
            for (name, labels), g in sorted(self._gauges.items()):
                lines.append(f"# TYPE {name} gauge")
                lines.append(f"{name}{self._fmt_labels(labels)} {g.value()}")
            for (name, labels), h in sorted(self._histograms.items()):
                lines.append(f"# TYPE {name} histogram")
                snap = h.snapshot()
                cum = 0
                for b, c in zip(snap["buckets"], snap["counts"]):
                    cum += c
                    lines.append(
                        f"{name}_bucket{self._fmt_labels(labels, le=b)} {cum}")
                lines.append(
                    f"{name}_bucket{self._fmt_labels(labels, le='+Inf')} "
                    f"{snap['count']}")
                lines.append(f"{name}_sum{self._fmt_labels(labels)} {snap['sum']}")
                lines.append(f"{name}_count{self._fmt_labels(labels)} {snap['count']}")
        return "\n".join(lines) + ("\n" if lines else "")

    @staticmethod
    def _fmt_labels(labels: tuple[tuple[str, str], ...],
                    le: Any = None) -> str:
        parts = [f'{k}="{v}"' for k, v in labels]
        if le is not None:
            parts.append(f'le="{le}"')
        return "{" + ",".join(parts) + "}" if parts else ""


# Process-wide default registry (import-and-use convenience).
metrics = MetricsRegistry()

# Pre-declared decision counters so dashboards have stable series names.
DECISION_COUNTER = "aegis_decision_total"
DETECTOR_LATENCY = "aegis_detector_latency_ms"
QUEUE_DEPTH = "aegis_approval_queue_depth"


__all__ = [
    "Correlation",
    "DECISION_COUNTER",
    "DETECTOR_LATENCY",
    "JsonFormatter",
    "MetricsRegistry",
    "QUEUE_DEPTH",
    "configure_logging",
    "metrics",
]
