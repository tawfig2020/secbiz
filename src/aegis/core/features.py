"""Feature flags for safe rollout.

A flag is a named boolean with a default and an optional allowlist of
subjects/tenants. Flags gate risky behavior (e.g. HARD self-improvement,
PQC key exchange) so it can be rolled out incrementally and reverted without
a redeploy.

    flags = FeatureFlags({"hard_loop": False})
    if flags.enabled("hard_loop"):
        run_hard_loop()
"""
from __future__ import annotations

import threading
from typing import Any, Mapping


class FeatureFlags:
    def __init__(self, defaults: Mapping[str, bool] | None = None,
                 overrides: Mapping[str, bool] | None = None) -> None:
        self._flags: dict[str, bool] = dict(defaults or {})
        self._flags.update(overrides or {})
        self._lock = threading.Lock()

    def enabled(self, name: str, *, default: bool = False) -> bool:
        with self._lock:
            return self._flags.get(name, default)

    def set(self, name: str, value: bool) -> None:
        with self._lock:
            self._flags[name] = bool(value)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return dict(self._flags)


# Process-wide defaults. Production overrides come from config/env.
flags = FeatureFlags({
    "hard_loop": False,          # self-improvement: off until governance §4
    "pqc_key_exchange": False,   # PQC seam: off until a backend is injected
    "idempotency": True,         # replay cache on mutating endpoints
})


__all__ = ["FeatureFlags", "flags"]
