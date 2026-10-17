"""Text renderers for the three dashboard views.

The same DashboardState powers these renderers, `snapshot_dict()` for JSON
serialization (API / WebSocket payloads), and any future GUI.
"""
from __future__ import annotations

from typing import Any

from .aggregator import DashboardState


def _hline(ch: str = "-", w: int = 72) -> str:
    return ch * w


def render_executive(state: DashboardState) -> str:
    """Cyber financial statement — the Board/CISO view."""
    bs, inc, post = (state.balance_sheet, state.income_statement,
                     state.posture)
    lines = [
        _hline("="),
        "  EXECUTIVE VIEW - CYBER FINANCIAL STATEMENT",
        _hline("="),
        "  BALANCE SHEET",
        f"    Agents/sources protected     : {bs.get('assets_protected', 0)}",
        f"    Capability contracts enforced: {bs.get('contracts_enforced', 0)}",
        f"    Detection coverage           : "
        f"{post.get('detection_rate_pct', 0)}%",
        f"    MTTC (mean)                  : {post.get('mttc_ms', 0)}ms",
        f"    Firewall uptime              : "
        f"{bs.get('firewall_uptime_pct', 0)}%",
        f"    Active threat vectors        : "
        f"{bs.get('active_threat_vectors', 0)}",
        f"    Compliance gaps              : "
        f"{bs.get('compliance_gaps', 0)} "
        f"({', '.join(bs.get('compliance_frameworks', [])) or 'n/a'})",
        "",
        "  INCOME STATEMENT",
        f"    Attacks prevented            : {inc.get('attacks_prevented', 0)}",
        f"    Exfil events blocked         : "
        f"{inc.get('exfil_events_blocked', 0)}",
        f"    Contract denials             : "
        f"{inc.get('contract_denials', 0)}",
        f"    Human approvals deferred     : "
        f"{inc.get('human_approvals_deferred', 0)}",
        f"    Exfiltration events          : "
        f"{inc.get('losses', {}).get('exfiltration_events', 0)}",
        f"    Contract violations executed : "
        f"{inc.get('losses', {}).get('contract_violations_executed', 0)}",
        "",
        "  POSTURE",
        f"    p99 latency                  : {post.get('p99_latency_ms', 0)}ms",
        f"    Egress events scanned        : {post.get('egress_events', 0)}",
    ]
    return "\n".join(lines)


def _fmt_event(ev) -> str:
    hits = ev.data.get("detector_hits") or {}
    hits_s = (", ".join(f"{k}:{v}" for k, v in
                        sorted(hits.items(), key=lambda kv: -kv[1])[:3]))
    extra = f" [{hits_s}]" if hits_s else ""
    lat = ev.data.get("latency_ms")
    lat_s = f" {lat:.1f}ms" if isinstance(lat, (int, float)) else ""
    return f"  {ev.ts_ms:>13.1f}  {ev.kind:<17} {ev.summary}{lat_s}{extra}"


def render_soc(state: DashboardState, limit: int = 14) -> str:
    """SOC analyst view — live attack timeline + decisions + HARD log."""
    lines = [
        _hline("="),
        "  SOC ANALYST VIEW - LIVE ATTACK TIMELINE",
        _hline("="),
    ]
    lines += [_fmt_event(e) for e in state.timeline[-limit:]] \
        or ["  (no events)"]
    lines += ["", "  CAPABILITY CONTRACT DECISIONS"]
    for e in state.contract_decisions[-6:]:
        lines.append(
            f"  {e.ts_ms:>13.1f}  {e.data.get('decision', '?'):<11} "
            f"{str(e.data.get('action', '?')):<34} "
            f"-> {e.data.get('contract_id', '?')}")
    lines += ["", "  HARD SELF-IMPROVEMENT LOG"]
    for e in state.hard_log[-6:]:
        lines.append(f"  {e.ts_ms:>13.1f}  {e.summary}")
    lines.append(
        f"  Red/Blue: {state.soc_loop.get('attacks_simulated', 0)} attacks "
        f"simulated, {state.soc_loop.get('countermeasures', 0)} "
        f"countermeasures, containment "
        f"{state.soc_loop.get('containment_ms', 0)}ms")
    return "\n".join(lines)


def render_threat_intel(state: DashboardState) -> str:
    """Unified threat-intelligence view — trends, forecast, self-improvement."""
    tr, si = state.trends, state.self_improvement
    lines = [
        _hline("="),
        "  UNIFIED THREAT INTELLIGENCE",
        _hline("="),
        "  TRENDS",
        f"    Attacks observed             : {tr.get('attacks_total', 0)}",
        f"    Detections (1st/2nd half)    : "
        f"{tr.get('detections_first_half', 0)} -> "
        f"{tr.get('detections_second_half', 0)} "
        f"(delta {tr.get('detection_rate_delta', 0)}%)",
        f"    Avg latency (1st/2nd half)   : "
        f"{tr.get('latency_ms_first_half', 0)}ms -> "
        f"{tr.get('latency_ms_second_half', 0)}ms",
        f"    Forecast next window         : "
        f"{tr.get('forecast_attacks_next_window', 'n/a')}",
        "",
        "  SELF-IMPROVEMENT",
        f"    HARD cycles completed        : {si.get('hard_cycles', 0)}",
        f"    Artifacts deployed           : {si.get('artifacts_deployed', 0)}",
        f"    New signatures learned       : {si.get('new_signatures', 0)}",
        f"    Contract recommendations     : "
        f"{si.get('contract_recommendations', 0)}",
        f"    Intel feeds                  : "
        f"{', '.join(state.intel_feeds) or 'none'}",
    ]
    return "\n".join(lines)


def render_all(state: DashboardState) -> str:
    return "\n\n".join((render_executive(state), render_soc(state),
                        render_threat_intel(state)))


def snapshot_dict(state: DashboardState) -> dict[str, Any]:
    """JSON-serializable payload for APIs/WebSocket front-ends."""
    def ev_dict(e):
        return {"ts_ms": e.ts_ms, "kind": e.kind, "actor": e.actor,
                "summary": e.summary, "data": e.data}
    return {
        "balance_sheet": state.balance_sheet,
        "income_statement": state.income_statement,
        "posture": state.posture,
        "timeline": [ev_dict(e) for e in state.timeline],
        "contract_decisions": [ev_dict(e) for e in state.contract_decisions],
        "hard_log": [ev_dict(e) for e in state.hard_log],
        "soc_loop": state.soc_loop,
        "trends": state.trends,
        "self_improvement": state.self_improvement,
        "intel_feeds": state.intel_feeds,
    }
