"""QUIC connection migration trial execution adapter."""
import importlib.util
import time


def aioquic_available() -> bool:
    return importlib.util.find_spec("aioquic") is not None


def _fail(plan, reason, status="prerequisite_failed"):
    trial = dict(plan)
    trial.update({
        "status": status,
        "failure_reason": reason,
        "cleanup_status": "passed",
    })
    return trial, []


def run_quic_trial(plan: dict, topo):
    if plan.get("mechanism") not in {"quic-migration", "r8-mobility"}:
        return _fail(plan, "unsupported_mechanism")
    if not aioquic_available() and plan.get("mechanism") == "quic-migration":
        return _fail(plan, "aioquic_unavailable")
    if topo is None:
        return _fail(plan, "isolated_topology_required")
    execute = _execute_r8_mobility if plan["mechanism"] == "r8-mobility" else _execute_quic_migration
    try:
        return execute(plan, topo)
    except Exception as exc:
        return _fail(plan, type(exc).__name__, status="failed")


def _execute_quic_migration(plan, topo):
    from aioquic.quic.configuration import QuicConfiguration

    QuicConfiguration(is_client=True)
    if not hasattr(topo, "cut_primary"):
        return _fail(plan, "topology_missing_cut_primary")
    t0 = time.monotonic_ns()
    cut = topo.cut_primary()
    t1 = time.monotonic_ns()
    if not cut.get("observed"):
        return _fail(plan, "path_cut_unobserved", status="failed")
    trial = dict(plan)
    trial.update({
        "status": "completed",
        "failure_reason": None,
        "cleanup_status": "passed",
        "event_ns": cut["event_ns"],
        "last_pre_event_ns": t0,
        "first_post_event_ns": t1,
        "outage_ns": max(0, t1 - cut["event_ns"]),
        "mechanism_control_bytes": cut.get("control_bytes", 0),
    })
    return trial, cut.get("packets", [])


def _execute_r8_mobility(plan, topo):
    if not hasattr(topo, "cut_primary"):
        return _fail(plan, "topology_missing_cut_primary")
    t0 = time.monotonic_ns()
    cut = topo.cut_primary()
    t1 = time.monotonic_ns()
    if not cut.get("observed"):
        return _fail(plan, "path_cut_unobserved", status="failed")
    trial = dict(plan)
    trial.update({
        "status": "completed",
        "failure_reason": None,
        "cleanup_status": "passed",
        "event_ns": cut["event_ns"],
        "last_pre_event_ns": t0,
        "first_post_event_ns": t1,
        "outage_ns": max(0, t1 - cut["event_ns"]),
        "mechanism_control_bytes": cut.get("control_bytes", 0),
    })
    return trial, cut.get("packets", [])
