"""Linux MPTCP failover trial execution adapter."""
import socket
import subprocess
import time

from . import model


def mptcp_available() -> bool:
    proto = getattr(socket, "IPPROTO_MPTCP", None)
    if proto is None:
        return False
    try:
        shown = subprocess.run(
            ["sysctl", "-n", "net.mptcp.enabled"],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return False
    return shown.returncode == 0 and shown.stdout.strip() == "1"


def _fail(plan, reason, status="prerequisite_failed"):
    trial = dict(plan)
    trial.update({
        "status": status,
        "failure_reason": reason,
        "cleanup_status": "passed",
    })
    return trial, []


def run_mptcp_trial(plan: dict, topo):
    if plan.get("mechanism") not in {"linux-mptcp", "r8-redundant"}:
        return _fail(plan, "unsupported_mechanism")
    if plan.get("mechanism") == "linux-mptcp" and not mptcp_available():
        return _fail(plan, "mptcp_unavailable")
    if topo is None:
        return _fail(plan, "isolated_topology_required")
    execute = _execute_r8_redundant if plan["mechanism"] == "r8-redundant" else _execute_mptcp
    try:
        return execute(plan, topo)
    except Exception as exc:
        return _fail(plan, type(exc).__name__, status="failed")


def _execute_mptcp(plan, topo):
    proto = getattr(socket, "IPPROTO_MPTCP")
    socket.socket(socket.AF_INET, socket.SOCK_STREAM, proto).close()
    if not hasattr(topo, "cut_primary"):
        return _fail(plan, "topology_missing_cut_primary")
    t0 = time.monotonic_ns()
    cut = topo.cut_primary()
    t1 = time.monotonic_ns()
    if not cut.get("observed"):
        return _fail(plan, "path_cut_unobserved", status="failed")
    if cut.get("subflows", 0) < 2:
        return _fail(plan, "mptcp_subflows_unproven", status="failed")
    if not model.transfer_proven(cut):
        return _fail(plan, "transfer_unproven", status="failed")
    trial = dict(plan)
    trial.update({
        "status": "completed",
        "failure_reason": None,
        "cleanup_status": "passed",
        "event_ns": cut["event_ns"],
        "last_pre_event_ns": t0,
        "first_post_event_ns": t1,
        "outage_ns": max(0, t1 - cut["event_ns"]),
        "subflows": cut["subflows"],
        "path_bytes": cut.get("path_bytes", {}),
    })
    return trial, cut.get("packets", [])


def _execute_r8_redundant(plan, topo):
    if not hasattr(topo, "cut_primary"):
        return _fail(plan, "topology_missing_cut_primary")
    t0 = time.monotonic_ns()
    cut = topo.cut_primary()
    t1 = time.monotonic_ns()
    if not cut.get("observed"):
        return _fail(plan, "path_cut_unobserved", status="failed")
    if not model.transfer_proven(cut):
        return _fail(plan, "transfer_unproven", status="failed")
    trial = dict(plan)
    trial.update({
        "status": "completed",
        "failure_reason": None,
        "cleanup_status": "passed",
        "event_ns": cut["event_ns"],
        "last_pre_event_ns": t0,
        "first_post_event_ns": t1,
        "outage_ns": max(0, t1 - cut["event_ns"]),
        "path_bytes": cut.get("path_bytes", {}),
    })
    return trial, cut.get("packets", [])
