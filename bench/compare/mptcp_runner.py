"""Linux MPTCP failover trial execution adapter."""
import socket
import subprocess


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


def run_mptcp_trial(plan: dict, topo):
    trial = dict(plan)
    if not mptcp_available():
        trial.update({
            "status": "prerequisite_failed",
            "failure_reason": "mptcp_unavailable",
            "cleanup_status": "passed",
        })
        return trial, []
    # Full netns live trial will be added once endpoint sockets are bound.
    trial.update({
        "status": "not_implemented",
        "failure_reason": "adapter_in_progress",
        "cleanup_status": "passed",
    })
    return trial, []
