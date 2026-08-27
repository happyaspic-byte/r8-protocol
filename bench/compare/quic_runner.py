"""QUIC connection migration trial execution adapter."""
import importlib.util


def aioquic_available() -> bool:
    return importlib.util.find_spec("aioquic") is not None


def run_quic_trial(plan: dict, topo):
    trial = dict(plan)
    if not aioquic_available():
        trial.update({
            "status": "prerequisite_failed",
            "failure_reason": "aioquic_unavailable",
            "cleanup_status": "passed",
        })
        return trial, []
    # Full netns live trial will be added once aioquic dependency is pinned.
    trial.update({
        "status": "not_implemented",
        "failure_reason": "adapter_in_progress",
        "cleanup_status": "passed",
    })
    return trial, []
