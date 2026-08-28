"""CLI package generator for the external comparison series."""
from pathlib import Path

from . import lisp_runner, model, mptcp_runner, quic_runner
from .netns import CompareTopology


def _dispatch(plan, topo):
    mechanism = plan["mechanism"]
    if mechanism in {"quic-migration", "r8-mobility"}:
        return quic_runner.run_quic_trial(plan, topo)
    if mechanism == "lisp-xtr":
        return lisp_runner.run_lisp_trial(plan, topo)
    return mptcp_runner.run_mptcp_trial(plan, topo)


def run_package(output_dir: Path, smoke: bool = False, privileged: bool = False) -> int:
    output_dir.mkdir(parents=True, exist_ok=True)
    plans = [row for row in model.plan_rows() if not smoke or row["seed"] == 0]
    trials, packets = [], []
    topologies = {}
    try:
        for plan in plans:
            topo = None
            if privileged:
                topo = topologies.get(plan["seed"])
                if topo is None:
                    topo = CompareTopology(plan["seed"])
                    topo.setup()
                    topologies[plan["seed"]] = topo
            trial, trial_packets = _dispatch(plan, topo)
            trials.append(trial)
            packets.extend(trial_packets)
    finally:
        for seed, topo in sorted(topologies.items(), reverse=True):
            if not topo.cleanup():
                for trial in trials:
                    if trial.get("seed") == seed:
                        trial["cleanup_status"] = "failed"
                        trial["status"] = "failed"
                        trial["failure_reason"] = "namespace_cleanup_failed"

    trial_path = output_dir / "trial.jsonl"
    packet_path = output_dir / "packet.jsonl"
    trial_path.write_text("".join(model.canonical_json(row) + "\n" for row in trials))
    packet_path.write_text("".join(model.canonical_json(row) + "\n" for row in packets))

    files = {
        "trial.jsonl": model.sha256_hex(trial_path.read_bytes()),
        "packet.jsonl": model.sha256_hex(packet_path.read_bytes()),
    }
    eligible = bool(trials) and all(
        row.get("status") == "completed" and row.get("cleanup_status") == "passed"
        for row in trials
    )
    (output_dir / "publication_eligible.json").write_text(model.canonical_json(eligible) + "\n")
    manifest = {
        "series": "r8-external-comparison-v1",
        "smoke": smoke,
        "privileged": privileged,
        "row_counts": {"trials": len(trials), "packets": len(packets)},
        "files": files,
        "limitations": [
            "Isolated Linux network-namespace comparison only.",
            "No Internet, public-network, or standardized IPv8 claim.",
        ],
    }
    (output_dir / "manifest.json").write_text(model.canonical_json(manifest) + "\n")
    return 0
