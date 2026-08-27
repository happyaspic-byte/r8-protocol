"""CLI package generator for the external comparison series."""
import json
from pathlib import Path

from . import model, mptcp_runner, quic_runner


def _dispatch(plan):
    if plan["mechanism"] in {"quic-migration", "r8-mobility"}:
        return quic_runner.run_quic_trial(plan, None)
    return mptcp_runner.run_mptcp_trial(plan, None)


def run_package(output_dir: Path, smoke: bool = False) -> int:
    output_dir.mkdir(parents=True, exist_ok=True)
    plans = [row for row in model.plan_rows() if not smoke or row["seed"] == 0]
    trials, packets = [], []
    for plan in plans:
        trial, trial_packets = _dispatch(plan)
        trials.append(trial)
        packets.extend(trial_packets)

    trial_path = output_dir / "trial.jsonl"
    packet_path = output_dir / "packet.jsonl"
    trial_path.write_text("".join(model.canonical_json(row) + "\n" for row in trials))
    packet_path.write_text("".join(model.canonical_json(row) + "\n" for row in packets))

    files = {
        "trial.jsonl": model.sha256_hex(trial_path.read_bytes()),
        "packet.jsonl": model.sha256_hex(packet_path.read_bytes()),
    }
    eligible = bool(trials) and all(row.get("status") == "completed" for row in trials)
    (output_dir / "publication_eligible.json").write_text(model.canonical_json(eligible) + "\n")
    manifest = {
        "series": "r8-external-comparison-v1",
        "smoke": smoke,
        "row_counts": {"trials": len(trials), "packets": len(packets)},
        "files": files,
        "limitations": [
            "Isolated Linux network-namespace comparison only.",
            "No Internet, public-network, or standardized IPv8 claim.",
        ],
    }
    (output_dir / "manifest.json").write_text(model.canonical_json(manifest) + "\n")
    return 0
