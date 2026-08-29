"""Independent validator for comparison evidence packages."""
import json
from pathlib import Path

from . import model

EXPECTED_FILES = {"trial.jsonl", "packet.jsonl", "publication_eligible.json"}


def _load_jsonl(path, errors):
    rows = []
    try:
        lines = path.read_text().splitlines()
    except OSError:
        return rows
    for index, line in enumerate(lines, 1):
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            errors.append(f"invalid JSON in {path.name} row {index}")
            continue
        if not isinstance(row, dict):
            errors.append(f"non-object row in {path.name} row {index}")
            continue
        if line != model.canonical_json(row):
            errors.append(f"non-canonical JSON in {path.name} row {index}")
        rows.append(row)
    return rows


def validate_package(package_dir: Path) -> list:
    errors = []
    manifest_path = package_dir / "manifest.json"
    if not manifest_path.exists():
        return ["missing manifest.json"]
    try:
        manifest_text = manifest_path.read_text()
        manifest = json.loads(manifest_text)
    except (OSError, json.JSONDecodeError):
        return ["invalid manifest.json"]
    if not isinstance(manifest, dict):
        return ["invalid manifest.json"]
    if manifest_text != model.canonical_json(manifest) + "\n":
        errors.append("non-canonical manifest.json")
    if manifest.get("series") != "r8-external-comparison-v1":
        errors.append("manifest series mismatch")
    if not isinstance(manifest.get("smoke"), bool) or not isinstance(manifest.get("privileged"), bool):
        errors.append("manifest mode fields invalid")
    files = manifest.get("files")
    if not isinstance(files, dict):
        return errors + ["manifest files map is missing"]
    if set(files) != EXPECTED_FILES:
        errors.append("manifest files set mismatch")
    for name in EXPECTED_FILES:
        path = package_dir / name
        expected_sha = files.get(name)
        if not path.exists():
            errors.append(f"missing file: {name}")
            continue
        if not isinstance(expected_sha, str) or len(expected_sha) != 64:
            errors.append(f"invalid sha on {name}")
            continue
        if model.sha256_hex(path.read_bytes()) != expected_sha:
            errors.append(f"sha mismatch on {name}")

    trial_path = package_dir / "trial.jsonl"
    packet_path = package_dir / "packet.jsonl"
    eligible_path = package_dir / "publication_eligible.json"
    trials = _load_jsonl(trial_path, errors) if trial_path.exists() else []
    packets = _load_jsonl(packet_path, errors) if packet_path.exists() else []
    counts = manifest.get("row_counts")
    if not isinstance(counts, dict) or counts.get("trials") != len(trials) or counts.get("packets") != len(packets):
        errors.append("manifest row_counts mismatch")

    eligible = None
    if eligible_path.exists():
        try:
            eligible_text = eligible_path.read_text()
            eligible = json.loads(eligible_text)
        except (OSError, json.JSONDecodeError):
            errors.append("invalid publication_eligible.json")
        else:
            if not isinstance(eligible, bool) or eligible_text != model.canonical_json(eligible) + "\n":
                errors.append("invalid publication_eligible.json")

    packets_by_trial = {}
    for packet in packets:
        trial_id = packet.get("trial_id")
        if not isinstance(trial_id, str):
            errors.append("packet missing trial_id")
            continue
        packets_by_trial.setdefault(trial_id, []).append(packet)
    seen = set()
    derived_eligible = False
    for index, trial in enumerate(trials, 1):
        trial_id = trial.get("trial_id")
        if not isinstance(trial_id, str) or len(trial_id) != 64:
            errors.append(f"trial row {index} invalid trial_id")
            derived_eligible = False
            continue
        if trial_id in seen:
            errors.append(f"duplicate trial_id: {trial_id}")
        seen.add(trial_id)
        completed = trial.get("status") == "completed" and trial.get("cleanup_status") == "passed"
        proven = model.transfer_proven(trial, packets_by_trial.get(trial_id))
        if trial.get("status") == "completed" and not proven:
            errors.append(f"trial row {index} transfer unproven")
        if not completed or not proven:
            derived_eligible = False
    if eligible is not None and eligible != derived_eligible:
        errors.append("publication eligibility does not match trial evidence")
    return errors

