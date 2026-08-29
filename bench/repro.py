"""Deterministic external reproducibility bundle. CI cannot self-claim independence."""
import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

SCHEMA_VERSION = "r8-repro-v1"


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def sha256_hex(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _git(args, cwd):
    result = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "git failed")
    return result.stdout.strip()


def collect_environment(root: Path):
    return {
        "python": sys.version.split()[0],
        "platform": sys.platform,
        "cwd": str(root),
        "ci": bool(os.environ.get("CI") or os.environ.get("GITHUB_ACTIONS")),
    }


def build_bundle(root: Path, outputs=None, reproducer_identity=None, evidence_path=None):
    commit = _git(["rev-parse", "HEAD"], root)
    tree = _git(["rev-parse", "HEAD^{tree}"], root)
    status = _git(["status", "--porcelain"], root)
    outputs = outputs or {}
    hashed = {name: sha256_hex(data) for name, data in outputs.items()}
    evidence = Path(evidence_path) if evidence_path else None
    evidence_sha256 = sha256_hex(evidence.read_bytes()) if evidence and evidence.is_file() else None
    independent = False
    if os.environ.get("GITHUB_ACTIONS") or os.environ.get("CI"):
        reproducer_identity = None
        evidence_path = None
        evidence_sha256 = None
    bundle = {
        "schema": SCHEMA_VERSION,
        "commit": commit,
        "tree": tree,
        "clean": status == "",
        "commands": [
            "python3 -m unittest discover -s tests -p 'test_*.py'",
            "go test ./...",
            "cd rust && cargo test --workspace --locked",
        ],
        "environment": collect_environment(root),
        "outputs": hashed,
        "attestation": {
            "independent_reproducer": independent,
            "reproducer_identity": reproducer_identity,
            "evidence": str(evidence_path) if evidence_path else None,
            "evidence_sha256": evidence_sha256,
        },
        "limitations": [
            "Isolated-lab evidence only.",
            "Project CI cannot self-claim independent_reproducer=true.",
            "No Internet or IPv8-standard claim.",
        ],
    }
    return bundle


def validate_bundle(bundle: dict):
    errors = []
    if bundle.get("schema") != SCHEMA_VERSION:
        errors.append("schema mismatch")
    attestation = bundle.get("attestation") or {}
    if attestation.get("independent_reproducer") is True:
        errors.append("independent_reproducer requires external verification")
        if bundle.get("environment", {}).get("ci"):
            errors.append("CI cannot self-claim independent_reproducer")
        if not attestation.get("reproducer_identity"):
            errors.append("independent_reproducer requires identity")
        if not attestation.get("evidence"):
            errors.append("independent_reproducer requires evidence")
        if not attestation.get("evidence_sha256"):
            errors.append("independent_reproducer requires evidence_sha256")
    if not bundle.get("commit") or not bundle.get("tree"):
        errors.append("missing commit/tree")
    return errors


def write_bundle(path: Path, bundle: dict):
    errors = validate_bundle(bundle)
    if errors:
        raise ValueError("; ".join(errors))
    path.write_text(canonical_json(bundle) + "\n")
    return path


def main(argv=None):
    parser = argparse.ArgumentParser(description="Build an R8 reproducibility bundle")
    parser.add_argument("--output", required=True)
    parser.add_argument("--identity")
    parser.add_argument("--evidence")
    args = parser.parse_args(argv)
    root = Path.cwd()
    bundle = build_bundle(root, reproducer_identity=args.identity, evidence_path=args.evidence)
    write_bundle(Path(args.output), bundle)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
