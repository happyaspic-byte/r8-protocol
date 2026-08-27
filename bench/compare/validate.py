"""Independent validator for comparison evidence packages."""
import json
from pathlib import Path

from . import model


def validate_package(package_dir: Path) -> list:
    errors = []
    manifest_path = package_dir / "manifest.json"
    if not manifest_path.exists():
        return ["missing manifest.json"]
    try:
        manifest = json.loads(manifest_path.read_text())
    except json.JSONDecodeError:
        return ["invalid manifest.json"]
    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        return ["manifest files map is missing"]
    for name, expected_sha in files.items():
        path = package_dir / name
        if not path.exists():
            errors.append(f"missing file: {name}")
            continue
        actual_sha = model.sha256_hex(path.read_bytes())
        if actual_sha != expected_sha:
            errors.append(f"sha mismatch on {name}")
    eligible_path = package_dir / "publication_eligible.json"
    if not eligible_path.exists():
        errors.append("missing publication_eligible.json")
    return errors
