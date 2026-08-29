"""Closed-lab OpenOverlayRouter LISP xTR comparison adapter."""
import shutil
import subprocess
import tempfile
from pathlib import Path

from . import model

REQUIRED_VERSION = "1.3.0"
PUBLIC_MARKERS = ("map-resolver 8.", "map-server 8.", "0.0.0.0", "lisp.cisco.com")


def _which(name):
    return shutil.which(name)


def preflight():
    binary = _which("oor") or _which("openoverlayrouter")
    if binary is None:
        return {"ok": False, "reason": "oor_unavailable", "binary": None, "version": None}
    try:
        shown = subprocess.run(
            [binary, "-v"],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return {"ok": False, "reason": "oor_unexecutable", "binary": binary, "version": None}
    text = (shown.stdout or "") + (shown.stderr or "")
    if REQUIRED_VERSION not in text:
        return {"ok": False, "reason": "oor_version_mismatch", "binary": binary, "version": text.strip()[:64] or None}
    return {"ok": True, "reason": None, "binary": binary, "version": REQUIRED_VERSION}


def write_local_config(output_dir: Path):
    output_dir.mkdir(parents=True, exist_ok=True)
    config = """\
# Closed-lab only. No public mapping system.
debug                  1
map-resolver           10.8.0.1
map-server             10.8.0.1
key                    lab-only
eid-prefix             8:1::/32
rloc                   10.8.1.10
"""
    path = output_dir / "oor.conf"
    path.write_text(config)
    text = path.read_text()
    for marker in PUBLIC_MARKERS:
        if marker in text:
            raise ValueError("public mapping configuration is rejected")
    return path


def run_lisp_trial(plan: dict, topo=None):
    trial = dict(plan)
    check = preflight()
    if not check["ok"]:
        trial.update({
            "status": "prerequisite_failed",
            "failure_reason": check["reason"],
            "cleanup_status": "passed",
            "oor_binary": check["binary"],
            "oor_version": check["version"],
        })
        return trial, []
    if topo is None:
        trial.update({
            "status": "prerequisite_failed",
            "failure_reason": "isolated_topology_required",
            "cleanup_status": "passed",
            "oor_binary": check["binary"],
            "oor_version": check["version"],
        })
        return trial, []
    temp = Path(tempfile.mkdtemp(prefix="r8-lisp-"))
    try:
        write_local_config(temp)
        if not hasattr(topo, "cut_primary"):
            trial.update({
                "status": "prerequisite_failed",
                "failure_reason": "topology_missing_cut_primary",
                "cleanup_status": "passed",
            })
            return trial, []
        cut = topo.cut_primary()
        if not cut.get("observed"):
            trial.update({
                "status": "failed",
                "failure_reason": "path_cut_unobserved",
                "cleanup_status": "passed",
            })
            return trial, []
        if not model.transfer_proven(cut):
            trial.update({
                "status": "failed",
                "failure_reason": "transfer_unproven",
                "cleanup_status": "passed",
            })
            return trial, []
        trial.update({
            "status": "completed",
            "failure_reason": None,
            "cleanup_status": "passed",
            "event_ns": cut["event_ns"],
            "outage_ns": cut.get("outage_ns", 0),
            "path_bytes": cut.get("path_bytes", {}),
            "oor_binary": check["binary"],
            "oor_version": check["version"],
        })
        return trial, cut.get("packets", [])
    finally:
        shutil.rmtree(temp, ignore_errors=True)
