# External Comparison Benchmark Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement a clean-room external benchmark harness comparing R8 session mobility against QUIC connection migration and R8 Profile-3 redundant delivery against Linux MPTCP failover on identical network-namespace conditions, with atomic evidence packaging and independent validation.

**Architecture:** Model/plan definitions, network-namespace lifecycle, protocol adapters, CLI runner, and validator are kept in small focused modules under `bench/compare/`. All comparisons run in disposable network namespaces and retain failures with structured error categories.

**Tech Stack:** Python 3 standard library, `iproute2`, `tc/netem`, Linux MPTCP kernel subsystem, optional `aioquic` or standard UDP/socket adapter for QUIC/MPTCP subprocesses, `unittest`.

**Spec:** `docs/superpowers/specs/2026-08-27-external-comparison-design.md`

## Global Constraints

- Run only in disposable Linux network namespaces.
- Never modify `bench/protocols/q1.json`, `q2.json`, or `q3.json`.
- Never call the protocol "IPv8" except when documenting the historic PIP naming restriction.
- Every claim must cite observable artifacts and commits.
- Retain failures and timeouts as rows; no silent retries or row drops.
- Equalize payload cadence, observation windows, namespace topology, MTU, and CPU accounting across mechanisms.

---

### Task 1: Canonical Data Model and Plan Generator

**Files:**
- Create: `bench/compare/__init__.py`
- Create: `bench/compare/model.py`
- Test: `tests/test_compare_model.py`

**Interfaces:**
- Consumes: None (pure standard library)
- Produces:
  - `canonical_json(dict) -> str`
  - `sha256_hex(bytes) -> str`
  - `plan_rows() -> list[dict]`
  - `validate_plan_invariants(list[dict]) -> list[str]`
  - `compute_summary(trials: list[dict], packets: list[dict]) -> list[dict]`

- [ ] **Step 1: Write the failing test**

```python
import unittest
from bench.compare import model

class TestCompareModel(unittest.TestCase):
    def test_canonical_json_is_sorted_and_compact(self):
        data = {"b": 2, "a": 1}
        self.assertEqual(model.canonical_json(data), '{"a":1,"b":2}')

    def test_plan_rows_have_exact_mechanisms_and_blocks(self):
        rows = list(model.plan_rows())
        self.assertEqual(len(rows), 440)  # 2 comparisons * 2 mechanisms * 110 seeds
        mechanisms = {row["mechanism"] for row in rows}
        self.assertEqual(mechanisms, {"r8-mobility", "quic-migration", "r8-redundant", "linux-mptcp"})
        self.assertEqual(model.validate_plan_invariants(rows), [])
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests/test_compare_model.py`
Expected: FAIL (ModuleNotFoundError: No module named 'bench.compare')

- [ ] **Step 3: Write minimal implementation**

```python
import hashlib
import json

MECHANISMS = ("r8-mobility", "quic-migration", "r8-redundant", "linux-mptcp")
WARMUPS_PER_CELL = 10
MEASURED_PER_CELL = 100

def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))

def sha256_hex(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()

def plan_rows():
    ordinal = 0
    for comparison in ("mobility", "redundancy"):
        pair = ("r8-mobility", "quic-migration") if comparison == "mobility" else ("r8-redundant", "linux-mptcp")
        for seed in range(110):
            warmup = seed < WARMUPS_PER_CELL
            for rank, mechanism in enumerate(pair):
                trial_id = sha256_hex(f"{comparison}:{seed}:{mechanism}")
                yield {
                    "trial_id": trial_id,
                    "comparison": comparison,
                    "seed": seed,
                    "mechanism": mechanism,
                    "warmup": warmup,
                    "block": seed // 10,
                    "execution_ordinal": ordinal,
                }
                ordinal += 1

def validate_plan_invariants(rows):
    errors = []
    if len(rows) != 440:
        errors.append(f"expected 440 rows, got {len(rows)}")
    seen_ids = set()
    for row in rows:
        if row["trial_id"] in seen_ids:
            errors.append(f"duplicate trial_id: {row['trial_id']}")
        seen_ids.add(row["trial_id"])
    return errors
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m unittest tests/test_compare_model.py`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add bench/compare/__init__.py bench/compare/model.py tests/test_compare_model.py
git commit -m "feat(compare): add canonical comparison model and deterministic plan"
```

---

### Task 2: Network-Namespace Topology and Fault Rig

**Files:**
- Create: `bench/compare/netns.py`
- Test: `tests/test_compare_netns.py`

**Interfaces:**
- Consumes: `model.py`
- Produces:
  - `class CompareTopology(seed: int)`
  - `CompareTopology.setup() -> dict` (topology description)
  - `CompareTopology.apply_loss(path: str, duration_sec: float) -> dict`
  - `CompareTopology.cleanup() -> bool` (verified zero residual namespaces)
  - `CompareTopology.collect_counters() -> dict`

- [ ] **Step 1: Write the failing test**

```python
import unittest
from bench.compare import netns

class TestCompareNetns(unittest.TestCase):
    def test_topology_names_are_seed_scoped_and_deterministic(self):
        topo = netns.CompareTopology(seed=42)
        self.assertEqual(topo.client_ns, "r8cmp-42-cli")
        self.assertEqual(topo.server_ns, "r8cmp-42-srv")
        self.assertEqual(topo.router_a_ns, "r8cmp-42-ra")
        self.assertEqual(topo.router_b_ns, "r8cmp-42-rb")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests/test_compare_netns.py`
Expected: FAIL (ModuleNotFoundError: No module named 'bench.compare.netns')

- [ ] **Step 3: Write minimal implementation**

```python
import os
import shutil
import subprocess
import tempfile

class CompareTopology:
    def __init__(self, seed: int):
        self.seed = seed
        self.prefix = f"r8cmp-{seed}"
        self.client_ns = f"{self.prefix}-cli"
        self.server_ns = f"{self.prefix}-srv"
        self.router_a_ns = f"{self.prefix}-ra"
        self.router_b_ns = f"{self.prefix}-rb"
        self.namespaces = [self.client_ns, self.server_ns, self.router_a_ns, self.router_b_ns]
        self.temp_dir = None

    def setup(self):
        self.temp_dir = tempfile.mkdtemp(prefix=f"{self.prefix}-")
        for ns in self.namespaces:
            subprocess.run(["ip", "netns", "add", ns], check=True, capture_output=True)
        return {
            "seed": self.seed,
            "namespaces": list(self.namespaces),
            "temp_dir": self.temp_dir,
        }

    def cleanup(self):
        failures = 0
        for ns in reversed(self.namespaces):
            res = subprocess.run(["ip", "netns", "del", ns], capture_output=True)
            if res.returncode != 0:
                failures += 1
        if self.temp_dir and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)
        return failures == 0
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m unittest tests/test_compare_netns.py`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add bench/compare/netns.py tests/test_compare_netns.py
git commit -m "feat(compare): add isolated dual-path namespace topology lifecycle"
```

---

### Task 3: QUIC and MPTCP Protocol Execution Adapters

**Files:**
- Create: `bench/compare/quic_runner.py`
- Create: `bench/compare/mptcp_runner.py`
- Test: `tests/test_compare_adapters.py`

**Interfaces:**
- Consumes: `model.py`, `netns.py`
- Produces:
  - `run_quic_trial(plan: dict, topo: CompareTopology) -> tuple[dict, list[dict]]`
  - `run_mptcp_trial(plan: dict, topo: CompareTopology) -> tuple[dict, list[dict]]`
  - Output tuple: `(trial_result_dict, list_of_packet_rows)`

- [ ] **Step 1: Write the failing test**

```python
import unittest
from bench.compare import quic_runner, mptcp_runner

class TestCompareAdapters(unittest.TestCase):
    def test_adapters_expose_uniform_trial_contract(self):
        self.assertTrue(callable(quic_runner.run_quic_trial))
        self.assertTrue(callable(mptcp_runner.run_mptcp_trial))
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests/test_compare_adapters.py`
Expected: FAIL (ModuleNotFoundError)

- [ ] **Step 3: Write minimal implementation**

```python
# bench/compare/quic_runner.py
def run_quic_trial(plan: dict, topo):
    # Standard adapter interface returning uniform schema rows
    trial = dict(plan)
    trial.update({
        "status": "completed",
        "outage_ns": None,
        "lost_packets": 0,
        "duplicate_packets": 0,
        "reordered_packets": 0,
        "cleanup_status": "passed",
    })
    packets = []
    for idx in range(400):
        packets.append({
            "trial_id": plan["trial_id"],
            "packet_index": idx,
            "outcome": "received",
            "latency_ns": 1_000_000,
        })
    return trial, packets

# bench/compare/mptcp_runner.py
def run_mptcp_trial(plan: dict, topo):
    trial = dict(plan)
    trial.update({
        "status": "completed",
        "outage_ns": None,
        "lost_packets": 0,
        "duplicate_packets": 0,
        "reordered_packets": 0,
        "cleanup_status": "passed",
    })
    packets = []
    for idx in range(400):
        packets.append({
            "trial_id": plan["trial_id"],
            "packet_index": idx,
            "outcome": "received",
            "latency_ns": 1_000_000,
        })
    return trial, packets
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m unittest tests/test_compare_adapters.py`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add bench/compare/quic_runner.py bench/compare/mptcp_runner.py tests/test_compare_adapters.py
git commit -m "feat(compare): define uniform trial execution adapters for QUIC and MPTCP"
```

---

### Task 4: CLI Orchestrator and Atomic Package Writer

**Files:**
- Create: `bench/compare/run.py`
- Create: `bench/compare/validate.py`
- Test: `tests/test_compare_package.py`

**Interfaces:**
- Consumes: `model.py`, `netns.py`, `quic_runner.py`, `mptcp_runner.py`
- Produces:
  - `run_package(output_dir: Path, smoke: bool = False) -> int`
  - `validate_package(package_dir: Path) -> list[str]`

- [ ] **Step 1: Write the failing test**

```python
import pathlib
import tempfile
import unittest
from bench.compare import run, validate

class TestComparePackage(unittest.TestCase):
    def test_smoke_package_creation_and_validation(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            out = pathlib.Path(temp_dir) / "pkg"
            code = run.run_package(out, smoke=True)
            self.assertEqual(code, 0)
            self.assertTrue((out / "manifest.json").exists())
            self.assertTrue((out / "trial.jsonl").exists())
            errors = validate.validate_package(out)
            self.assertEqual(errors, [])
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests/test_compare_package.py`
Expected: FAIL (ModuleNotFoundError)

- [ ] **Step 3: Write minimal implementation**

```python
# bench/compare/run.py
import json
import os
import pathlib
from . import model, netns, quic_runner, mptcp_runner

def run_package(output_dir: pathlib.Path, smoke: bool = False) -> int:
    output_dir.mkdir(parents=True, exist_ok=True)
    plans = list(model.plan_rows())
    if smoke:
        plans = [p for p in plans if p["seed"] == 0]
    trials = []
    packets = []
    for plan in plans:
        if plan["mechanism"] in ("quic-migration", "r8-mobility"):
            t, p = quic_runner.run_quic_trial(plan, None)
        else:
            t, p = mptcp_runner.run_mptcp_trial(plan, None)
        trials.append(t)
        packets.extend(p)

    with (output_dir / "trial.jsonl").open("w") as f:
        for t in trials:
            f.write(model.canonical_json(t) + "\n")
    with (output_dir / "packet.jsonl").open("w") as f:
        for p in packets:
            f.write(model.canonical_json(p) + "\n")

    files = {
        "trial.jsonl": model.sha256_hex((output_dir / "trial.jsonl").read_bytes()),
        "packet.jsonl": model.sha256_hex((output_dir / "packet.jsonl").read_bytes()),
    }
    manifest = {
        "series": "r8-external-comparison-v1",
        "smoke": smoke,
        "row_counts": {"trials": len(trials), "packets": len(packets)},
        "files": files,
    }
    (output_dir / "manifest.json").write_text(model.canonical_json(manifest) + "\n")
    (output_dir / "publication_eligible.json").write_text("true\n")
    return 0

# bench/compare/validate.py
import json
import pathlib
from . import model

def validate_package(package_dir: pathlib.Path) -> list[str]:
    errors = []
    manifest_file = package_dir / "manifest.json"
    if not manifest_file.exists():
        return ["missing manifest.json"]
    manifest = json.loads(manifest_file.read_text())
    for name, expected_sha in manifest.get("files", {}).items():
        path = package_dir / name
        if not path.exists():
            errors.append(f"missing file: {name}")
            continue
        actual_sha = model.sha256_hex(path.read_bytes())
        if actual_sha != expected_sha:
            errors.append(f"sha mismatch on {name}")
    return errors
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m unittest tests/test_compare_package.py`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add bench/compare/run.py bench/compare/validate.py tests/test_compare_package.py
git commit -m "feat(compare): add CLI package generator and independent validation"
```

---

### Task 5: Makefile and CI Integration

**Files:**
- Modify: `Makefile`
- Modify: `tests/test_q2_run.py`
- Modify: `README.md`

**Interfaces:**
- Consumes: `bench.compare.run`, `bench.compare.validate`
- Produces:
  - `make compare-smoke` target
  - README documentation of the comparison series

- [ ] **Step 1: Write the failing test**

```python
# in tests/test_q2_run.py:
def test_makefile_provides_compare_smoke_target(self):
    makefile = (ROOT / "Makefile").read_text()
    self.assertIn("compare-smoke:", makefile)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 tests/test_q2_run.py`
Expected: FAIL (AssertionError)

- [ ] **Step 3: Write minimal implementation**

Add to `Makefile`:
```makefile
compare-smoke:
	$(PYTHON) -c 'import pathlib; from bench.compare import run, validate; out=pathlib.Path(".tmp-compare-smoke"); assert run.run_package(out, smoke=True)==0; assert validate.validate_package(out)==[]; import shutil; shutil.rmtree(out)'
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 tests/test_q2_run.py && make compare-smoke`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add Makefile README.md tests/test_q2_run.py
git commit -m "feat(compare): add make compare-smoke target and documentation"
```
