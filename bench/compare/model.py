"""Canonical data model for the external comparison benchmark."""
import hashlib
import json

MECHANISMS = (
    "r8-mobility",
    "quic-migration",
    "r8-redundant",
    "linux-mptcp",
)
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
        pair = (
            ("r8-mobility", "quic-migration")
            if comparison == "mobility"
            else ("r8-redundant", "linux-mptcp")
        )
        for seed in range(WARMUPS_PER_CELL + MEASURED_PER_CELL):
            warmup = seed < WARMUPS_PER_CELL
            for mechanism in pair:
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
    ordinals = set()
    for row in rows:
        trial_id = row.get("trial_id")
        ordinal = row.get("execution_ordinal")
        if trial_id in seen_ids:
            errors.append(f"duplicate trial_id: {trial_id}")
        if ordinal in ordinals:
            errors.append(f"duplicate execution_ordinal: {ordinal}")
        if row.get("mechanism") not in MECHANISMS:
            errors.append(f"unknown mechanism: {row.get('mechanism')}")
        seen_ids.add(trial_id)
        ordinals.add(ordinal)
    if ordinals != set(range(len(rows))):
        errors.append("execution ordinals are not contiguous")
    return errors
