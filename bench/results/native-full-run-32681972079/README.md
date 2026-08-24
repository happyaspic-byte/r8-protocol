# Native full Gate 4/5 evidence (run 32681972079)

This directory retains the `native-full-diagnostics` artifact from closed-lab GitHub Actions run `32681972079` (workflow `Native full`, `workflow_dispatch`, gate3 run `32671846443`) at commit `27f949f8974e0c538c89058be0cc00162be99fae`. The run completed successfully on 2026-08-24 (created 02:07Z, finished 02:09:27Z).

## Contents

- `native-one-hop.json`: Gate 4 one-hop isolated native forwarding proof (`ok: true`).
- `native-two-hop.json`: Gate 4 two-hop proof (`ok: true`).
- `redundant-native.json`: Gate 5 authenticated redundant two-path native composition proof (`ok: true`, `privilege_dropped: true`, `revocation_verified: true`, `cleanup_verified: true`).

All three files record `error_category: null` and zero cleanup failures. The Gate 5 `manifest_hash` is `4e3223aac7e405db0a3e9ac76d9edd08d7eed3a568b5312c1d78c07c3da3e73e`, matching the value enforced by `bench/q2_run.py::_expected_gate5_manifest_hash()` at this commit.

Hosted artifact digest at retention time: `sha256:9565eaa8156c7b2317ad605de697abab15d73f3b43e40ca4db2bff9dca0a4c10`; artifact expires 2026-11-22.

This is closed-lab-only evidence from an isolated privileged hosted run. It makes no Internet or standardization claim.
