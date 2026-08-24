# Q1 v5 closed-lab result package (run 32671846443, commit 27f949f)

This byte-for-byte package came from closed-lab GitHub Actions run `32671846443` (workflow `Q1 Full`, `workflow_dispatch`) at commit `27f949f8974e0c538c89058be0cc00162be99fae` and host epoch `closed-lab-epoch-20260823225106`. The run was created 2026-08-23T22:51:08Z and completed successfully in approximately 3h16m.

`publication_eligible.json` is `true`. It was produced under the frozen preregistration `bench/protocols/q1.json` v5 (`sha256:905f2eb8abd6a2927c4d3e8416574a4da9c4a9fe14eea4624a98a604b75b5b48`); `manifest.json` records `row_count: 1320` and a single source identity across the 12 implementation sources. This is the second publication-eligible Q1 evidence series and the first at commit `27f949f`; the first is retained at `bench/results/q1-closed-lab-v5-run-31913402239` (commit `d62cd80`).

## Package contents

- `raw.json`: 1,320 rows. Six cells (`R8`, `TCP-reconnect`, `GARP-VIP` × `abrupt-break`, `make-before-break`) with 200 measured trials plus 20 excluded warmups each.
- `summary.json`: one estimand row per cell, failure rate, outage p50/p95 in nanoseconds, and block-bootstrap 95% CIs (10,000 resamples, fixed seed).
- `environment.json`, `topology.json`: redacted environment and topology records (`cpu_model`/`cpu_governor` redacted).
- `preflight.json`: required root capabilities (`CAP_NET_ADMIN`, `CAP_NET_RAW`) and binaries.
- `manifest.json`: SHA-256 of every listed file, the git commit, the host epoch, and the implementation source map.

## Observed outcome summary (nearest-rank quantiles over nonfailed uncensored outages)

| Mechanism | Arm | n | failure rate | outage p50 (ms) | outage p95 (ms) |
|---|---|---:|---:|---:|---:|
| R8 | abrupt-break | 200 | 0.0 | 110.005927 | 110.170909 |
| R8 | make-before-break | 200 | 0.0 | 100.035703 | 100.172842 |
| TCP-reconnect | abrupt-break | 200 | 0.0 | 130.001431 | 130.067724 |
| TCP-reconnect | make-before-break | 200 | 0.0 | 120.003623 | 120.066072 |
| GARP-VIP | abrupt-break | 200 | 0.0 | 100.003900 | 100.047992 |
| GARP-VIP | make-before-break | 200 | 0.0 | 100.003275 | 100.049691 |

Across all 1,200 measured rows there were zero failures, zero duplicate payloads, zero reordered payloads, and zero censored rows; 603 scheduled payloads were lost during outage windows. A single `configuration_sha256` (`2b88cf1fdff4f5d2b61cecefc3f6d11a65870d41b8cea311493c51e616d33ce2`) covers every cell. Interpretation beyond the preregistered fields is out of scope for this package README.

## Verification performed on retention (2026-08-24)

- Every file hash in `manifest.json` matches the retained bytes.
- Recomputing nearest-rank p50/p95 per cell from `raw.json` reproduces every `summary.json` point estimate exactly.
- Hosted artifact digest at retention time: `sha256:f603522645cddbcce687621b3b182778be9f41bd7ba18fd56ef19f2a2c7f22bb`; artifact expires 2026-09-23.

This is closed-lab-only evidence from an isolated privileged hosted run. It makes no Internet or standardization claim.
