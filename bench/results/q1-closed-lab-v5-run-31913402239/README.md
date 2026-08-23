# Q1 v5 closed-lab result package

This byte-for-byte package came from closed-lab GitHub Actions run `31913402239` (workflow `Q1 Full`, `workflow_dispatch`) at commit `d62cd8054cf859ab85d21ddda22b02404f8d81fb` and host epoch `closed-lab-epoch-260815225528`. The run started 2026-08-15T22:55:46Z and completed successfully in 3h13m42s.

`publication_eligible.json` is `true` and this is the first publication-eligible Q1 evidence series. It was produced under the frozen preregistration `bench/protocols/q1.json` v5 (`sha256:905f2eb8abd6a2927c4d3e8416574a4da9c4a9fe14eea4624a98a604b75b5b48`, 14,317 bytes); the artifact `summary.json` rows record `contract_version: r8-benchmark-preregistration-v5` and a single `configuration_sha256:793bd42253251a30d11bf97f51e0196bdda27e96a1520b1e537fea7d6ab2feaf` across all six cells.

## Package contents

- `raw.json`: 1,320 rows. Six cells (`R8`, `TCP-reconnect`, `GARP-VIP` × `abrupt-break`, `make-before-break`) with 200 measured trials plus 20 excluded warmups each.
- `summary.json`: one estimand row per cell, failure rate, outage p50/p95 in nanoseconds, and block-bootstrap 95% CIs (10,000 resamples, fixed seed).
- `environment.json`, `topology.json`: redacted environment and topology records (CPU model/governor redacted; 3 netns, 10 interfaces, IPv4-only, MTU 1500, offloads disabled).
- `preflight.json`: required root capabilities (`CAP_NET_ADMIN`, `CAP_NET_RAW`) and binaries.
- `manifest.json`: SHA-256 of every listed file, the git commit, the host epoch, and the implementation source map.

## Observed outcome summary (nearest-rank quantiles over nonfailed uncensored outages)

| Mechanism | Arm | n | failure rate | outage p50 (ms) | outage p95 (ms) |
|---|---|---:|---:|---:|---:|
| R8 | abrupt-break | 200 | 0.0 | 110.038803 | 110.175793 |
| R8 | make-before-break | 200 | 0.0 | 100.052691 | 100.176378 |
| TCP-reconnect | abrupt-break | 200 | 0.0 | 129.999624 | 130.042595 |
| TCP-reconnect | make-before-break | 200 | 0.0 | 120.000143 | 120.032297 |
| GARP-VIP | abrupt-break | 200 | 0.0 | 100.002123 | 100.033094 |
| GARP-VIP | make-before-break | 200 | 0.0 | 100.000793 | 100.030057 |

Across all 1,200 measured rows there were zero failures, zero duplicate payloads, and zero reordered payloads; 602 scheduled payloads were lost during outage windows. Interpretation beyond the preregistered fields is out of scope for this package README.

## Verification performed on retention (2026-08-23)

- Every file hash in `manifest.json` matches the retained bytes.
- All 12 implementation-source hashes match blob contents at commit `d62cd8054cf859ab85d21ddda22b02404f8d81fb`.
- Recomputing nearest-rank p50/p95 per cell from `raw.json` reproduces every `summary.json` point estimate exactly.
- Hosted artifact digest at retention time: `sha256:35c6e98151b28f2f4cd08f81d59da48704155aea72622429c69f304c48496349`; artifact expires 2026-09-15.

This is closed-lab-only evidence from an isolated privileged hosted run. It makes no Internet or standardization claim.
