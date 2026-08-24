# Q3 closed-lab result package (run 32686226408, current censor-aware contract)

This byte-for-byte package came from closed-lab GitHub Actions run `32686226408` (workflow `Q3 Full`, `workflow_dispatch`) at commit `a5bf3b98368ba1216976b301b7cf493261f6640f` and host epoch `closed-lab-epoch-20260824032231`. The run was created 2026-08-24T03:22:32Z and completed successfully in about eight minutes in a dedicated root network namespace (`isolated_netns_proof: true`, loopback-only).

This is the first Q3 evidence package satisfying the current censor-aware preregistration `bench/protocols/q3.json` (`sha256:e5a7f57a2f9ec152edad127c84ad6a9a80b8f5b3c9e4b7299e44fd815a677e1b`). The retained `bench/results/q3-closed-lab-v8` remains historical prior-source evidence for the superseded v1 contract and is unchanged by this package.

## Package contents

- `raw.jsonl`: 4,200 rows. Four groups (`R8-cookie-pinned-full-handshake`, `TLS-1.3-full-handshake` × `cold-process-primary`, `warm-process`), each with 50 excluded warmups and 1,000 measured trials.
- `summary.json`: per group/series failure rate and Kaplan–Meier right-censored latency p50/p90 with block-bootstrap-free 95% CIs, mean CPU time, and symmetric mean network counters.
- `environment.json`: redacted environment with isolated-netns proof and implementation-source bindings.
- `run-manifest.json`: SHA-256 of every listed file, git commit, host epoch, source identity, row cardinalities.

## Observed outcome summary (preregistered estimands only)

| Series | Mechanism | n | failure rate | p50 (ms) | p90 (ms) | mean net (B/pkts each way) |
|---|---|---:|---:|---:|---:|---:|
| cold-process-primary | R8 cookie-pinned full handshake | 1000 | 0.0 | 3.005832 | 3.095002 | 1326 / 7 |
| cold-process-primary | TLS 1.3 full handshake | 1000 | 0.0 | 43.791223 | 44.182618 | 3979 / 12 |
| warm-process | R8 cookie-pinned full handshake | 1000 | 0.0 | 1.840551 | 1.953587 | 1326 / 7 |
| warm-process | TLS 1.3 full handshake | 1000 | 0.0 | 42.237867 | 42.559855 | 3979 / 12 |

Zero failures across all 4,000 measured rows; zero censored rows; network byte/packet counters are symmetric per row. Interpretation beyond these preregistered fields is out of scope for this README.

## Verification performed on retention (2026-08-24)

- Every file hash in `run-manifest.json` matches the retained bytes.
- Row count matches `row_count: 4200`; group warmup/measured/rows cardinalities match; per-row network counters are symmetric.
- The same assertions as `.github/workflows/q3-full.yml` "Validate full Q3 package" step were re-executed locally against this directory and passed.
- Hosted artifact digest at retention time: `sha256:60d2a08fe50cf647e2420763434a0da8a53856d6ae212248715be8f869ee1e7c`; artifact expires 2026-09-23.

This is closed-lab-only evidence from an isolated privileged hosted run. It makes no Internet or standardization claim.
