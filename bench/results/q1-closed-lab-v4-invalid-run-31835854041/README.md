# Q1 v4 invalid diagnostic package

This byte-for-byte package came from closed-lab GitHub Actions run `31835854041` at commit `881826bb64bc38bbbbffe7ab9cdcedecc98a82e2` and host epoch `closed-lab-epoch-011`.

It is **not a result package** and must not be used for estimands. `publication_eligible.json` is `false` and `summary.json` is empty. Of 1,320 retained rows, 1,257 reached complete source-bound evidence and 63 were pre-runtime `worker_timeout` setup failures. The failures exposed an unbounded aggregate readiness wait: a TCP/GARP endpoint could exit before writing its readiness byte, leaving the worker blocked until supervisor termination.

The package manifest and all listed file hashes were verified after download. Its implementation source map independently matches the exact Git commit. Q1 v5 supersedes this series with bounded child-liveness-aware readiness and preserves every v4 row here solely as negative diagnostic evidence.
