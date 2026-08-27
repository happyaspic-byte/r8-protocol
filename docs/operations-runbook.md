# R8 Closed-Lab Operations Runbook

R8 is an experimental protocol for isolated laboratories. Public and third-party networks are prohibited. This runbook does not authorize Internet deployment.

## Preconditions

1. Use a disposable Linux host or disposable network namespaces.
2. Confirm no namespace interface has a default route, global address, bridge, bond, or attachment to public/third-party networks.
3. Record the git commit, source identity, host epoch, kernel, MTU, and topology.
4. Run `make check`, `make test`, and `make demo` before promotion.
5. Run `make compare-smoke`; `publication_eligible=false` is expected until live QUIC/MPTCP adapters are complete.
6. For Native/Gate evidence, use the exact-head Q1 → Native → Q2 workflow chain.

## Deployment

### Loopback evaluation

```bash
make package-deb
sudo dpkg -i dist/r8-protocol_0.1.0_amd64.deb
r8d --address 8:1::1 --bind 127.0.0.1:52808
```

In another terminal:

```bash
r8ping --address 8:1::2 --peer 8:1::1=127.0.0.1:52808 --count 4 8:1::1
```

Expected result: `sent=4 received=4 invalid=0`.

### Namespace evaluation

Run `make demo`. It creates only `r8-a`, `r8-rtr`, and `r8-b`, then tears them down on success or failure. Verify `ip netns list` contains none of those names afterward.

### Container evaluation

```bash
docker compose up -d
docker compose exec r8d /usr/local/bin/r8ping --address 8:1::2 --peer 8:1::1=127.0.0.1:52808 --count 4 8:1::1
docker compose down
```

## Observability

Allowed telemetry is finite counters and monotonic timestamps only:

- parser categories
- sent/received/lost/duplicate/reordered packets
- authentication and replay closes
- candidate/path transitions
- route/hop/MTU/filter drops
- queue/window high-water values
- setup, cleanup, and process exit status

Never log cookies, keys, plaintext, raw pins, or unbounded EID/SCID/LOC/IP/MAC labels. Retained evidence must bind every file with SHA-256 and include source identity, commit, host epoch, topology, and limitations.

## Rollback

1. Stop `r8gateway`, `r8d`, `r8-native`, and `r8-redundant-native` processes.
2. Run `make teardown` and confirm `ip netns list` has no `r8-*` namespace.
3. Remove the package with `sudo dpkg -r r8-protocol`, or run `docker compose down` for container evaluation.
4. Restore the last commit with independently usable gate evidence; never weaken validation or bypass failed checks.
5. Preserve failed evidence packages and logs before removing temporary state.

## Capacity limits

Operational limits are authoritative in `spec/parameters-v0.1.md`:

- serialized R8 packet maximum: 1280 bytes
- UDP default binding budget: 1252 bytes
- DGRAM payload in the gateway: at most `binding_budget - 56`
- session, pending, replay, candidate, dedup, and queue limits: reject new state at the registered limit
- counter zero and exhaustion are terminal errors; no wraparound

Do not raise a limit during a measured run. Any changed limit creates a new labeled series and a new source/config binding.

## Incident response

| Signal | Immediate action | Evidence to preserve |
|---|---|---|
| Parser crash or unbounded state | Stop newest feature; terminate run | input category, process status, bounded diagnostic |
| Nonce/counter reuse | Stop all session traffic | source identity, session category counts; no keys |
| Auth/replay/binding bypass | Stop and review; do not retry | failing fixture, commit, exact binding role |
| Secret or raw identifier leak | Revoke evidence package access; stop publication | file hash, field name, affected run IDs |
| Native interface not isolated | Kill native process; teardown namespace | interface/route/filter/UID attestation |
| Missing topology/path proof | Mark run ineligible | manifest, cleanup result, missing proof category |
| Unequal comparison trigger/load | Mark comparison ineligible | plan row, event timestamps, mechanism config |
| Q2 failure | Let ownership restoration upload diagnostics | artifact digest, trial/evidence rows, publication flag |

Stop and review rather than adding fallback, retries, validation exceptions, or `--no-verify` behavior.
