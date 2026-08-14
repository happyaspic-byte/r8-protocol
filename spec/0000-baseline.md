# R8 Gate-0 baseline inventory

> Status: FROZEN BASELINE — private, experimental, closed-lab R8 only. This is not an Internet standard and must not be called “IPv8”.
> Revalidation method: read-only Git and file inspection; no test, build, formatter, CI, or network operation was run.

## 1. Bound source and repository state

| Item | Recorded value |
|---|---|
| Commit (`git rev-parse HEAD`) | `aacadeee2a83b7639225cd11b9c020c69526fa1e` |
| Tree (`git rev-parse HEAD^{tree}`) | `94fed3c18bbfb276c9fe5d558277b8afe1d7bca5` |
| Working-tree observation | `git status --short` reported only untracked `.gjc/`; it is outside this inventory and was not inspected or changed. |
| Active CI | No `.github/workflows` path is present in the bound tree. `tools/ci-template.yml` is an inactive template, not an active workflow. |
| Existing commands recorded, not run | `python3 reference/r8ref.py selftest`; `python3 reference/r8ref.py listen …`; `python3 reference/r8ref.py ping …`; `sudo tools/netns-topo.sh setup|demo|teardown`; `cd rust && cargo test --workspace`. |

### 1.1 Authoritative existing paths and blobs

| Existing path | Blob | Recorded role / symbols |
|---|---|---|
| `README.md` | `625dc30fa0198817167adbd6dab28a096333a047` | repository status and operator commands |
| `spec/0001-wire-format-v0.1.md` | `29928f1b82c78675ec9a6f04c0478cc90295e920` | bound-snapshot v0.1 wire authority: header §2, CTL §4, DGRAM §5, SES §6, MTU §8 |
| `spec/0002-architecture.md` | `97cc46ffb8deb974d5705e582d6df4da8edd5659` | architecture summary |
| `spec/0003-test-plan.md` | `c15906e2424e678089ae21099242643e2c81566c` | Q1–Q3 test-plan authority |
| `docs/naming-and-legal.md` | `d130d49d6c8f7870f761cbf1baf61b2b5bfb681a` | naming and legal constraints |
| `reference/r8ref.py` | `8de5edb952a2b2b0b0006d06c5168eb7c143ce49` | `Header.pack` 73–79; `Header.unpack` 81–93; `build_ctl` 98–103; `parse_ctl` 106–113; `build_dgram` 118–123; `parse_dgram` 126–133; `run_echo_server` 148–179; `cmd_ping` 189–221; `selftest` 236–280 |
| `rust/crates/r8-proto/src/lib.rs` | `fed45d5ec559c6381a6dc2f6ac509041757d0402` | `Header::pack` 64–78; `Header::unpack` 81–109; `build_ctl` 147–158; `parse_ctl` 161–171; `build_dgram` 174–187; `parse_dgram` 190–206; tests `header_roundtrip` 217–225, `rejects_bad_version_and_truncation` 228–235, `ctl_checksum_detects_corruption` 238–249, `dgram_roundtrip` 252–258 |
| `rust/crates/r8d/src/main.rs` | `bf55cabf8b9306823169fada9ef13d9f74dd9142` | UDP daemon entry point and CTL/DGRAM dispatch 8–65 |
| `rust/crates/r8ping/src/main.rs` | `d15467e27681b12efe7828ef062068e268b6ff54` | UDP echo-client entry point and packet call site 9–82 |
| `tools/netns-topo.sh` | `fd17a7c0d9d9d5e8fe3a4cc1b0afd8acee21acf5` | `setup|demo|teardown` IPv4 UDP topology |
| `tools/wireshark/r8.lua` | `9cab6de6560f7d3d00e19d58e8088dcd68d32414` | minimal CTL dissector |
| `tools/ci-template.yml` | `a725f40c2e540b062f9e46c6ae242e2034744d3a` | inactive CI template |

### 1.2 Existing defects and observable baseline

* Rust `Header::pack` converts `payload.len()` with `as u16` (line 68), and Rust `build_dgram` does the same for the DGRAM length (line 175).
* Both header parsers reject only a packet shorter than `48 + Payload Length`; both return that declared slice and ignore trailing bytes (Python 89–93; Rust 88–108).
* Python `parse_dgram` does not reject a declared length below 8 or beyond the supplied payload and computes its checksum over the supplied payload rather than the declared DGRAM span (126–133). Rust checks `8 <= Length <= supplied payload` but likewise checks the supplied payload (194–205).
* CTL parsers require only four bytes. `run_echo_server` then unpacks the first four ECHO body bytes without a body-length check (Python 163–171), so malformed ECHO can raise instead of producing a defined parse outcome.

## 2. v0.1 frozen field, length, checksum, and accepted-language matrix

All integer fields are big-endian. “Accepted now” describes the bound reference implementations; it does not silently add a strict behavior to v0.1.

| Layer / field | Offset | Width | v0.1 emitted value / checksum coverage | Accepted now |
|---|---:|---:|---|---|
| Base header | 0 | 48 bytes | exactly 48 bytes before payload | parser requires at least 48 bytes |
| Version / Profile | 0 | 4b / 4b | Version is 8; pack masks Profile to 4 bits | only Version 8 is rejected/accepted; Profile values 0–15 are preserved, with 0 emitted by default |
| Traffic Class | 1 | 8b | default 0 | any value is preserved; no parser policy |
| Payload Length | 2 | 16b | emitted as payload byte count by Python; Rust truncates modulo 2^16 on oversized input | packet is accepted when supplied bytes are at least `48 + declared length`; trailing bytes are ignored |
| Next Header | 4 | 8b | CTL=1, DGRAM=2, SES=3, NONE=59 | header parser has no next-header allow-list; daemon handles CTL/DGRAM only |
| Hop Limit | 5 | 8b | default 64 | no parser or forwarding decrement policy in the bound implementations |
| Flags | 6 | 8b | default 0; documented V=bit0, R=bit1, C=bit2 | every bit is preserved; no reserved-bit policy |
| Path Slot | 7 | 8b | default 0 | every value is preserved; no profile/slot policy |
| SCID | 8 | 64b | default 0 | every value is preserved; no session-state validation |
| Source LOC | 16 | 128b | serialized locator | any 16 bytes are accepted as a locator |
| Destination LOC | 32 | 128b | serialized locator | any 16 bytes are accepted as a locator; daemon additionally compares it with its configured locator |
| CTL Type / Code / Checksum | 48 / 49 / 50 | 1 / 1 / 2 bytes | CTL is `Type||Code||Checksum||Body`; checksum is one’s complement over `src||dst||u32(payload length)||u32(1)||entire CTL`, with checksum field included | at least 4 CTL bytes; checksum 0 is accepted as unchecked, otherwise verification verdict is returned rather than rejected by `parse_ctl` |
| CTL ECHO body | 52 | at least 4 bytes for ECHO handling | request body begins `Identifier:u16||Sequence:u16`; reply reflects body | parser accepts any body length; echo server assumes at least 4 bytes |
| DGRAM ports / length / checksum | 48 / 50 / 52 / 54 | 2 / 2 / 2 / 2 bytes | `SourcePort||DestinationPort||Length||Checksum||Data`; Length is header-inclusive; checksum uses the same pseudo-header with next-header 2 | Python: supplied payload ≥8, returned data is slice `[8:Length]`; Rust: `8 <= Length <= supplied payload`, returned data is `[8:Length]`; both permit trailing bytes and verify a nonzero checksum over supplied payload |
| SES common header | 48 | 4 bytes | `Type:u8||Flags:u8||Reserved:u16||Body` is documented only | no SES parser or serializer exists in the bound implementations |

**Exact datagram length:** the emitted v0.1 form is `48 + Payload Length`, and emitted DGRAM body length is its serialized `Length`. The current accepted language is deliberately broader because trailing bytes are ignored. Changing acceptance to require exact equality, changing checksum coverage to the declared DGRAM span, or rejecting malformed DGRAM lengths changes the accepted language and observable parse outcome.

**Reserved/profile/flags:** v0.1 emits default Profile=0, Traffic Class=0, Flags=0, Path Slot=0, and has no implemented reserved-bit, profile, or flag admission rule. Assigning meanings or rejecting values is a semantic change, not a v0.1 clarification.

**CTL minima:** every CTL message requires the four-byte common header; ECHO_REQUEST and ECHO_REPLY require at least four additional body bytes (`Identifier||Sequence`) before an echo endpoint may consume them. The bound parser does not enforce the latter minimum.

## 3. Single-valued change classification

**Classification: clean v0.2 is REQUIRED.** The required strict exact-datagram rule, declared-span DGRAM checksum, DGRAM-length validation, CTL ECHO body minimum, and reserved/profile/flags admission rules alter accepted packet language and/or observable parse outcome. They therefore cannot be made as v0.1 edits. There is no compatibility shim, downgrade negotiation, or dual interpretation.

The v0.1 documents retain their existing emitted bytes: 48-byte base header, offsets, field encodings, and checksum domain for packets they emit. `spec/0004-wire-format-v0.2.md` now defines the strict language and clean deployment/configuration cutover; `spec/0005-session-security-v0.1.md`, `spec/0006-mobility-v0.1.md`, `spec/0007-native-binding-v0.1.md`, and `spec/0008-redundant-v0.1.md` are the separate frozen Gate-0 companion contracts. v0.1 is offline historical emitted-byte evidence only and is not an active implementation target.

## 4. Serialized cap and binding budgets

The serialized R8 packet cap is **1280 bytes**, including the 48-byte base header. It is not automatically a UDP payload or application budget. Fragmentation is forbidden; serializers reject rather than fragment.

| Binding | Effective binding budget | Default at PMTU 1280 |
|---|---|---:|
| UDP | `min(1280, configured_or_discovered_PMTU - IP_header - UDP_header)` | IPv4: 1252 bytes; IPv6: 1232 bytes |
| Native Ethernet | `min(1280, Ethernet_payload_budget_after_VLAN)` | binding-specific |

Application budget is the effective binding budget minus the 48-byte base header, selected SES/DGRAM framing, 16-byte AEAD tag, and mobility/multipath metadata. Exact per-binding application formulas, constants, and boundary vectors are normative in `spec/parameters-v0.1.md` and applied by `0004-wire-format-v0.2.md` and the applicable frozen companion contract; no implementation may infer them by fragmenting.

## 5. Path status

| Path | Status at bound tree | Current Gate-0 disposition |
|---|---|---|
| `spec/0000-baseline.md` | absent | frozen provenance record; its commit/tree/blob facts remain historical facts about the bound tree |
| `spec/0001-wire-format-v0.1.md` | existing | offline historical 48-byte emitted-byte evidence only; not an active parser or implementation target |
| `spec/0002-architecture.md` | existing | architecture summary updated to name the active contract set |
| `README.md` | existing | operator status and active-contract index |
| `spec/0004-wire-format-v0.2.md` | absent | frozen Gate-0 contract; the single active strict wire target |
| `spec/0005-session-security-v0.1.md` | absent | frozen Gate-0 session-security contract |
| `spec/0006-mobility-v0.1.md` | absent | frozen Gate-0 mobility and candidate-binding contract |
| `spec/0007-native-binding-v0.1.md` | absent | frozen Gate-0 native-binding contract |
| `spec/0008-redundant-v0.1.md` | absent | frozen Gate-0 Profile-3 REDUNDANT contract |
| `spec/parameters-v0.1.md` | absent | frozen Gate-0 registry for packet, binding, and resource limits |

“Absent” in this table is a fact about the bound commit/tree only. The frozen contracts listed as current were added after that source snapshot and do not revise its provenance facts.

M2, M3, M4, and M5 remain unexecuted. The frozen contracts define implementation targets; this inventory records no implementation, CI, security, mobility, native-forwarding, or multipath completion.
## 6. Frozen machine-contract artifacts

The following paths are created Gate-0 artifacts, not existing paths in the bound commit/tree inventory above:

| Path | Role / status |
|---|---|
| `tests/vectors/schema.json` | frozen machine-readable vector-manifest schema |
| `tests/vectors/manifest.json` | frozen vector-manifest contract; its fixtures are planned, not executed tests |
| `bench/protocols/q1.json` | frozen Q1 preregistration, no results |
| `bench/protocols/q2.json` | frozen Q2 preregistration, no results |
| `bench/protocols/q3.json` | frozen Q3 preregistration, no results |
| `bench/protocols/manifest.json` | frozen preregistration manifest, `r8-benchmark-preregistration-manifest-v1` |

`bench/protocols/manifest.json` binds the approved-plan SHA-256 `f3a1b806f8ae6de4e622ade08797f28034827afeaef4500768a20eefc75c550c` and baseline commit `aacadeee2a83b7639225cd11b9c020c69526fa1e` / tree `94fed3c18bbfb276c9fe5d558277b8afe1d7bca5`, and records these byte-derived preregistration digests and sizes:

| Protocol | Path | Size (bytes) | SHA-256 |
|---|---|---:|---|
| Q1 | `bench/protocols/q1.json` | 3196 | `a63788866da7a7b0cfbb8af0b07f96a0ddc041b2926d04debe8ee48e83cd5960` |
| Q2 | `bench/protocols/q2.json` | 3367 | `12f678e6af04b1377bb977cf17da7f3a08bd2f0f9b3b30c43d4e6f072dbd840d` |
| Q3 | `bench/protocols/q3.json` | 3014 | `86de498d4690d9de98333d8a99b74c985e8561e57f060b7c6bb68a833ba58cbf` |

The manifest’s change rule requires a new labeled series and manifest for any preregistration byte or configuration change; observed data must not be overwritten. These artifacts record contracts and preregistration only, not test execution, implementation, CI, or results.
