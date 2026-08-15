# R8 Native Binding v0.1

> Status: normative Gate-0 contract for private, experimental, isolated closed-lab networks only. Native R8 is forbidden on public, third-party, or non-isolated networks.

## 1. Ethernet framing and packet budget

The native carrier is one Ethernet II frame: destination MAC (6 bytes), source MAC (6 bytes), EtherType `0x88B5` (2 bytes), then one complete serialized R8 packet. VLAN tags are outside the R8 packet and reduce the available Ethernet payload. The R8 Version and the EtherType are both required; a frame matching only one is dropped. The frame has no native binding trailer, padding semantic, or fragmentation facility.

The maximum serialized R8 packet and native effective budget are exactly the formulas and limits in `spec/parameters-v0.1.md`: `min(1280, Ethernet_payload_budget_after_VLAN)`. Before serialization, every sender computes the effective budget and subtracts the 48-byte base header plus the selected payload framing, AEAD tag, and applicable mobility or Profile-3 metadata. Oversize packets are rejected locally as `MTU_EXCEEDED`; received declared lengths over budget and physical frames whose R8 payload exceeds 1280 bytes are counted drops, never descriptor faults, and the daemon remains live. Truncation-aware receive is mandatory. No IP packet may be generated as a fallback.

A native binding is exactly `NativeBinding { ingress_descriptor_id:u32, next_hop_mac:6 }` as canonically defined in `0006-mobility-v0.1.md`. Descriptor ID is a manifest ID, not a kernel ifindex, and a packet may be emitted only via the pre-opened descriptor named by the selected route.

## 2. Immutable manifest

The manifest is parsed, fully validated, and made immutable before descriptors are opened. It contains only the following records:

```
local_locs: [loc128]
interfaces: [{ descriptor_id:u32, interface_name, allowed_source_macs:[mac48],
               local_delivery:bool, transit:bool }]
routes: [{ destination_prefix:loc128/prefix_length,
           egress_descriptor_id:u32, next_hop_mac:mac48 }]
```

`prefix_length` is 0 through 128, but prefix length zero is invalid: there is no default route. Interface names and descriptor IDs are unique. Every route refers to one declared interface, every next-hop MAC is explicit and non-broadcast, and every local LOC has exactly 16 bytes. A startup validation rejects duplicate equal-prefix routes, overlapping equal-prefix routes, a route missing an egress descriptor, a source-MAC policy with no allowed MAC, or an interface not on the startup allowlist. The current v0.1 launcher is transit-only: `local_locs` must be empty and every `local_delivery` value must be false; any other manifest is rejected rather than handed to a sink. Manifest reload is out of scope; changing it requires process replacement and fresh validation.

Forwarding selects the matching route with greatest prefix length. Equal-length ambiguity is a startup error, so lookup is single-valued. A lookup miss is `ROUTE_MISS`, not a request for discovery. The daemon never learns routes or neighbors from traffic.

## 3. Receive and forwarding contract

The daemon runs non-root after a narrow launcher opens only manifest-named EtherType-filtered descriptors. Before inspecting network state, the launcher binds its link/address/route watcher. It requires the observed interface set to equal `{lo}` plus the exact manifest allowlist; verifies no default route, no global address, no bridge or bond attachment, the exact EtherType-and-version filter, and immutable filter state; opens only named descriptors; rejects queued watcher events; and performs a final full revalidation. It then irreversibly sets real, effective, saved, and filesystem UID/GID to the configured nonzero identities, empties supplementary groups and effective/permitted/inheritable/ambient/bounding capability sets, enables no-new-privileges, and reads every value back before readiness. Failure to apply or verify any required check aborts startup. Physical or VLAN isolation is a separately recorded operator attestation naming switch/VLAN/interfaces and confirming no public or third-party attachment.
Immediately before readiness, the unprivileged process rejects any newly queued watcher event and revalidates every mutable topology property. It does not reopen `/proc/1/ns/net` after privilege removal: the pre-drop namespace-identity proof plus the verified absence of every namespace-changing capability makes that identity irreversible, while avoiding a false startup failure when the configured nonzero UID cannot inspect PID 1.
A native Profile-3 endpoint receives exactly 64 credential bytes through inherited descriptor 3, rejects a trailing byte, zeroizes the input buffer, opens only its two named filtered packet descriptors, and then performs the same irreversible nonzero-UID/GID, empty-group, empty-capability, no-new-privileges, and nondumpable transition before any handshake packet. Credential material is never accepted through argv or environment. Endpoint readiness is emitted only after this verified transition.
Every manifest-named interface must be up at startup. Each subscribed link/address/route change revalidates the same isolation predicate, so a named interface going down or any undeclared interface appearing is irreversible runtime revocation rather than a recoverable state.
The launcher requires `disable_ipv6=1` for `all`, `default`, loopback, and every manifest-named interface, and separately requires loopback down. Residual kernel IPv6 route-table entries therefore have no active stack and are not routing authority. The IPv4 route table is still parsed strictly; any usable zero-prefix entry or malformed record aborts startup.

| State + event | Precondition | Action and mutation | Error | Timer / idempotency | Release |
|---|---|---|---|---|---|
| `STARTING` + manifest load | complete transit-only manifest and watcher-first launcher checks pass | bind watcher; validate; pre-open only named descriptors; reject queued events; revalidate; irreversibly drop and verify all privilege; enter `RUNNING` | `MANIFEST_INVALID`/`ISOLATION_FAILED` | no retry within process; repeated identical startup is independent | failed startup closes descriptors and erases manifest copy |
| `RUNNING` + Ethernet frame | EtherType, descriptor, source policy, exact R8 length, and physical receive length valid | parse header and evaluate transit | `FRAME_INVALID`/`SOURCE_SPOOF`/`MALFORMED` | no state allocation; over-budget input is a counted drop and processing continues | no per-frame release needed |
| `RUNNING` + transit packet | ingress permits transit; hop limit greater than one; deterministic route exists; egress budget fits | decrement hop once; preserve all other packet bytes; send through selected descriptor using manifest next-hop MAC | `TRANSIT_DISABLED`/`HOP_EXCEEDED`/`ROUTE_MISS`/`MTU_EXCEEDED` | no retry or queue created by forwarding; same frame is processed independently | none |
| `STARTING` + local-delivery configuration | any local LOC or `local_delivery=true` | reject the manifest; no descriptor becomes ready | `MANIFEST_INVALID` | no fallback or counted sink | erase manifest copy |
| `RUNNING` + descriptor/filter/privilege fault | any runtime check detects revoked required invariant | stop receive/transmit and enter `STOPPING` | `ISOLATION_FAILED` | no automatic recovery | close every descriptor and erase process-held sensitive state |
| `STOPPING` + teardown | owned descriptors only | close descriptors; remove only launcher-owned resources; enter `RELEASED` | local `TEARDOWN_FAILED` if cleanup is incomplete | idempotent close | all live references released |

A forwarding implementation is flow-stateless: it retains no route, peer, session, or neighbor information as a consequence of a forwarded packet. It applies `0004-wire-format-v0.2.md` before forwarding. Endpoint security state remains governed by `0005-session-security-v0.1.md`; native forwarding cannot relax pin, cookie, AEAD, replay, binding, or budget checks. Strict local session handoff is deferred; the v0.1 launcher therefore rejects local delivery rather than claiming it.

## 4. Error and observability contract

Native internal reason tags are externally reported only as `E-BUDGET` (budget), `E-RESIDUAL` (manifest/isolation/teardown), or the applicable session registry category. Frame drops are deterministic and do not emit error frames. Telemetry is bounded counters by this finite category plus descriptor high-water marks; it never logs packet plaintext, raw MAC/LOC/IP values, pins, cookies, or keys.
