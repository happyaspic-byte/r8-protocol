# R8 Native Binding v0.1

> Status: normative Gate-0 contract for private, experimental, isolated closed-lab networks only. Native R8 is forbidden on public, third-party, or non-isolated networks.

## 1. Ethernet framing and packet budget

The native carrier is one Ethernet II frame: destination MAC (6 bytes), source MAC (6 bytes), EtherType `0x88B5` (2 bytes), then one complete serialized R8 packet. VLAN tags are outside the R8 packet and reduce the available Ethernet payload. The R8 Version and the EtherType are both required; a frame matching only one is dropped. The frame has no native binding trailer, padding semantic, or fragmentation facility.

The maximum serialized R8 packet and native effective budget are exactly the formulas and limits in `spec/parameters-v0.1.md`: `min(1280, Ethernet_payload_budget_after_VLAN)`. Before serialization, every sender computes the effective budget and subtracts the 48-byte base header plus the selected payload framing, AEAD tag, and applicable mobility or Profile-3 metadata. Oversize packets are rejected locally as `MTU_EXCEEDED`; received declared lengths over budget are dropped. No IP packet may be generated as a fallback.

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

`prefix_length` is 0 through 128, but prefix length zero is invalid: there is no default route. Interface names and descriptor IDs are unique. Every route refers to one declared interface, every next-hop MAC is explicit and non-broadcast, and every local LOC has exactly 16 bytes. A startup validation rejects duplicate equal-prefix routes, overlapping equal-prefix routes, a route missing an egress descriptor, a source-MAC policy with no allowed MAC, or an interface not on the startup allowlist. Manifest reload is out of scope; changing it requires process replacement and fresh validation.

Forwarding selects the matching route with greatest prefix length. Equal-length ambiguity is a startup error, so lookup is single-valued. A lookup miss is `ROUTE_MISS`, not a request for discovery. The daemon never learns routes or neighbors from traffic.

## 3. Receive and forwarding contract

The daemon runs non-root after a narrow launcher opens only manifest-named EtherType-filtered descriptors. The launcher must verify the active isolated namespace/allowlist, no default route, no global address, no bridge or bond attachment, exact EtherType filter, named interfaces only, non-root long-lived UID, no broad `CAP_NET_ADMIN`, no-new-privileges, and immutable filter state where supported. Failure to apply a required check aborts startup. Physical or VLAN isolation is a separately recorded operator attestation naming switch/VLAN/interfaces and confirming no public or third-party attachment.
A kernel-generated zero-prefix entry carrying the exact `RTF_REJECT` bit is an inert reject sentinel, not a usable default route; the launcher may ignore it only after strict field parsing. Any zero-prefix entry without `RTF_REJECT`, or any malformed route-table record, aborts startup.

| State + event | Precondition | Action and mutation | Error | Timer / idempotency | Release |
|---|---|---|---|---|---|
| `STARTING` + manifest load | complete manifest and launcher checks pass | validate records; pre-open only named descriptors; drop privileges/capabilities; enter `RUNNING` | `MANIFEST_INVALID`/`ISOLATION_FAILED` | no retry within process; repeated identical startup is independent | failed startup closes descriptors and erases manifest copy |
| `RUNNING` + Ethernet frame | EtherType, descriptor, source policy, and exact R8 length valid | parse header; local-deliver only when destination LOC is local; otherwise evaluate transit | `FRAME_INVALID`/`SOURCE_SPOOF`/`MALFORMED` | no state allocation; duplicate frames are handled by session replay where applicable | no per-frame release needed |
| `RUNNING` + transit packet | ingress permits transit; hop limit greater than one; deterministic route exists; egress budget fits | decrement hop once; preserve all other packet bytes; send through selected descriptor using manifest next-hop MAC | `TRANSIT_DISABLED`/`HOP_EXCEEDED`/`ROUTE_MISS`/`MTU_EXCEEDED` | no retry or queue created by forwarding; same frame is processed independently | none |
| `RUNNING` + local packet | destination LOC local; interface permits local delivery | hand the exact R8 packet to strict wire/session processing | downstream parse/auth error | no binding state inferred from passive receipt | none |
| `RUNNING` + descriptor/filter/privilege fault | any runtime check detects revoked required invariant | stop receive/transmit and enter `STOPPING` | `ISOLATION_FAILED` | no automatic recovery | close every descriptor and erase process-held sensitive state |
| `STOPPING` + teardown | owned descriptors only | close descriptors; remove only launcher-owned resources; enter `RELEASED` | local `TEARDOWN_FAILED` if cleanup is incomplete | idempotent close | all live references released |

A forwarding implementation is flow-stateless: it retains no route, peer, session, or neighbor information as a consequence of a forwarded packet. It applies `0004-wire-format-v0.2.md` before local delivery. Endpoint security state remains governed by `0005-session-security-v0.1.md`; native forwarding cannot relax pin, cookie, AEAD, replay, binding, or budget checks.

## 4. Error and observability contract

Native internal reason tags are externally reported only as `E-BUDGET` (budget), `E-RESIDUAL` (manifest/isolation/teardown), or the applicable session registry category. Frame drops are deterministic and do not emit error frames. Telemetry is bounded counters by this finite category plus descriptor high-water marks; it never logs packet plaintext, raw MAC/LOC/IP values, pins, cookies, or keys.
