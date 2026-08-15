use serde::Deserialize;
use std::collections::BTreeSet;
use std::fmt;

/// A finite, redacted manifest validation failure category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifestError {
    Syntax,
    Schema,
    Invariant,
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("manifest rejected")
    }
}

impl std::error::Error for ManifestError {}

/// A validated interface record. Its fields are intentionally immutable.
#[derive(Clone, Eq, PartialEq)]
pub struct Interface {
    descriptor_id: u32,
    interface_name: String,
    allowed_source_macs: Vec<[u8; 6]>,
    local_delivery: bool,
    transit: bool,
}

impl Interface {
    pub fn descriptor_id(&self) -> u32 {
        self.descriptor_id
    }

    pub fn interface_name(&self) -> &str {
        &self.interface_name
    }

    pub fn allowed_source_macs(&self) -> &[[u8; 6]] {
        &self.allowed_source_macs
    }

    pub fn local_delivery(&self) -> bool {
        self.local_delivery
    }

    pub fn transit(&self) -> bool {
        self.transit
    }

    pub fn permits_source_mac(&self, mac: &[u8; 6]) -> bool {
        self.allowed_source_macs.contains(mac)
    }
}
impl fmt::Debug for Interface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Interface").finish_non_exhaustive()
    }
}

/// A validated static route. Its fields are intentionally immutable.
#[derive(Clone, Eq, PartialEq)]
pub struct Route {
    destination_network: [u8; 16],
    prefix_length: u8,
    egress_descriptor_id: u32,
    next_hop_mac: [u8; 6],
}

impl Route {
    pub fn destination_network(&self) -> &[u8; 16] {
        &self.destination_network
    }

    pub fn prefix_length(&self) -> u8 {
        self.prefix_length
    }

    pub fn egress_descriptor_id(&self) -> u32 {
        self.egress_descriptor_id
    }

    pub fn next_hop_mac(&self) -> &[u8; 6] {
        &self.next_hop_mac
    }

    fn matches(&self, loc: &[u8; 16]) -> bool {
        prefix_matches(&self.destination_network, loc, self.prefix_length)
    }
}
impl fmt::Debug for Route {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Route").finish_non_exhaustive()
    }
}

/// Fully validated, process-lifetime native manifest.
#[derive(Clone, Eq, PartialEq)]
pub struct NativeManifest {
    local_locs: Vec<[u8; 16]>,
    interfaces: Vec<Interface>,
    routes: Vec<Route>,
}

impl NativeManifest {
    pub fn local_locs(&self) -> &[[u8; 16]] {
        &self.local_locs
    }

    pub fn interfaces(&self) -> &[Interface] {
        &self.interfaces
    }

    pub fn routes(&self) -> &[Route] {
        &self.routes
    }

    pub fn is_local_loc(&self, loc: &[u8; 16]) -> bool {
        self.local_locs.contains(loc)
    }

    pub fn interface(&self, descriptor_id: u32) -> Option<&Interface> {
        self.interfaces
            .iter()
            .find(|interface| interface.descriptor_id == descriptor_id)
    }

    /// Selects the unique longest-prefix route, without route learning or fallback.
    pub fn route_for(&self, loc: &[u8; 16]) -> Option<&Route> {
        self.routes
            .iter()
            .filter(|route| route.matches(loc))
            .max_by_key(|route| route.prefix_length)
    }
}
impl fmt::Debug for NativeManifest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeManifest")
            .field("local_loc_count", &self.local_locs.len())
            .field("interface_count", &self.interfaces.len())
            .field("route_count", &self.routes.len())
            .finish()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawManifest {
    local_locs: Vec<[u8; 16]>,
    interfaces: Vec<RawInterface>,
    routes: Vec<RawRoute>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawInterface {
    descriptor_id: u32,
    interface_name: String,
    allowed_source_macs: Vec<[u8; 6]>,
    local_delivery: bool,
    transit: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRoute {
    destination_prefix: RawPrefix,
    egress_descriptor_id: u32,
    next_hop_mac: [u8; 6],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPrefix {
    network: [u8; 16],
    prefix_length: u8,
}

/// Parses and validates a complete JSON native manifest against the startup interface allowlist.
///
/// Serde's struct deserializer rejects duplicate fields; `from_slice` also requires that the
/// complete input is one JSON value, so unknown fields and trailing records are rejected.
pub fn validate_manifest_json<I, S>(
    bytes: &[u8],
    allowlist: I,
) -> Result<NativeManifest, ManifestError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let raw: RawManifest = serde_json::from_slice(bytes).map_err(classify_json_error)?;
    let allowed_names: BTreeSet<String> = allowlist
        .into_iter()
        .map(|name| name.as_ref().to_owned())
        .collect();
    let mut local_locs = BTreeSet::new();
    let mut descriptor_ids = BTreeSet::new();
    let mut interface_names = BTreeSet::new();
    let mut interfaces = Vec::with_capacity(raw.interfaces.len());

    for raw_interface in raw.interfaces {
        if raw_interface.descriptor_id == 0
            || raw_interface.interface_name.is_empty()
            || !allowed_names.contains(raw_interface.interface_name.as_str())
            || !descriptor_ids.insert(raw_interface.descriptor_id)
            || !interface_names.insert(raw_interface.interface_name.clone())
            || raw_interface.allowed_source_macs.is_empty()
        {
            return Err(ManifestError::Invariant);
        }

        let mut source_macs = BTreeSet::new();
        for mac in &raw_interface.allowed_source_macs {
            if is_broadcast(mac) || !source_macs.insert(*mac) {
                return Err(ManifestError::Invariant);
            }
        }

        interfaces.push(Interface {
            descriptor_id: raw_interface.descriptor_id,
            interface_name: raw_interface.interface_name,
            allowed_source_macs: raw_interface.allowed_source_macs,
            local_delivery: raw_interface.local_delivery,
            transit: raw_interface.transit,
        });
    }

    for loc in raw.local_locs {
        if !local_locs.insert(loc) {
            return Err(ManifestError::Invariant);
        }
    }

    let mut routes = Vec::with_capacity(raw.routes.len());
    let mut route_keys = BTreeSet::new();
    for raw_route in raw.routes {
        let prefix = raw_route.destination_prefix;
        if prefix.prefix_length == 0
            || prefix.prefix_length > 128
            || !is_canonical_network(&prefix.network, prefix.prefix_length)
            || raw_route.egress_descriptor_id == 0
            || !descriptor_ids.contains(&raw_route.egress_descriptor_id)
            || is_broadcast(&raw_route.next_hop_mac)
            || !route_keys.insert((prefix.network, prefix.prefix_length))
        {
            return Err(ManifestError::Invariant);
        }
        routes.push(Route {
            destination_network: prefix.network,
            prefix_length: prefix.prefix_length,
            egress_descriptor_id: raw_route.egress_descriptor_id,
            next_hop_mac: raw_route.next_hop_mac,
        });
    }

    Ok(NativeManifest {
        local_locs: local_locs.into_iter().collect(),
        interfaces,
        routes,
    })
}

fn classify_json_error(error: serde_json::Error) -> ManifestError {
    if error.is_syntax() || error.is_eof() {
        ManifestError::Syntax
    } else {
        ManifestError::Schema
    }
}

fn is_broadcast(mac: &[u8; 6]) -> bool {
    *mac == [0xff; 6]
}

fn is_canonical_network(network: &[u8; 16], prefix_length: u8) -> bool {
    let full_bytes = (prefix_length / 8) as usize;
    let remaining_bits = prefix_length % 8;
    if remaining_bits != 0 && network[full_bytes] & ((1u8 << (8 - remaining_bits)) - 1) != 0 {
        return false;
    }
    network[full_bytes + usize::from(remaining_bits != 0)..]
        .iter()
        .all(|byte| *byte == 0)
}

fn prefix_matches(network: &[u8; 16], loc: &[u8; 16], prefix_length: u8) -> bool {
    let full_bytes = (prefix_length / 8) as usize;
    if network[..full_bytes] != loc[..full_bytes] {
        return false;
    }
    let remaining_bits = prefix_length % 8;
    remaining_bits == 0
        || network[full_bytes] >> (8 - remaining_bits) == loc[full_bytes] >> (8 - remaining_bits)
}
