use r8d::{validate_manifest_json, ManifestError};
use serde_json::{json, Value};

fn manifest() -> Value {
    json!({
        "local_locs": [[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]],
        "interfaces": [{
            "descriptor_id": 7,
            "interface_name": "lab0",
            "allowed_source_macs": [[0, 1, 2, 3, 4, 5]],
            "local_delivery": true,
            "transit": true
        }, {
            "descriptor_id": 8,
            "interface_name": "lab1",
            "allowed_source_macs": [[0, 1, 2, 3, 4, 6]],
            "local_delivery": false,
            "transit": true
        }],
        "routes": [{
            "destination_prefix": {"network": [32, 1, 13, 184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], "prefix_length": 32},
            "egress_descriptor_id": 7,
            "next_hop_mac": [0, 1, 2, 3, 4, 7]
        }, {
            "destination_prefix": {"network": [32, 1, 13, 184, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], "prefix_length": 40},
            "egress_descriptor_id": 8,
            "next_hop_mac": [0, 1, 2, 3, 4, 8]
        }]
    })
}

fn parse(value: Value) -> Result<r8d::NativeManifest, ManifestError> {
    validate_manifest_json(value.to_string().as_bytes(), ["lab0", "lab1"])
}

#[test]
fn accepts_complete_manifest_and_exposes_only_safe_accessors() {
    let parsed = parse(manifest()).unwrap();
    assert!(parsed.is_local_loc(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]));
    assert_eq!(parsed.interface(7).unwrap().interface_name(), "lab0");
    assert!(parsed
        .interface(7)
        .unwrap()
        .permits_source_mac(&[0, 1, 2, 3, 4, 5]));
    assert!(parsed.interface(7).unwrap().local_delivery());
    assert!(!parsed.interface(8).unwrap().local_delivery());
    assert_eq!(parsed.routes().len(), 2);
}

#[test]
fn longest_prefix_match_is_deterministic_and_has_no_default() {
    let parsed = parse(manifest()).unwrap();
    assert_eq!(
        parsed
            .route_for(&[32, 1, 13, 184, 1, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
            .unwrap()
            .egress_descriptor_id(),
        8
    );
    assert_eq!(
        parsed
            .route_for(&[32, 1, 13, 184, 9, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
            .unwrap()
            .egress_descriptor_id(),
        7
    );
    assert!(parsed.route_for(&[0; 16]).is_none());
}

#[test]
fn rejects_schema_unknown_duplicate_and_trailing_records() {
    for value in [
        "{\"local_locs\":[],\"interfaces\":[],\"routes\":[],\"extra\":true}".to_owned(),
        "{\"local_locs\":[],\"local_locs\":[],\"interfaces\":[],\"routes\":[]}".to_owned(),
        "{\"local_locs\":[],\"interfaces\":[],\"routes\":[]} null".to_owned(),
        "{\"local_locs\":[],\"interfaces\":[],\"routes\":[{\"destination_prefix\":{\"network\":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],\"prefix_length\":1},\"egress_descriptor_id\":7,\"egress_descriptor_id\":7,\"next_hop_mac\":[0,1,2,3,4,5]}]}".to_owned(),
    ] {
        assert!(validate_manifest_json(value.as_bytes(), ["lab0"]).is_err());
    }
}

#[test]
fn rejects_every_semantic_manifest_invariant() {
    let mut cases = Vec::new();

    let mut value = manifest();
    value["local_locs"]
        .as_array_mut()
        .unwrap()
        .push(json!([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]));
    cases.push(value);

    let mut value = manifest();
    value["interfaces"][0]["descriptor_id"] = json!(0);
    cases.push(value);
    let mut value = manifest();
    value["interfaces"][1]["descriptor_id"] = json!(7);
    cases.push(value);
    let mut value = manifest();
    value["interfaces"][0]["interface_name"] = json!("");
    cases.push(value);
    let mut value = manifest();
    value["interfaces"][0]["interface_name"] = json!("unlisted");
    cases.push(value);
    let mut value = manifest();
    value["interfaces"][1]["interface_name"] = json!("lab0");
    cases.push(value);
    let mut value = manifest();
    value["interfaces"][0]["allowed_source_macs"] = json!([]);
    cases.push(value);
    let mut value = manifest();
    value["interfaces"][0]["allowed_source_macs"] = json!([[0, 1, 2, 3, 4, 5], [0, 1, 2, 3, 4, 5]]);
    cases.push(value);
    let mut value = manifest();
    value["interfaces"][0]["allowed_source_macs"] = json!([[255, 255, 255, 255, 255, 255]]);
    cases.push(value);
    let mut value = manifest();
    value["routes"][0]["destination_prefix"]["prefix_length"] = json!(0);
    cases.push(value);
    let mut value = manifest();
    value["routes"][0]["destination_prefix"]["prefix_length"] = json!(129);
    cases.push(value);
    let mut value = manifest();
    value["routes"][0]["destination_prefix"]["prefix_length"] = json!(255);
    cases.push(value);
    let mut value = manifest();
    value["routes"][0]["destination_prefix"]["network"][15] = json!(1);
    cases.push(value);
    let mut value = manifest();
    value["routes"][0]["egress_descriptor_id"] = json!(9);
    cases.push(value);
    let mut value = manifest();
    value["routes"][0]["next_hop_mac"] = json!([255, 255, 255, 255, 255, 255]);
    cases.push(value);
    let mut value = manifest();
    value["routes"][1]["destination_prefix"] = value["routes"][0]["destination_prefix"].clone();
    cases.push(value);

    for value in cases {
        assert_eq!(parse(value), Err(ManifestError::Invariant));
    }
}

#[test]
fn rejects_missing_fields_and_wrong_array_lengths() {
    let mut value = manifest();
    value["interfaces"][0]
        .as_object_mut()
        .unwrap()
        .remove("transit");
    assert_eq!(parse(value), Err(ManifestError::Schema));

    let mut value = manifest();
    value["local_locs"][0] = Value::Array(vec![json!(0); 15]);
    assert_eq!(parse(value), Err(ManifestError::Schema));

    let mut value = manifest();
    value["routes"][0]["next_hop_mac"] = json!([0, 1, 2, 3, 4]);
    assert_eq!(parse(value), Err(ManifestError::Schema));
}

#[test]
fn errors_never_include_manifest_identifiers() {
    let error = validate_manifest_json(
        br#"{"local_locs":[],"interfaces":[{"descriptor_id":1,"interface_name":"sensitive-interface","allowed_source_macs":[],"local_delivery":true,"transit":true}],"routes":[]}"#,
        ["sensitive-interface"],
    )
    .unwrap_err();
    assert!(!format!("{error:?}").contains("sensitive-interface"));
    assert!(!error.to_string().contains("sensitive-interface"));
}
