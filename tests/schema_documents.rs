#[test]
fn published_contracts_are_closed_json_schemas() {
    for source in [
        include_str!("../schemas/sensor-evidence-v1.schema.json"),
        include_str!("../schemas/signed-sensor-evidence-v1.schema.json"),
        include_str!("../schemas/readback-report-v1.schema.json"),
        include_str!("../schemas/intrusion-report-v1.schema.json"),
        include_str!("../schemas/signed-readback-report-v1.schema.json"),
        include_str!("../schemas/readback-report-trust-manifest-v1.schema.json"),
    ] {
        let schema: serde_json::Value = serde_json::from_str(source).unwrap();
        assert_eq!(
            schema["$schema"],
            "https://json-schema.org/draft/2020-12/schema"
        );
        assert_eq!(schema["type"], "object");
        assert_eq!(schema["additionalProperties"], false);
        assert!(
            schema["required"]
                .as_array()
                .is_some_and(|value| !value.is_empty())
        );
    }
}

#[test]
fn signed_envelope_rejects_unknown_fields() {
    let source = r#"{
      "evidence": {},
      "key_id": "sensor",
      "algorithm": "Ed25519",
      "signature": "",
      "unexpected": true
    }"#;
    assert!(serde_json::from_str::<crowsi_independent_verifier::SignedEvidenceV1>(source).is_err());
}

#[test]
fn evidence_json_rejects_legacy_numeric_resource_versions() {
    let source = r#"{
      "schema": "crowsi.sensor-evidence.v1",
      "observation_id": "legacy",
      "sensor_id": "sensor-a",
      "security_domain": "domain:personal",
      "deployment_id": "deployment.personal.1",
      "resource_uri": "host://device-a/firewall",
      "command_id": "cmd-isolate",
      "kind": "state-readback",
      "assertion": {"type": "state", "value": "isolated"},
      "resource_version": 9,
      "fence": 9,
      "provenance": "host-agent",
      "observed_at_ms": 1800000000000,
      "expires_at_ms": 1800000005000
    }"#;
    assert!(serde_json::from_str::<crowsi_independent_verifier::EvidenceV1>(source).is_err());
}

#[test]
fn readback_expectation_rejects_the_legacy_minimum_version_field() {
    let source = r#"{
      "command_id": "cmd-isolate",
      "security_domain": "domain:personal",
      "deployment_id": "deployment.personal.1",
      "resource_uri": "host://device-a/firewall",
      "expected_state": "isolated",
      "minimum_resource_version": 9,
      "minimum_fence": 9,
      "required_quorum": 2,
      "max_age_ms": 5000
    }"#;
    assert!(serde_json::from_str::<crowsi_independent_verifier::ExpectedReadback>(source).is_err());
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../schemas/sensor-evidence-v1.schema.json")).unwrap();
    assert_eq!(
        schema["properties"]["resource_version"]["type"][0],
        "string"
    );
    assert_eq!(schema["properties"]["resource_version"]["maxLength"], 256);
}
