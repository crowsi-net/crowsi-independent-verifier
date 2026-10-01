mod support;

use crowsi_independent_verifier::{
    ExpectedReadback, ObservedState, ReadbackState, SensorCapability, SensorProvenance,
    SensorTrust, TrustStore, VerifierError,
};
use support::{readback, signer, trust, verifier};

fn expected() -> ExpectedReadback {
    ExpectedReadback {
        command_id: "cmd-isolate".into(),
        security_domain: "domain:personal".into(),
        deployment_id: "deployment.personal.1".into(),
        resource_uri: "host://device-a/firewall".into(),
        expected_state: ObservedState::Isolated,
        expected_resource_version: "rv:crowsi-enforcer-host-firewall:9".into(),
        minimum_fence: 9,
        required_quorum: 2,
        max_age_ms: 5_000,
    }
}

#[test]
fn sensor_key_rotation_cannot_change_its_independence_claim() {
    let current = signer("sensor-current", "sensor-a", 31);
    let next = signer("sensor-next", "sensor-a", 32);
    let mut registry = TrustStore::new();
    let policy = |signer: &support::TestSensorSigner, group: &str| SensorTrust {
        key_id: signer.key_id().into(),
        sensor_id: signer.sensor_id().into(),
        verifying_key: signer.verifying_key(),
        independence_group: group.into(),
        provenance: SensorProvenance::HostAgent,
        capabilities: vec![SensorCapability::Readback],
        security_domains: vec!["domain:personal".into()],
        deployments: vec!["deployment.personal.1".into()],
        resources: vec!["host://device-a/firewall".into()],
    };
    registry.register(policy(&current, "host-plane")).unwrap();
    registry.register(policy(&next, "host-plane")).unwrap();
    let attacker = signer("sensor-attacker", "sensor-a", 33);
    assert!(
        registry
            .register(policy(&attacker, "fake-independent-plane"))
            .is_err()
    );
}

#[test]
fn public_key_cannot_be_aliased_to_another_sensor_or_group() {
    let first = signer("sensor-key-a", "sensor-a", 44);
    let mut store = TrustStore::new();
    let policy = |key_id: &str, sensor_id: &str, group: &str| SensorTrust {
        key_id: key_id.into(),
        sensor_id: sensor_id.into(),
        verifying_key: first.verifying_key(),
        independence_group: group.into(),
        provenance: SensorProvenance::HostAgent,
        capabilities: vec![SensorCapability::Readback],
        security_domains: vec!["domain:personal".into()],
        deployments: vec!["deployment.personal.1".into()],
        resources: vec!["host://device-a/firewall".into()],
    };
    store
        .register(policy("sensor-key-a", "sensor-a", "host-plane"))
        .unwrap();
    assert!(
        store
            .register(policy("sensor-key-alias", "sensor-b", "fake-plane"))
            .is_err()
    );
}

#[test]
fn claimed_provenance_and_capability_must_match_registration() {
    let sensor = signer("sensor-key", "sensor-a", 31);
    let registry = trust(&[(
        &sensor,
        "host-plane",
        SensorProvenance::HostAgent,
        vec![SensorCapability::IntrusionDetection],
    )]);
    let verifier = verifier(registry);
    let wrong = sensor
        .sign(readback(
            "wrong",
            "sensor-a",
            SensorProvenance::NetworkProbe,
            ObservedState::Isolated,
        ))
        .unwrap();

    let report = verifier.verify_readback(&expected(), &[wrong]).unwrap();
    assert_eq!(report.state, ReadbackState::Unknown);
    assert_eq!(report.accepted_evidence, 0);
}

#[test]
fn observation_identifier_collision_is_rejected_durably() {
    let sensor = signer("sensor-key", "sensor-a", 31);
    let registry = trust(&[(
        &sensor,
        "host-plane",
        SensorProvenance::HostAgent,
        vec![SensorCapability::Readback],
    )]);
    let verifier = verifier(registry);
    let first = sensor
        .sign(readback(
            "same-id",
            "sensor-a",
            SensorProvenance::HostAgent,
            ObservedState::Isolated,
        ))
        .unwrap();
    assert_eq!(
        verifier
            .verify_readback(&expected(), &[first])
            .unwrap()
            .state,
        ReadbackState::Unknown
    );
    let changed = sensor
        .sign(readback(
            "same-id",
            "sensor-a",
            SensorProvenance::HostAgent,
            ObservedState::Connected,
        ))
        .unwrap();

    assert!(matches!(
        verifier.verify_readback(&expected(), &[changed]),
        Err(VerifierError::ReplayConflict)
    ));
}
