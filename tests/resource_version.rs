mod support;

use crowsi_independent_verifier::{
    ExpectedReadback, IndependentVerifier, ObservedState, ReadbackState, SensorCapability,
    SensorProvenance,
};
use support::{TestSensorSigner, readback, signer, trust, verifier};

fn expected(version: &str) -> ExpectedReadback {
    ExpectedReadback {
        command_id: "cmd-isolate".into(),
        security_domain: "domain:personal".into(),
        deployment_id: "deployment.personal.1".into(),
        resource_uri: "host://device-a/firewall".into(),
        expected_state: ObservedState::Isolated,
        expected_resource_version: version.into(),
        minimum_fence: 9,
        required_quorum: 2,
        max_age_ms: 5_000,
    }
}

fn setup(seed: u8) -> (TestSensorSigner, TestSensorSigner, IndependentVerifier) {
    let host = signer("sensor-key", "sensor-a", seed);
    let network = signer("network-key", "sensor-b", seed + 1);
    let registry = trust(&[
        (
            &host,
            "host-plane",
            SensorProvenance::HostAgent,
            vec![SensorCapability::Readback],
        ),
        (
            &network,
            "network-plane",
            SensorProvenance::NetworkProbe,
            vec![SensorCapability::Readback],
        ),
    ]);
    (host, network, verifier(registry))
}

#[test]
fn stale_fence_or_different_version_cannot_verify_a_new_command() {
    let (sensor, _, verifier) = setup(17);
    let mut stale = readback(
        "stale-cas",
        "sensor-a",
        SensorProvenance::HostAgent,
        ObservedState::Isolated,
    );
    stale.resource_version = Some("rv:crowsi-enforcer-host-firewall:8".into());
    stale.fence = Some(8);
    let signed = sensor.sign(stale).unwrap();
    let report = verifier
        .verify_readback(&expected("rv:crowsi-enforcer-host-firewall:9"), &[signed])
        .unwrap();
    assert_eq!(report.state, ReadbackState::Unknown);
}

#[test]
fn exact_opaque_resource_version_is_required() {
    let (sensor, _, verifier) = setup(18);
    let mut different = readback(
        "different-version",
        "sensor-a",
        SensorProvenance::HostAgent,
        ObservedState::Isolated,
    );
    different.resource_version = Some("rv:crowsi-enforcer-host-firewall:10".into());
    let signed = sensor.sign(different).unwrap();
    let report = verifier
        .verify_readback(&expected("rv:crowsi-enforcer-host-firewall:9"), &[signed])
        .unwrap();
    assert_eq!(report.state, ReadbackState::Unknown);
}

#[test]
fn opaque_resource_version_is_covered_by_the_sensor_signature() {
    let (sensor, _, verifier) = setup(20);
    let mut signed = sensor
        .sign(readback(
            "tampered-version",
            "sensor-a",
            SensorProvenance::HostAgent,
            ObservedState::Isolated,
        ))
        .unwrap();
    signed.evidence.resource_version = Some("rv:attacker:10".into());
    let report = verifier
        .verify_readback(&expected("rv:attacker:10"), &[signed])
        .unwrap();
    assert_eq!(report.state, ReadbackState::Unknown);
    assert_eq!(report.accepted_evidence, 0);
}

#[test]
fn opaque_resource_version_enforces_the_closed_length_boundary() {
    let (sensor, network, verifier) = setup(19);
    let boundary = "v".repeat(256);
    let mut evidence = readback(
        "boundary-version",
        "sensor-a",
        SensorProvenance::HostAgent,
        ObservedState::Isolated,
    );
    evidence.resource_version = Some(boundary.clone());
    let signed = sensor.sign(evidence.clone()).unwrap();
    let mut network_evidence = evidence;
    network_evidence.observation_id = "boundary-version-network".into();
    network_evidence.sensor_id = "sensor-b".into();
    network_evidence.provenance = SensorProvenance::NetworkProbe;
    let network_signed = network.sign(network_evidence).unwrap();
    let report = verifier
        .verify_readback(&expected(&boundary), &[signed, network_signed])
        .unwrap();
    assert_eq!(report.state, ReadbackState::Verified);

    let mut too_long = readback(
        "too-long-version",
        "sensor-a",
        SensorProvenance::HostAgent,
        ObservedState::Isolated,
    );
    too_long.resource_version = Some("v".repeat(257));
    assert!(sensor.sign(too_long).is_err());
    assert!(
        verifier
            .verify_readback(&expected(&"v".repeat(257)), &[])
            .is_err()
    );
}
