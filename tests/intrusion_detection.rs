mod support;

use crowsi_independent_verifier::{
    IntrusionExpectation, IntrusionState, SensorCapability, SensorProvenance,
};
use support::{intrusion, signer, trust, verifier};

fn expectation(quorum: u16) -> IntrusionExpectation {
    IntrusionExpectation {
        security_domain: "domain:personal".into(),
        deployment_id: "deployment.personal.1".into(),
        resource_uri: "host://device-a/firewall".into(),
        required_clear_quorum: quorum,
        max_age_ms: 5_000,
    }
}

#[test]
fn one_trusted_detection_is_immediately_visible() {
    let ids = signer("ids-key", "ids-a", 21);
    let registry = trust(&[(
        &ids,
        "network-ids",
        SensorProvenance::NetworkIds,
        vec![SensorCapability::IntrusionDetection],
    )]);
    let verifier = verifier(registry);
    let finding = ids
        .sign(intrusion(
            "finding",
            "ids-a",
            SensorProvenance::NetworkIds,
            true,
        ))
        .unwrap();

    assert_eq!(
        verifier
            .verify_intrusion(&expectation(2), &[finding])
            .unwrap()
            .state,
        IntrusionState::Detected
    );
}

#[test]
fn clear_requires_fresh_independent_quorum() {
    let host = signer("host-key", "host-ids", 22);
    let network = signer("network-key", "network-ids", 23);
    let registry = trust(&[
        (
            &host,
            "host-ids",
            SensorProvenance::HostAgent,
            vec![SensorCapability::IntrusionDetection],
        ),
        (
            &network,
            "network-ids",
            SensorProvenance::NetworkIds,
            vec![SensorCapability::IntrusionDetection],
        ),
    ]);
    let verifier = verifier(registry);
    let evidence = vec![
        host.sign(intrusion(
            "clear-a",
            "host-ids",
            SensorProvenance::HostAgent,
            false,
        ))
        .unwrap(),
        network
            .sign(intrusion(
                "clear-b",
                "network-ids",
                SensorProvenance::NetworkIds,
                false,
            ))
            .unwrap(),
    ];

    assert_eq!(
        verifier
            .verify_intrusion(&expectation(2), &evidence)
            .unwrap()
            .state,
        IntrusionState::Clear
    );
}

#[test]
fn absent_ids_connection_is_unknown_never_clear() {
    assert_eq!(
        verifier(trust(&[]))
            .verify_intrusion(&expectation(2), &[])
            .unwrap()
            .state,
        IntrusionState::Unknown
    );
}
