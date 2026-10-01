mod support;

use crowsi_independent_verifier::{
    ExpectedReadback, ObservedState, ReadbackState, SensorCapability, SensorProvenance,
};
use support::{NOW, readback, signer, trust, verifier};

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
fn forged_stale_or_future_evidence_cannot_promote_state() {
    let trusted = signer("sensor-key", "sensor-a", 14);
    let attacker = signer("sensor-key", "sensor-a", 15);
    let registry = trust(&[(
        &trusted,
        "host-plane",
        SensorProvenance::HostAgent,
        vec![SensorCapability::Readback],
    )]);
    let verifier = verifier(registry);

    let forged = attacker
        .sign(readback(
            "forged",
            "sensor-a",
            SensorProvenance::HostAgent,
            ObservedState::Isolated,
        ))
        .unwrap();
    let mut stale_value = readback(
        "stale",
        "sensor-a",
        SensorProvenance::HostAgent,
        ObservedState::Isolated,
    );
    stale_value.observed_at_ms = NOW - 6_000;
    let stale = trusted.sign(stale_value).unwrap();
    let mut future_value = readback(
        "future",
        "sensor-a",
        SensorProvenance::HostAgent,
        ObservedState::Isolated,
    );
    future_value.observed_at_ms = NOW + 1_001;
    let future = trusted.sign(future_value).unwrap();

    let report = verifier
        .verify_readback(&expected(), &[forged, stale, future])
        .unwrap();
    assert_eq!(report.state, ReadbackState::Unknown);
    assert_eq!(report.accepted_evidence, 0);
}

#[test]
fn contradictory_quorum_is_reported_not_hidden() {
    let host = signer("host-key", "sensor-a", 14);
    let network = signer("network-key", "sensor-b", 16);
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
    let verifier = verifier(registry);
    let evidence = [
        host.sign(readback(
            "connected-host",
            "sensor-a",
            SensorProvenance::HostAgent,
            ObservedState::Connected,
        ))
        .unwrap(),
        network
            .sign(readback(
                "connected-network",
                "sensor-b",
                SensorProvenance::NetworkProbe,
                ObservedState::Connected,
            ))
            .unwrap(),
    ];

    assert_eq!(
        verifier
            .verify_readback(&expected(), &evidence)
            .unwrap()
            .state,
        ReadbackState::Contradicted
    );
}

#[test]
fn textual_uri_prefix_is_not_an_authorization_scope() {
    let sensor = signer("sensor-key", "sensor-a", 14);
    let registry = trust(&[(
        &sensor,
        "host-plane",
        SensorProvenance::HostAgent,
        vec![SensorCapability::Readback],
    )]);
    let verifier = verifier(registry);
    let mut sibling = readback(
        "sibling",
        "sensor-a",
        SensorProvenance::HostAgent,
        ObservedState::Isolated,
    );
    sibling.resource_uri = "host://device-a/firewall-shadow".into();
    let signed = sensor.sign(sibling).unwrap();
    let report = verifier.verify_readback(&expected(), &[signed]).unwrap();
    assert_eq!(report.state, ReadbackState::Unknown);
    assert_eq!(report.accepted_evidence, 0);
}
