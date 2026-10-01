mod support;

use crowsi_independent_verifier::{
    ExpectedReadback, ObservedState, ReadbackState, SensorCapability, SensorProvenance,
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
fn two_independent_fresh_signed_sources_verify_isolation() {
    let first = signer("sensor-a-key", "sensor-a", 11);
    let second = signer("sensor-b-key", "sensor-b", 12);
    let registry = trust(&[
        (
            &first,
            "host-plane",
            SensorProvenance::HostAgent,
            vec![SensorCapability::Readback],
        ),
        (
            &second,
            "network-plane",
            SensorProvenance::NetworkProbe,
            vec![SensorCapability::Readback],
        ),
    ]);
    let verifier = verifier(registry);
    let evidence = vec![
        first
            .sign(readback(
                "obs-a",
                "sensor-a",
                SensorProvenance::HostAgent,
                ObservedState::Isolated,
            ))
            .unwrap(),
        second
            .sign(readback(
                "obs-b",
                "sensor-b",
                SensorProvenance::NetworkProbe,
                ObservedState::Isolated,
            ))
            .unwrap(),
    ];

    let report = verifier.verify_readback(&expected(), &evidence).unwrap();
    assert_eq!(report.state, ReadbackState::Verified);
    assert_eq!(report.independent_groups, 2);
}

#[test]
fn same_independence_group_never_satisfies_quorum() {
    let first = signer("sensor-a-key", "sensor-a", 11);
    let second = signer("sensor-b-key", "sensor-b", 12);
    let registry = trust(&[
        (
            &first,
            "shared-plane",
            SensorProvenance::HostAgent,
            vec![SensorCapability::Readback],
        ),
        (
            &second,
            "shared-plane",
            SensorProvenance::NetworkProbe,
            vec![SensorCapability::Readback],
        ),
    ]);
    let verifier = verifier(registry);
    let evidence = vec![
        first
            .sign(readback(
                "obs-a",
                "sensor-a",
                SensorProvenance::HostAgent,
                ObservedState::Isolated,
            ))
            .unwrap(),
        second
            .sign(readback(
                "obs-b",
                "sensor-b",
                SensorProvenance::NetworkProbe,
                ObservedState::Isolated,
            ))
            .unwrap(),
    ];

    assert_eq!(
        verifier
            .verify_readback(&expected(), &evidence)
            .unwrap()
            .state,
        ReadbackState::Unknown
    );
}

#[test]
fn no_connection_or_evidence_is_explicitly_unknown() {
    let report = verifier(trust(&[]))
        .verify_readback(&expected(), &[])
        .unwrap();
    assert_eq!(report.state, ReadbackState::Unknown);
    assert_eq!(report.reason_code, "insufficient-independent-evidence");
}
