mod support;

use crowsi_independent_verifier::{
    EvidenceLedger, ExpectedReadback, IndependentVerifier, ObservedState, ReadbackState,
    SensorCapability, SensorProvenance, TrustStore,
};
use support::{NOW, readback, signer, trust};

#[test]
fn signed_evidence_journal_survives_restart_idempotently() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("evidence.sqlite3");
    let sensor = signer("sensor-key", "sensor-a", 41);
    let expected = ExpectedReadback {
        command_id: "cmd-isolate".into(),
        security_domain: "domain:personal".into(),
        deployment_id: "deployment.personal.1".into(),
        resource_uri: "host://device-a/firewall".into(),
        expected_state: ObservedState::Isolated,
        expected_resource_version: "rv:crowsi-enforcer-host-firewall:9".into(),
        minimum_fence: 9,
        required_quorum: 2,
        max_age_ms: 5_000,
    };
    let signed = sensor
        .sign(readback(
            "durable",
            "sensor-a",
            SensorProvenance::HostAgent,
            ObservedState::Isolated,
        ))
        .unwrap();
    let registry = || {
        trust(&[(
            &sensor,
            "host-plane",
            SensorProvenance::HostAgent,
            vec![SensorCapability::Readback],
        )])
    };

    let first = IndependentVerifier::new_for_test(
        EvidenceLedger::open_for_test(&path).unwrap(),
        registry(),
        1_000,
        NOW,
    );
    assert_eq!(
        first
            .verify_readback(&expected, std::slice::from_ref(&signed))
            .unwrap()
            .state,
        ReadbackState::Unknown
    );
    drop(first);
    let second = IndependentVerifier::new_for_test(
        EvidenceLedger::open_for_test(&path).unwrap(),
        registry(),
        1_000,
        NOW + 1,
    );
    assert_eq!(
        second.verify_readback(&expected, &[signed]).unwrap().state,
        ReadbackState::Unknown
    );
}

#[test]
fn verifier_clock_watermark_rejects_restart_rollback() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("clock.sqlite3");
    let first = IndependentVerifier::new_for_test(
        EvidenceLedger::open_for_test(&path).unwrap(),
        TrustStore::new(),
        1_000,
        NOW,
    );
    assert!(first.verify_readback(&empty_expected(), &[]).is_ok());
    drop(first);
    let restarted = IndependentVerifier::new_for_test(
        EvidenceLedger::open_for_test(&path).unwrap(),
        TrustStore::new(),
        1_000,
        NOW - 1,
    );
    assert!(matches!(
        restarted.verify_readback(&empty_expected(), &[]),
        Err(crowsi_independent_verifier::VerifierError::TrustedClockRollback)
    ));
}

fn empty_expected() -> ExpectedReadback {
    ExpectedReadback {
        command_id: "cmd-clock".into(),
        security_domain: "domain:personal".into(),
        deployment_id: "deployment.personal.1".into(),
        resource_uri: "host://device-a/firewall".into(),
        expected_state: ObservedState::Isolated,
        expected_resource_version: "etag-clock".into(),
        minimum_fence: 1,
        required_quorum: 2,
        max_age_ms: 5_000,
    }
}

#[test]
fn secure_production_journal_rejects_an_exposed_parent() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let absolute = std::fs::canonicalize(directory.path())
        .unwrap()
        .join("evidence.sqlite3");
    assert!(EvidenceLedger::open_secure(&absolute).is_err());
}
