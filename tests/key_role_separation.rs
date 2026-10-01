mod support;

use std::sync::Arc;

use crowsi_independent_verifier::{
    ExpectedReadback, ObservedState, ReadbackReportEmitter, SensorCapability, SensorProvenance,
    TrustedReportKey, VerifierError,
};
use support::{TestReportSigner, signer, trust, verifier};

#[test]
fn sensor_and_report_roles_reject_reused_public_key_material() {
    let sensor = signer("sensor-key", "sensor-a", 81);
    let verifier = verifier(trust(&[(
        &sensor,
        "host-plane",
        SensorProvenance::HostAgent,
        vec![SensorCapability::Readback],
    )]));
    let signer = Arc::new(TestReportSigner::new("report-key", 81));
    let key = TrustedReportKey::new("report-key", signer.verifying_key()).unwrap();
    let emitter = ReadbackReportEmitter::new(signer, key).unwrap();

    assert!(matches!(
        verifier.verify_signed_readback(&expected(), &[], &emitter, 30_000),
        Err(VerifierError::Trust)
    ));
}

#[test]
fn sensor_and_report_roles_reject_reused_key_identifier() {
    let sensor = signer("shared-key", "sensor-a", 82);
    let verifier = verifier(trust(&[(
        &sensor,
        "host-plane",
        SensorProvenance::HostAgent,
        vec![SensorCapability::Readback],
    )]));
    let signer = Arc::new(TestReportSigner::new("shared-key", 83));
    let key = TrustedReportKey::new("shared-key", signer.verifying_key()).unwrap();
    let emitter = ReadbackReportEmitter::new(signer, key).unwrap();

    assert!(matches!(
        verifier.verify_signed_readback(&expected(), &[], &emitter, 30_000),
        Err(VerifierError::Trust)
    ));
}

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
