mod support;

use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use crowsi_independent_verifier::{
    ExpectedReadback, IndependentVerifier, ObservedState, ReadbackReportEmitter, ReadbackState,
    SensorCapability, SensorProvenance, SignedEvidenceV1, TrustedReportKey,
};
use support::{TestReportSigner, readback, signer, trust, verifier};

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
fn verifier_emits_a_context_bound_externally_signed_report() {
    let (verifier, evidence) = verified_inputs(51, 53, "signed-report");
    let report_signer = Arc::new(TestReportSigner::new("report-key.1", 52));
    let trust = TrustedReportKey::new("report-key.1", report_signer.verifying_key()).unwrap();
    let emitter = ReadbackReportEmitter::new(report_signer, trust).unwrap();
    let signed = verifier
        .verify_signed_readback(&expected(), &evidence, &emitter, 30_000)
        .unwrap();
    let verifier_key = TrustedReportKey::new("report-key.1", emitter_key(52)).unwrap();

    verifier_key.verify_signature(&signed).unwrap();
    assert_eq!(signed.report.state, ReadbackState::Verified);
    assert_eq!(signed.deployment_id, "deployment.personal.1");
    assert_eq!(signed.report.accepted_evidence_digests.len(), 2);
}

#[test]
fn any_context_or_evidence_digest_change_invalidates_the_report() {
    let (mut signed, key) = signed_fixture();
    signed.expected_resource_version = "rv:attacker:10".into();
    assert!(key.verify_signature(&signed).is_err());
    let (mut signed, key) = signed_fixture();
    signed.report.accepted_evidence_digests[0] = format!("sha256:{:064x}", 9);
    assert!(key.verify_signature(&signed).is_err());
    let (mut signed, key) = signed_fixture();
    signed.expires_at_ms += 1;
    assert!(key.verify_signature(&signed).is_err());
}

#[test]
fn released_signed_report_is_generated_and_verified_byte_exact() {
    let (signed, _) = signed_fixture();
    let manifest: serde_json::Value = serde_json::from_str(include_str!(
        "../fixtures/conformance/v1/readback-report-trust-manifest-v1.json"
    ))
    .unwrap();
    let public: [u8; 32] = URL_SAFE_NO_PAD
        .decode(manifest["report_verifier"]["public_key"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let key = TrustedReportKey::new("report-key.1", public).unwrap();

    key.verify_signature(&signed).unwrap();
    assert_eq!(
        format!("{}\n", serde_json::to_string_pretty(&signed).unwrap()),
        include_str!("../fixtures/conformance/v1/signed-readback-report-v1.json")
    );
}

fn signed_fixture() -> (
    crowsi_independent_verifier::SignedReadbackReportV1,
    TrustedReportKey,
) {
    let (verifier, evidence) = verified_inputs(61, 63, "fixture-report");
    let signer = Arc::new(TestReportSigner::new("report-key.1", 62));
    let key = TrustedReportKey::new("report-key.1", signer.verifying_key()).unwrap();
    let emitter = ReadbackReportEmitter::new(signer, key).unwrap();
    let signed_report = verifier
        .verify_signed_readback(&expected(), &evidence, &emitter, 30_000)
        .unwrap();
    (
        signed_report,
        TrustedReportKey::new("report-key.1", emitter_key(62)).unwrap(),
    )
}

fn verified_inputs(
    host_seed: u8,
    network_seed: u8,
    id: &str,
) -> (IndependentVerifier, Vec<SignedEvidenceV1>) {
    let host = signer("sensor-key", "sensor-a", host_seed);
    let network = signer("network-key", "sensor-b", network_seed);
    let verifier = verifier(trust(&[
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
    ]));
    let evidence = vec![
        host.sign(readback(
            id,
            "sensor-a",
            SensorProvenance::HostAgent,
            ObservedState::Isolated,
        ))
        .unwrap(),
        network
            .sign(readback(
                &format!("{id}-network"),
                "sensor-b",
                SensorProvenance::NetworkProbe,
                ObservedState::Isolated,
            ))
            .unwrap(),
    ];
    (verifier, evidence)
}

fn emitter_key(seed: u8) -> [u8; 32] {
    TestReportSigner::new("report-key.1", seed).verifying_key()
}
