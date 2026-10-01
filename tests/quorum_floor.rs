mod support;

use crowsi_independent_verifier::{
    ExpectedReadback, IntrusionExpectation, ObservedState, SignedReadbackReportV1, VerifierError,
};
use support::{trust, verifier};

#[test]
fn caller_cannot_reduce_independent_readback_or_clear_quorum_below_two() {
    let verifier = verifier(trust(&[]));
    let readback = ExpectedReadback {
        command_id: "cmd-isolate".into(),
        security_domain: "domain:personal".into(),
        deployment_id: "deployment.personal.1".into(),
        resource_uri: "host://device-a/firewall".into(),
        expected_state: ObservedState::Isolated,
        expected_resource_version: "rv:crowsi-enforcer-host-firewall:9".into(),
        minimum_fence: 9,
        required_quorum: 1,
        max_age_ms: 5_000,
    };
    let intrusion = IntrusionExpectation {
        security_domain: "domain:personal".into(),
        deployment_id: "deployment.personal.1".into(),
        resource_uri: "host://device-a/firewall".into(),
        required_clear_quorum: 1,
        max_age_ms: 5_000,
    };

    assert!(matches!(
        verifier.verify_readback(&readback, &[]),
        Err(VerifierError::Validation(_))
    ));
    assert!(matches!(
        verifier.verify_intrusion(&intrusion, &[]),
        Err(VerifierError::Validation(_))
    ));
}

#[test]
fn signed_report_contract_and_schema_reject_single_group_quorum() {
    let mut report: SignedReadbackReportV1 = serde_json::from_str(include_str!(
        "../fixtures/conformance/v1/signed-readback-report-v1.json"
    ))
    .unwrap();
    report.required_quorum = 1;
    report.signed.digest = report.payload_digest();
    assert!(matches!(
        report.validate_contract(),
        Err(VerifierError::Validation(_))
    ));

    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../schemas/signed-readback-report-v1.schema.json"
    ))
    .unwrap();
    assert_eq!(schema["properties"]["required_quorum"]["minimum"], 2);
}
