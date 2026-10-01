#![allow(dead_code)]

mod report_signing;
mod sensor_signing;

use crowsi_independent_verifier::{
    EvidenceAssertion, EvidenceKind, EvidenceLedger, EvidenceV1, IndependentVerifier,
    ObservedState, SensorCapability, SensorProvenance, SensorTrust, TrustStore,
};
#[allow(unused_imports)]
pub use report_signing::TestReportSigner;
pub use sensor_signing::TestSensorSigner;

pub const NOW: i64 = 1_800_000_000_000;

pub fn signer(key: &str, sensor: &str, seed: u8) -> TestSensorSigner {
    TestSensorSigner::new(key, sensor, seed)
}

pub fn trust(
    entries: &[(
        &TestSensorSigner,
        &str,
        SensorProvenance,
        Vec<SensorCapability>,
    )],
) -> TrustStore {
    let mut registry = TrustStore::new();
    for (signer, group, provenance, capabilities) in entries {
        registry
            .register(SensorTrust {
                key_id: signer.key_id().into(),
                sensor_id: signer.sensor_id().into(),
                verifying_key: signer.verifying_key(),
                independence_group: (*group).into(),
                provenance: *provenance,
                capabilities: capabilities.clone(),
                security_domains: vec!["domain:personal".into()],
                deployments: vec!["deployment.personal.1".into()],
                resources: vec!["host://device-a/firewall".into()],
            })
            .unwrap();
    }
    registry
}

pub fn verifier(registry: TrustStore) -> IndependentVerifier {
    IndependentVerifier::new_for_test(
        EvidenceLedger::open_in_memory().unwrap(),
        registry,
        1_000,
        NOW,
    )
}

pub fn readback(
    id: &str,
    sensor: &str,
    provenance: SensorProvenance,
    state: ObservedState,
) -> EvidenceV1 {
    EvidenceV1 {
        schema: "crowsi.sensor-evidence.v1".into(),
        observation_id: id.into(),
        sensor_id: sensor.into(),
        security_domain: "domain:personal".into(),
        deployment_id: "deployment.personal.1".into(),
        resource_uri: "host://device-a/firewall".into(),
        command_id: Some("cmd-isolate".into()),
        kind: EvidenceKind::StateReadback,
        assertion: EvidenceAssertion::State(state),
        resource_version: Some("rv:crowsi-enforcer-host-firewall:9".into()),
        fence: Some(9),
        provenance,
        observed_at_ms: NOW - 500,
        expires_at_ms: NOW + 10_000,
    }
}

pub fn intrusion(
    id: &str,
    sensor: &str,
    provenance: SensorProvenance,
    detected: bool,
) -> EvidenceV1 {
    EvidenceV1 {
        schema: "crowsi.sensor-evidence.v1".into(),
        observation_id: id.into(),
        sensor_id: sensor.into(),
        security_domain: "domain:personal".into(),
        deployment_id: "deployment.personal.1".into(),
        resource_uri: "host://device-a/firewall".into(),
        command_id: None,
        kind: EvidenceKind::IntrusionAssessment,
        assertion: if detected {
            EvidenceAssertion::CompromiseDetected
        } else {
            EvidenceAssertion::NoCompromiseObserved
        },
        resource_version: None,
        fence: None,
        provenance,
        observed_at_ms: NOW - 500,
        expires_at_ms: NOW + 10_000,
    }
}
