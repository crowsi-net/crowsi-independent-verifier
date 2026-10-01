use std::error::Error;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crowsi_independent_verifier::{
    EvidenceAssertion, EvidenceKind, EvidenceLedger, EvidenceV1, ExpectedReadback,
    IndependentReport, IndependentVerifier, ObservedState, ReadbackReportEmitter, ReadbackState,
    SensorCapability, SensorProvenance, SensorTrust, SignedReadbackReportV1, TrustStore,
    TrustedReportKey,
};
use serde::Serialize;

use crate::sample_signing::{SampleReportSigner, SampleSensorSigner};

#[derive(Serialize)]
struct Sample {
    schema: &'static str,
    external_actions: bool,
    verified: IndependentReport<ReadbackState>,
    unknown: IndependentReport<ReadbackState>,
    signed: SignedReadbackReportV1,
}

pub(crate) fn run() -> Result<(), Box<dyn Error>> {
    let first = SampleSensorSigner::new("sensor-a-key", "sensor-a", 11);
    let second = SampleSensorSigner::new("sensor-b-key", "sensor-b", 12);
    let mut registry = TrustStore::new();
    register(
        &mut registry,
        &first,
        "host-plane",
        SensorProvenance::HostAgent,
    )?;
    register(
        &mut registry,
        &second,
        "network-plane",
        SensorProvenance::NetworkProbe,
    )?;
    let verifier = IndependentVerifier::new(EvidenceLedger::open_in_memory()?, registry, 1_000);
    let expectation = expectation();
    let evidence = vec![
        first.sign(observation(
            "obs-a",
            "sensor-a",
            SensorProvenance::HostAgent,
        )),
        second.sign(observation(
            "obs-b",
            "sensor-b",
            SensorProvenance::NetworkProbe,
        )),
    ];
    let report_signer = Arc::new(SampleReportSigner::new());
    let report_key = TrustedReportKey::new("report.sample.1", report_signer.verifying_key())?;
    let emitter = ReadbackReportEmitter::new(report_signer, report_key)?;
    let signed = verifier.verify_signed_readback(&expectation, &evidence, &emitter, 30_000)?;
    let report = Sample {
        schema: "crowsi.verifier-conformance-sample.v1",
        external_actions: false,
        verified: verifier.verify_readback(&expectation, &evidence)?,
        unknown: verifier.verify_readback(&expectation, &[])?,
        signed,
    };
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn register(
    registry: &mut TrustStore,
    signer: &SampleSensorSigner,
    group: &str,
    provenance: SensorProvenance,
) -> crowsi_independent_verifier::Result<()> {
    registry.register(SensorTrust {
        key_id: signer.key_id().into(),
        sensor_id: signer.sensor_id().into(),
        verifying_key: signer.verifying_key(),
        independence_group: group.into(),
        provenance,
        capabilities: vec![SensorCapability::Readback],
        security_domains: vec!["domain:sample".into()],
        deployments: vec!["deployment.sample.1".into()],
        resources: vec!["host://sample/firewall".into()],
    })
}

fn expectation() -> ExpectedReadback {
    ExpectedReadback {
        command_id: "cmd-sample".into(),
        security_domain: "domain:sample".into(),
        deployment_id: "deployment.sample.1".into(),
        resource_uri: "host://sample/firewall".into(),
        expected_state: ObservedState::Isolated,
        expected_resource_version: "rv:crowsi-enforcer-host-firewall:7".into(),
        minimum_fence: 7,
        required_quorum: 2,
        max_age_ms: 5_000,
    }
}

fn observation(id: &str, sensor: &str, provenance: SensorProvenance) -> EvidenceV1 {
    let now = now_ms();
    EvidenceV1 {
        schema: "crowsi.sensor-evidence.v1".into(),
        observation_id: id.into(),
        sensor_id: sensor.into(),
        security_domain: "domain:sample".into(),
        deployment_id: "deployment.sample.1".into(),
        resource_uri: "host://sample/firewall".into(),
        command_id: Some("cmd-sample".into()),
        kind: EvidenceKind::StateReadback,
        assertion: EvidenceAssertion::State(ObservedState::Isolated),
        resource_version: Some("rv:crowsi-enforcer-host-firewall:7".into()),
        fence: Some(7),
        provenance,
        observed_at_ms: now - 100,
        expires_at_ms: now + 5_000,
    }
}

fn now_ms() -> i64 {
    let value = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after epoch")
        .as_millis();
    i64::try_from(value).expect("system time fits i64")
}
