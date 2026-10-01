use sha2::{Digest, Sha256};

use crate::SignedReadbackReportV1;

impl SignedReadbackReportV1 {
    /// Returns the stable context-bound report signing payload.
    #[must_use]
    pub fn signing_payload(&self) -> Vec<u8> {
        bytes(self)
    }

    /// Returns the lowercase SHA-256 digest of the report signing payload.
    #[must_use]
    pub fn payload_digest(&self) -> String {
        digest(self)
    }
}

fn bytes(value: &SignedReadbackReportV1) -> Vec<u8> {
    let mut output = b"crowsi.signed-readback-report.v1\0".to_vec();
    for field in [
        value.schema.as_str(),
        &value.command_id,
        &value.security_domain,
        &value.deployment_id,
        &value.resource_uri,
        value.expected_state.code(),
        &value.expected_resource_version,
        &value.report.schema,
        value.report.state.code(),
        &value.report.reason_code,
    ] {
        push(&mut output, field.as_bytes());
    }
    number(&mut output, value.minimum_fence);
    number(&mut output, u64::from(value.required_quorum));
    number(&mut output, size(value.report.accepted_evidence));
    number(&mut output, size(value.report.rejected_evidence));
    number(&mut output, size(value.report.independent_groups));
    number(
        &mut output,
        size(value.report.accepted_evidence_digests.len()),
    );
    for digest in &value.report.accepted_evidence_digests {
        push(&mut output, digest.as_bytes());
    }
    output.extend_from_slice(&value.report.evaluated_at_ms.to_be_bytes());
    output.extend_from_slice(&value.expires_at_ms.to_be_bytes());
    output
}

fn digest(value: &SignedReadbackReportV1) -> String {
    let hash = Sha256::digest(bytes(value));
    format!("sha256:{hash:x}")
}

fn push(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&size(value.len()).to_be_bytes());
    output.extend_from_slice(value);
}

fn number(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn size(value: usize) -> u64 {
    u64::try_from(value).expect("supported Rust targets use at most 64-bit usize")
}
