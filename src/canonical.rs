use sha2::{Digest, Sha256};

use crate::{EvidenceAssertion, EvidenceV1};

impl EvidenceV1 {
    /// Returns the stable length-prefixed sensor signing payload.
    #[must_use]
    pub fn signing_payload(&self) -> Vec<u8> {
        bytes(self)
    }

    /// Returns the lowercase SHA-256 digest of the signing payload.
    #[must_use]
    pub fn payload_digest(&self) -> String {
        digest(self)
    }
}

pub(crate) fn bytes(value: &EvidenceV1) -> Vec<u8> {
    let mut output = b"crowsi.sensor-evidence.v1\0".to_vec();
    for field in [
        value.schema.as_str(),
        value.observation_id.as_str(),
        value.sensor_id.as_str(),
        value.security_domain.as_str(),
        value.deployment_id.as_str(),
        value.resource_uri.as_str(),
        value.command_id.as_deref().unwrap_or(""),
        value.kind.code(),
        assertion(&value.assertion),
        value.provenance.code(),
    ] {
        push(&mut output, field.as_bytes());
    }
    push_optional(&mut output, value.resource_version.as_deref());
    output.extend_from_slice(&value.fence.unwrap_or_default().to_be_bytes());
    output.extend_from_slice(&value.observed_at_ms.to_be_bytes());
    output.extend_from_slice(&value.expires_at_ms.to_be_bytes());
    output
}

pub(crate) fn digest(value: &EvidenceV1) -> String {
    let hash = Sha256::digest(bytes(value));
    let mut encoded = String::with_capacity(71);
    encoded.push_str("sha256:");
    for byte in hash {
        use std::fmt::Write as _;
        write!(encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

fn assertion(value: &EvidenceAssertion) -> &'static str {
    match value {
        EvidenceAssertion::State(state) => state.code(),
        EvidenceAssertion::CompromiseDetected => "compromise-detected",
        EvidenceAssertion::NoCompromiseObserved => "no-compromise-observed",
    }
}

fn push(output: &mut Vec<u8>, value: &[u8]) {
    let length = u32::try_from(value.len()).expect("validated fields fit in u32");
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
}

fn push_optional(output: &mut Vec<u8>, value: Option<&str>) {
    output.push(u8::from(value.is_some()));
    push(output, value.unwrap_or_default().as_bytes());
}
