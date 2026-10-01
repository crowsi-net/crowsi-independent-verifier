use crate::{Result, SignedReadbackReportV1};

use super::{canonical_uri, identifier, invalid};

impl SignedReadbackReportV1 {
    /// Validates the closed signed read-back report and canonical digest.
    ///
    /// # Errors
    ///
    /// Rejects malformed context, evidence linkage, expiry, or signature shape.
    pub fn validate_contract(&self) -> Result<()> {
        signed_report(self)
    }
}

pub(crate) fn signed_report(value: &SignedReadbackReportV1) -> Result<()> {
    let mut sorted = value.report.accepted_evidence_digests.clone();
    sorted.sort();
    sorted.dedup();
    let ttl = value
        .expires_at_ms
        .checked_sub(value.report.evaluated_at_ms);
    let verified_counts = value.report.state != crate::ReadbackState::Verified
        || (value.report.independent_groups >= usize::from(value.required_quorum)
            && value.report.accepted_evidence >= usize::from(value.required_quorum));
    let valid = value.schema == "crowsi.signed-readback-report.v1"
        && value.report.schema == "crowsi.readback-report.v1"
        && identifier(&value.command_id)
        && identifier(&value.security_domain)
        && identifier(&value.deployment_id)
        && canonical_uri(&value.resource_uri)
        && identifier(&value.expected_resource_version)
        && value.minimum_fence > 0
        && value.required_quorum >= 2
        && ttl.is_some_and(|duration| (1..=60_000).contains(&duration))
        && value.report.accepted_evidence_digests.len() <= 64
        && value.report.accepted_evidence_digests.len() <= value.report.accepted_evidence
        && (value.report.accepted_evidence == 0 || !sorted.is_empty())
        && identifier(&value.report.reason_code)
        && verified_counts
        && sorted == value.report.accepted_evidence_digests
        && sorted.iter().all(|entry| digest(entry))
        && identifier(&value.signed.key_id)
        && value.signed.algorithm == "Ed25519"
        && digest(&value.signed.digest)
        && signature(&value.signed.signature)
        && value.signed.digest == value.payload_digest();
    if valid {
        Ok(())
    } else {
        invalid("signed readback report")
    }
}

fn digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn signature(value: &str) -> bool {
    value.len() == 86
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte))
}
