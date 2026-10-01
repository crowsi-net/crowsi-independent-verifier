use serde::{Deserialize, Serialize};

use super::{IndependentReport, ObservedState, ReadbackState};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportSignatureV1 {
    pub algorithm: String,
    pub key_id: String,
    pub digest: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedReadbackReportV1 {
    pub schema: String,
    pub command_id: String,
    pub security_domain: String,
    pub deployment_id: String,
    pub resource_uri: String,
    pub expected_state: ObservedState,
    pub expected_resource_version: String,
    pub minimum_fence: u64,
    pub required_quorum: u16,
    pub report: IndependentReport<ReadbackState>,
    pub expires_at_ms: i64,
    pub signed: ReportSignatureV1,
}
