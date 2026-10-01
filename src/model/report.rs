use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReadbackState {
    Verified,
    Contradicted,
    Unknown,
}

impl ReadbackState {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Contradicted => "contradicted",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IntrusionState {
    Detected,
    Clear,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IndependentReport<T> {
    pub schema: String,
    pub state: T,
    pub reason_code: String,
    pub accepted_evidence: usize,
    pub accepted_evidence_digests: Vec<String>,
    pub rejected_evidence: usize,
    pub independent_groups: usize,
    pub evaluated_at_ms: i64,
}
