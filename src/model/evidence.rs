use serde::{Deserialize, Serialize};

use super::SensorProvenance;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceKind {
    StateReadback,
    IntrusionAssessment,
}

impl EvidenceKind {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::StateReadback => "state-readback",
            Self::IntrusionAssessment => "intrusion-assessment",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ObservedState {
    Connected,
    Isolated,
    Revoked,
    Indeterminate,
}

impl ObservedState {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::Connected => "connected",
            Self::Isolated => "isolated",
            Self::Revoked => "revoked",
            Self::Indeterminate => "indeterminate",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "kebab-case")]
pub enum EvidenceAssertion {
    State(ObservedState),
    CompromiseDetected,
    NoCompromiseObserved,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceV1 {
    pub schema: String,
    pub observation_id: String,
    pub sensor_id: String,
    pub security_domain: String,
    pub deployment_id: String,
    pub resource_uri: String,
    pub command_id: Option<String>,
    pub kind: EvidenceKind,
    pub assertion: EvidenceAssertion,
    pub resource_version: Option<String>,
    pub fence: Option<u64>,
    pub provenance: SensorProvenance,
    pub observed_at_ms: i64,
    pub expires_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedEvidenceV1 {
    pub evidence: EvidenceV1,
    pub key_id: String,
    pub algorithm: String,
    pub signature: String,
}
