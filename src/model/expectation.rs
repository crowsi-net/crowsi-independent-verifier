use serde::{Deserialize, Serialize};

use super::ObservedState;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedReadback {
    pub command_id: String,
    pub security_domain: String,
    pub deployment_id: String,
    pub resource_uri: String,
    pub expected_state: ObservedState,
    pub expected_resource_version: String,
    pub minimum_fence: u64,
    pub required_quorum: u16,
    pub max_age_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntrusionExpectation {
    pub security_domain: String,
    pub deployment_id: String,
    pub resource_uri: String,
    pub required_clear_quorum: u16,
    pub max_age_ms: i64,
}
