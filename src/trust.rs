use std::collections::BTreeMap;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, VerifyingKey};

use crate::{
    SensorCapability, SensorProvenance, SignedEvidenceV1, VerifierError, canonical, validation,
};

#[derive(Debug, Clone)]
pub struct SensorTrust {
    pub key_id: String,
    pub sensor_id: String,
    pub verifying_key: [u8; 32],
    pub independence_group: String,
    pub provenance: SensorProvenance,
    pub capabilities: Vec<SensorCapability>,
    pub security_domains: Vec<String>,
    pub deployments: Vec<String>,
    pub resources: Vec<String>,
}

struct RegisteredSensor {
    policy: SensorTrust,
    key: VerifyingKey,
}

#[derive(Default)]
pub struct TrustStore {
    entries: BTreeMap<String, RegisteredSensor>,
}

impl TrustStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a pinned sensor key without changing its independence assertion.
    ///
    /// # Errors
    ///
    /// Rejects weak keys, duplicates, malformed scope, and rotation scope drift.
    pub fn register(&mut self, policy: SensorTrust) -> crate::Result<()> {
        if !valid_policy(&policy)
            || self.entries.contains_key(&policy.key_id)
            || self
                .entries
                .values()
                .any(|entry| entry.policy.verifying_key == policy.verifying_key)
            || self.entries.values().any(|entry| {
                entry.policy.sensor_id == policy.sensor_id
                    && !same_sensor_binding(&entry.policy, &policy)
            })
        {
            return Err(VerifierError::Trust);
        }
        let key =
            VerifyingKey::from_bytes(&policy.verifying_key).map_err(|_| VerifierError::Trust)?;
        if key.is_weak() {
            return Err(VerifierError::Trust);
        }
        self.entries
            .insert(policy.key_id.clone(), RegisteredSensor { policy, key });
        Ok(())
    }

    pub(crate) fn authenticate(
        &self,
        signed: &SignedEvidenceV1,
        capability: SensorCapability,
    ) -> Option<&SensorTrust> {
        let registered = self.entries.get(&signed.key_id)?;
        let evidence = &signed.evidence;
        if signed.algorithm != "Ed25519"
            || evidence.sensor_id != registered.policy.sensor_id
            || evidence.provenance != registered.policy.provenance
            || !registered.policy.capabilities.contains(&capability)
            || !registered
                .policy
                .security_domains
                .contains(&evidence.security_domain)
            || !registered
                .policy
                .deployments
                .contains(&evidence.deployment_id)
            || !registered
                .policy
                .resources
                .iter()
                .any(|resource| resource == &evidence.resource_uri)
        {
            return None;
        }
        let bytes = URL_SAFE_NO_PAD.decode(&signed.signature).ok()?;
        let signature = Signature::from_slice(&bytes).ok()?;
        registered
            .key
            .verify_strict(&canonical::bytes(evidence), &signature)
            .ok()?;
        Some(&registered.policy)
    }

    pub(crate) fn conflicts_signing_role(&self, key_id: &str, key: [u8; 32]) -> bool {
        self.entries
            .values()
            .any(|entry| entry.policy.key_id == key_id || entry.policy.verifying_key == key)
    }
}

fn same_sensor_binding(left: &SensorTrust, right: &SensorTrust) -> bool {
    left.sensor_id == right.sensor_id
        && left.independence_group == right.independence_group
        && left.provenance == right.provenance
        && left.capabilities == right.capabilities
        && left.security_domains == right.security_domains
        && left.deployments == right.deployments
        && left.resources == right.resources
}

fn valid_policy(value: &SensorTrust) -> bool {
    validation::identifier(&value.key_id)
        && validation::identifier(&value.sensor_id)
        && validation::identifier(&value.independence_group)
        && !value.capabilities.is_empty()
        && !value.security_domains.is_empty()
        && value
            .security_domains
            .iter()
            .all(|entry| validation::identifier(entry))
        && !value.resources.is_empty()
        && !value.deployments.is_empty()
        && value
            .deployments
            .iter()
            .all(|entry| validation::identifier(entry))
        && value
            .resources
            .iter()
            .all(|entry| validation::canonical_uri(entry))
}
