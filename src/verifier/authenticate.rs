use crate::{
    EvidenceKind, EvidenceV1, Result, SensorCapability, SignedEvidenceV1, canonical, validation,
};

use super::IndependentVerifier;

pub(crate) struct Accepted {
    pub(crate) evidence: EvidenceV1,
    pub(crate) group: String,
    pub(crate) digest: String,
}

impl IndependentVerifier {
    pub(crate) fn accepted(
        &self,
        signed_values: &[SignedEvidenceV1],
        kind: EvidenceKind,
        capability: SensorCapability,
        now_ms: i64,
        max_age_ms: i64,
        binding: (&str, &str, &str),
    ) -> Result<(Vec<Accepted>, usize)> {
        let mut ordered = signed_values.iter().collect::<Vec<_>>();
        ordered.sort_by_key(|signed| signed.evidence.observed_at_ms);
        let mut accepted = Vec::new();
        let mut rejected = 0;
        for signed in ordered {
            let evidence = &signed.evidence;
            let fresh = evidence.observed_at_ms <= now_ms.saturating_add(self.max_future_skew_ms)
                && evidence.expires_at_ms > now_ms
                && now_ms.saturating_sub(evidence.observed_at_ms) <= max_age_ms;
            let bound = evidence.kind == kind
                && evidence.security_domain == binding.0
                && evidence.deployment_id == binding.1
                && evidence.resource_uri == binding.2;
            if validation::evidence(evidence).is_err() || !fresh || !bound {
                rejected += 1;
                continue;
            }
            let Some(sensor) = self.trust.authenticate(signed, capability) else {
                rejected += 1;
                continue;
            };
            let digest = canonical::digest(evidence);
            self.ledger.record(
                &evidence.observation_id,
                &digest,
                &serde_json::to_string(signed)?,
                &evidence.sensor_id,
                evidence.observed_at_ms,
                now_ms,
            )?;
            accepted.push(Accepted {
                evidence: evidence.clone(),
                group: sensor.independence_group.clone(),
                digest,
            });
        }
        Ok((accepted, rejected))
    }
}
