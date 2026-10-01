use std::collections::BTreeSet;

use crate::{
    EvidenceAssertion, EvidenceKind, IndependentReport, IntrusionExpectation, IntrusionState,
    Result, SensorCapability, SignedEvidenceV1, validation,
};

use super::IndependentVerifier;

impl IndependentVerifier {
    /// Evaluates intrusion findings and independently corroborated clear evidence.
    ///
    /// # Errors
    ///
    /// Rejects invalid expectations, replay collision, clock rollback, or journal failure.
    pub fn verify_intrusion(
        &self,
        expectation: &IntrusionExpectation,
        evidence: &[SignedEvidenceV1],
    ) -> Result<IndependentReport<IntrusionState>> {
        let now_ms = self.clock.now_ms()?;
        self.ledger.observe_clock(now_ms)?;
        validation::intrusion(expectation)?;
        let (accepted, rejected) = self.accepted(
            evidence,
            EvidenceKind::IntrusionAssessment,
            SensorCapability::IntrusionDetection,
            now_ms,
            expectation.max_age_ms,
            (
                &expectation.security_domain,
                &expectation.deployment_id,
                &expectation.resource_uri,
            ),
        )?;
        let detected = accepted
            .iter()
            .any(|entry| entry.evidence.assertion == EvidenceAssertion::CompromiseDetected);
        let clear_groups = accepted
            .iter()
            .filter(|entry| entry.evidence.assertion == EvidenceAssertion::NoCompromiseObserved)
            .map(|entry| entry.group.clone())
            .collect::<BTreeSet<_>>();
        let quorum = usize::from(expectation.required_clear_quorum);
        let (state, reason) = if detected {
            (IntrusionState::Detected, "trusted-detection")
        } else if clear_groups.len() >= quorum {
            (IntrusionState::Clear, "independent-clear-quorum")
        } else {
            (IntrusionState::Unknown, "insufficient-independent-evidence")
        };
        Ok(IndependentReport {
            schema: "crowsi.intrusion-report.v1".into(),
            state,
            reason_code: reason.into(),
            accepted_evidence: accepted.len(),
            accepted_evidence_digests: evidence_digests(&accepted),
            rejected_evidence: rejected,
            independent_groups: clear_groups.len(),
            evaluated_at_ms: now_ms,
        })
    }
}

fn evidence_digests(values: &[super::authenticate::Accepted]) -> Vec<String> {
    let mut digests = values
        .iter()
        .map(|entry| entry.digest.clone())
        .collect::<Vec<_>>();
    digests.sort();
    digests.dedup();
    digests
}
