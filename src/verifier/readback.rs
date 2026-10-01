use crate::{
    EvidenceKind, ExpectedReadback, IndependentReport, ReadbackState, Result, SensorCapability,
    SignedEvidenceV1, SignedReadbackReportV1, validation, votes,
};

use super::IndependentVerifier;

impl IndependentVerifier {
    /// Evaluates and externally signs a context-bound read-back report.
    ///
    /// # Errors
    ///
    /// Rejects invalid evidence, clock, signing, or trust state.
    pub fn verify_signed_readback(
        &self,
        expectation: &ExpectedReadback,
        evidence: &[SignedEvidenceV1],
        emitter: &crate::ReadbackReportEmitter,
        ttl_ms: i64,
    ) -> Result<SignedReadbackReportV1> {
        if self
            .trust
            .conflicts_signing_role(emitter.key_id(), emitter.verifying_key())
        {
            return Err(crate::VerifierError::Trust);
        }
        let report = self.verify_readback(expectation, evidence)?;
        emitter.emit(expectation, report, ttl_ms)
    }

    /// Evaluates exact command state from independently signed observations.
    ///
    /// # Errors
    ///
    /// Rejects invalid expectations, replay collision, clock rollback, or journal failure.
    pub fn verify_readback(
        &self,
        expectation: &ExpectedReadback,
        evidence: &[SignedEvidenceV1],
    ) -> Result<IndependentReport<ReadbackState>> {
        let now_ms = self.clock.now_ms()?;
        self.ledger.observe_clock(now_ms)?;
        validation::readback(expectation)?;
        let (accepted, rejected) = self.accepted(
            evidence,
            EvidenceKind::StateReadback,
            SensorCapability::Readback,
            now_ms,
            expectation.max_age_ms,
            (
                &expectation.security_domain,
                &expectation.deployment_id,
                &expectation.resource_uri,
            ),
        )?;
        let accepted_count = accepted.len();
        let command_bound = accepted
            .into_iter()
            .filter(|entry| {
                entry.evidence.command_id.as_deref() == Some(expectation.command_id.as_str())
            })
            .collect::<Vec<_>>();
        let vote_input = command_bound
            .iter()
            .map(|entry| (entry.evidence.clone(), entry.group.clone()))
            .collect::<Vec<_>>();
        let votes = votes::readback(expectation, &vote_input);
        let (matching, contradicting) = votes::counts(&votes);
        let quorum = usize::from(expectation.required_quorum);
        let (state, reason) = if contradicting >= quorum {
            (ReadbackState::Contradicted, "contradictory-quorum")
        } else if matching >= quorum && contradicting == 0 {
            (ReadbackState::Verified, "independent-quorum")
        } else {
            (ReadbackState::Unknown, "insufficient-independent-evidence")
        };
        Ok(IndependentReport {
            schema: "crowsi.readback-report.v1".into(),
            state,
            reason_code: reason.into(),
            accepted_evidence: command_bound.len(),
            accepted_evidence_digests: evidence_digests(&command_bound),
            rejected_evidence: rejected + accepted_count - command_bound.len(),
            independent_groups: votes.len(),
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
