mod report;

pub(crate) use report::signed_report;

use crate::{
    EvidenceAssertion, EvidenceKind, EvidenceV1, ExpectedReadback, IntrusionExpectation, Result,
    VerifierError,
};

impl EvidenceV1 {
    /// Validates the closed sensor-evidence contract before external signing.
    ///
    /// # Errors
    ///
    /// Rejects malformed identity, binding, state, version, fence, or time.
    pub fn validate_contract(&self) -> Result<()> {
        evidence(self)
    }
}

pub(crate) fn evidence(value: &EvidenceV1) -> Result<()> {
    if value.schema != "crowsi.sensor-evidence.v1"
        || value.expires_at_ms <= value.observed_at_ms
        || !identifier(&value.observation_id)
        || !identifier(&value.sensor_id)
        || !identifier(&value.security_domain)
        || !identifier(&value.deployment_id)
        || !canonical_uri(&value.resource_uri)
    {
        return invalid("evidence envelope");
    }
    match (&value.kind, &value.assertion) {
        (EvidenceKind::StateReadback, EvidenceAssertion::State(_))
            if value.command_id.as_deref().is_some_and(identifier)
                && value.resource_version.as_deref().is_some_and(identifier)
                && value.fence.is_some_and(|entry| entry > 0) =>
        {
            Ok(())
        }
        (
            EvidenceKind::IntrusionAssessment,
            EvidenceAssertion::CompromiseDetected | EvidenceAssertion::NoCompromiseObserved,
        ) if value.command_id.is_none()
            && value.resource_version.is_none()
            && value.fence.is_none() =>
        {
            Ok(())
        }
        _ => invalid("evidence kind binding"),
    }
}

pub(crate) fn readback(value: &ExpectedReadback) -> Result<()> {
    if identifier(&value.command_id)
        && identifier(&value.security_domain)
        && identifier(&value.deployment_id)
        && canonical_uri(&value.resource_uri)
        && identifier(&value.expected_resource_version)
        && value.minimum_fence > 0
        && value.required_quorum >= 2
        && value.max_age_ms > 0
    {
        Ok(())
    } else {
        invalid("readback expectation")
    }
}

pub(crate) fn intrusion(value: &IntrusionExpectation) -> Result<()> {
    if identifier(&value.security_domain)
        && identifier(&value.deployment_id)
        && canonical_uri(&value.resource_uri)
        && value.required_clear_quorum >= 2
        && value.max_age_ms > 0
    {
        Ok(())
    } else {
        invalid("intrusion expectation")
    }
}

pub(crate) fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

pub(crate) fn canonical_uri(value: &str) -> bool {
    if !identifier(value)
        || value.bytes().any(|byte| b"%?#\\@".contains(&byte))
        || value.chars().any(char::is_uppercase)
    {
        return false;
    }
    let Some((scheme, remainder)) = value.split_once("://") else {
        return false;
    };
    if scheme.is_empty()
        || !scheme.starts_with(|character: char| character.is_ascii_lowercase())
        || !scheme.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"+.-".contains(&byte)
        })
    {
        return false;
    }
    let mut segments = remainder.split('/');
    let Some(authority) = segments.next() else {
        return false;
    };
    !authority.is_empty()
        && segments.clone().next().is_some()
        && valid_uri_part(authority)
        && segments.all(|segment| {
            !segment.is_empty() && !matches!(segment, "." | "..") && valid_uri_part(segment)
        })
}

fn valid_uri_part(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"-._:~".contains(&byte))
}

pub(super) fn invalid<T>(field: &str) -> Result<T> {
    Err(VerifierError::Validation(field.into()))
}
