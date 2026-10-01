use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, VerifyingKey};

use crate::{
    ExpectedReadback, IndependentReport, ReadbackState, ReportSignatureV1, Result,
    SignedReadbackReportV1, VerifierError, validation,
};

pub trait ReportSigningPort: Send + Sync {
    /// Returns the identifier of the protected signing key.
    fn key_id(&self) -> &str;

    /// Signs the 32 bytes represented by a lowercase `sha256:` digest.
    ///
    /// # Errors
    ///
    /// Returns an error when protected signing is unavailable.
    fn sign_digest(&self, digest: &str) -> Result<String>;
}

pub struct ReadbackReportEmitter {
    signer: Arc<dyn ReportSigningPort>,
    trust: TrustedReportKey,
}

pub struct TrustedReportKey {
    key_id: String,
    key: VerifyingKey,
}

impl ReadbackReportEmitter {
    /// Binds an external signer to its separately pinned public key.
    ///
    /// # Errors
    ///
    /// Rejects malformed, mismatched, or weak key configuration.
    pub fn new<S>(signer: Arc<S>, trust: TrustedReportKey) -> Result<Self>
    where
        S: ReportSigningPort + 'static,
    {
        if !validation::identifier(signer.key_id()) || signer.key_id() != trust.key_id {
            return Err(VerifierError::Trust);
        }
        Ok(Self { signer, trust })
    }

    pub(crate) fn emit(
        &self,
        expected: &ExpectedReadback,
        report: IndependentReport<ReadbackState>,
        ttl_ms: i64,
    ) -> Result<SignedReadbackReportV1> {
        let expires_at_ms = report
            .evaluated_at_ms
            .checked_add(ttl_ms)
            .ok_or(VerifierError::Clock)?;
        let mut value = SignedReadbackReportV1 {
            schema: "crowsi.signed-readback-report.v1".into(),
            command_id: expected.command_id.clone(),
            security_domain: expected.security_domain.clone(),
            deployment_id: expected.deployment_id.clone(),
            resource_uri: expected.resource_uri.clone(),
            expected_state: expected.expected_state,
            expected_resource_version: expected.expected_resource_version.clone(),
            minimum_fence: expected.minimum_fence,
            required_quorum: expected.required_quorum,
            report,
            expires_at_ms,
            signed: ReportSignatureV1 {
                algorithm: "Ed25519".into(),
                key_id: self.signer.key_id().into(),
                digest: format!("sha256:{:064x}", 0),
                signature: "a".repeat(86),
            },
        };
        value.signed.digest = value.payload_digest();
        value.validate_contract()?;
        value.signed.signature = self.signer.sign_digest(&value.signed.digest)?;
        self.trust.verify_signature(&value)?;
        Ok(value)
    }

    pub(crate) fn key_id(&self) -> &str {
        &self.trust.key_id
    }

    pub(crate) fn verifying_key(&self) -> [u8; 32] {
        self.trust.key.to_bytes()
    }
}

impl TrustedReportKey {
    /// Pins the verifier report public key.
    ///
    /// # Errors
    ///
    /// Rejects malformed identifiers and invalid or weak Ed25519 keys.
    pub fn new(key_id: &str, bytes: [u8; 32]) -> Result<Self> {
        if !validation::identifier(key_id) {
            return Err(VerifierError::Trust);
        }
        let key = VerifyingKey::from_bytes(&bytes).map_err(|_| VerifierError::Trust)?;
        if key.is_weak() {
            return Err(VerifierError::Trust);
        }
        Ok(Self {
            key_id: key_id.into(),
            key,
        })
    }

    /// Verifies authenticity of the closed context-bound report.
    ///
    /// This method intentionally does not claim freshness. Runtime consumers
    /// must reject `expires_at_ms` using their own durable trusted clock.
    ///
    /// # Errors
    ///
    /// Rejects malformed context, digest, key binding, or signature.
    pub fn verify_signature(&self, value: &SignedReadbackReportV1) -> Result<()> {
        validation::signed_report(value)?;
        if value.signed.key_id != self.key_id {
            return Err(VerifierError::Trust);
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(&value.signed.signature)
            .map_err(|_| VerifierError::Signature)?;
        let signature = Signature::from_slice(&bytes).map_err(|_| VerifierError::Signature)?;
        self.key
            .verify_strict(&digest_bytes(&value.signed.digest)?, &signature)
            .map_err(|_| VerifierError::Signature)
    }
}

fn digest_bytes(value: &str) -> Result<[u8; 32]> {
    let hex = value
        .strip_prefix("sha256:")
        .ok_or(VerifierError::Signature)?;
    let mut bytes = [0_u8; 32];
    if hex.len() != 64 {
        return Err(VerifierError::Signature);
    }
    for (index, target) in bytes.iter_mut().enumerate() {
        *target = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16)
            .map_err(|_| VerifierError::Signature)?;
    }
    Ok(bytes)
}
