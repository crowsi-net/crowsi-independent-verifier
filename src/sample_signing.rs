use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use crowsi_independent_verifier::{
    EvidenceV1, ReportSigningPort, Result, SignedEvidenceV1, VerifierError,
};
use ed25519_dalek::{Signer as _, SigningKey};

pub(crate) struct SampleSensorSigner {
    key_id: String,
    sensor_id: String,
    key: SigningKey,
}

pub(crate) struct SampleReportSigner {
    key: SigningKey,
}

impl SampleSensorSigner {
    pub(crate) fn new(key_id: &str, sensor_id: &str, seed: u8) -> Self {
        Self {
            key_id: key_id.into(),
            sensor_id: sensor_id.into(),
            key: SigningKey::from_bytes(&[seed; 32]),
        }
    }

    pub(crate) fn key_id(&self) -> &str {
        &self.key_id
    }

    pub(crate) fn sensor_id(&self) -> &str {
        &self.sensor_id
    }

    pub(crate) fn verifying_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    pub(crate) fn sign(&self, evidence: EvidenceV1) -> SignedEvidenceV1 {
        let signature = self.key.sign(&evidence.signing_payload());
        SignedEvidenceV1 {
            evidence,
            key_id: self.key_id.clone(),
            algorithm: "Ed25519".into(),
            signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        }
    }
}

impl SampleReportSigner {
    pub(crate) fn new() -> Self {
        Self {
            key: SigningKey::from_bytes(&[13; 32]),
        }
    }

    pub(crate) fn verifying_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }
}

impl ReportSigningPort for SampleReportSigner {
    fn key_id(&self) -> &'static str {
        "report.sample.1"
    }

    fn sign_digest(&self, digest: &str) -> Result<String> {
        let hex = digest
            .strip_prefix("sha256:")
            .ok_or(VerifierError::Signature)?;
        if hex.len() != 64 {
            return Err(VerifierError::Signature);
        }
        let mut bytes = [0_u8; 32];
        for (index, target) in bytes.iter_mut().enumerate() {
            *target = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16)
                .map_err(|_| VerifierError::Signature)?;
        }
        Ok(URL_SAFE_NO_PAD.encode(self.key.sign(&bytes).to_bytes()))
    }
}
