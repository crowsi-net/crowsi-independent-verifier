use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use crowsi_independent_verifier::{EvidenceV1, Result, SignedEvidenceV1, VerifierError};
use ed25519_dalek::{Signer as _, SigningKey};

pub struct TestSensorSigner {
    key_id: String,
    sensor_id: String,
    key: SigningKey,
}

impl TestSensorSigner {
    pub fn new(key_id: &str, sensor_id: &str, seed: u8) -> Self {
        Self {
            key_id: key_id.into(),
            sensor_id: sensor_id.into(),
            key: SigningKey::from_bytes(&[seed; 32]),
        }
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn sensor_id(&self) -> &str {
        &self.sensor_id
    }

    pub fn verifying_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    pub fn sign(&self, evidence: EvidenceV1) -> Result<SignedEvidenceV1> {
        evidence.validate_contract()?;
        if evidence.sensor_id != self.sensor_id {
            return Err(VerifierError::Trust);
        }
        let signature = self.key.sign(&evidence.signing_payload());
        Ok(SignedEvidenceV1 {
            evidence,
            key_id: self.key_id.clone(),
            algorithm: "Ed25519".into(),
            signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        })
    }
}
