use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use crowsi_independent_verifier::{ReportSigningPort, Result, VerifierError};
use ed25519_dalek::{Signer as _, SigningKey};

pub struct TestReportSigner {
    key_id: String,
    key: SigningKey,
}

impl TestReportSigner {
    pub fn new(key_id: &str, seed: u8) -> Self {
        Self {
            key_id: key_id.into(),
            key: SigningKey::from_bytes(&[seed; 32]),
        }
    }

    pub fn verifying_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }
}

impl ReportSigningPort for TestReportSigner {
    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn sign_digest(&self, digest: &str) -> Result<String> {
        let bytes = digest_bytes(digest)?;
        Ok(URL_SAFE_NO_PAD.encode(self.key.sign(&bytes).to_bytes()))
    }
}

fn digest_bytes(value: &str) -> Result<[u8; 32]> {
    let hex = value
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
    Ok(bytes)
}
