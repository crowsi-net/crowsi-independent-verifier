use thiserror::Error;

pub type Result<T> = std::result::Result<T, VerifierError>;

#[derive(Debug, Error)]
pub enum VerifierError {
    #[error("evidence validation failed: {0}")]
    Validation(String),
    #[error("sensor trust registration is invalid")]
    Trust,
    #[error("report signature is invalid")]
    Signature,
    #[error("observation identifier was reused for different evidence")]
    ReplayConflict,
    #[error("sensor observation clock moved backwards")]
    ClockRollback,
    #[error("trusted verifier clock is unavailable")]
    Clock,
    #[error("trusted verifier clock moved behind its durable watermark")]
    TrustedClockRollback,
    #[error("evidence journal storage failed")]
    Storage(#[from] rusqlite::Error),
    #[error("evidence serialization failed")]
    Serialization(#[from] serde_json::Error),
    #[error("evidence journal identity, path, or schema is invalid")]
    LedgerIntegrity,
}
