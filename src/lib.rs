#![doc = "Independent signed read-back and intrusion verifier for Crowsi."]

mod canonical;
mod canonical_report;
mod clock;
mod error;
mod ledger;
#[cfg(unix)]
mod ledger_file;
mod model;
mod schema;
mod signed_report;
mod trust;
mod validation;
mod verifier;
mod votes;

pub use error::{Result, VerifierError};
pub use ledger::EvidenceLedger;
pub use model::{
    EvidenceAssertion, EvidenceKind, EvidenceV1, ExpectedReadback, IndependentReport,
    IntrusionExpectation, IntrusionState, ObservedState, ReadbackState, ReportSignatureV1,
    SensorCapability, SensorProvenance, SignedEvidenceV1, SignedReadbackReportV1,
};
pub use signed_report::{ReadbackReportEmitter, ReportSigningPort, TrustedReportKey};
pub use trust::{SensorTrust, TrustStore};
pub use verifier::IndependentVerifier;
