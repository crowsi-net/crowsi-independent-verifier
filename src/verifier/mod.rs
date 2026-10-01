mod authenticate;
mod intrusion;
mod readback;

use crate::{EvidenceLedger, TrustStore};
use std::sync::Arc;

pub struct IndependentVerifier {
    pub(crate) ledger: EvidenceLedger,
    pub(crate) trust: TrustStore,
    pub(crate) max_future_skew_ms: i64,
    pub(crate) clock: Arc<dyn crate::clock::TrustedClock>,
}

impl IndependentVerifier {
    #[must_use]
    pub fn new(ledger: EvidenceLedger, trust: TrustStore, max_future_skew_ms: i64) -> Self {
        Self {
            ledger,
            trust,
            max_future_skew_ms: max_future_skew_ms.max(0),
            clock: Arc::new(crate::clock::SystemTrustedClock),
        }
    }

    #[cfg(debug_assertions)]
    #[must_use]
    pub fn new_for_test(
        ledger: EvidenceLedger,
        trust: TrustStore,
        max_future_skew_ms: i64,
        now_ms: i64,
    ) -> Self {
        Self {
            ledger,
            trust,
            max_future_skew_ms: max_future_skew_ms.max(0),
            clock: Arc::new(crate::clock::FixedTrustedClock(now_ms)),
        }
    }
}
