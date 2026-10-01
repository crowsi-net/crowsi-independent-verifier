use std::time::{SystemTime, UNIX_EPOCH};

use crate::{Result, VerifierError};

pub(crate) trait TrustedClock: Send + Sync {
    fn now_ms(&self) -> Result<i64>;
}

pub(crate) struct SystemTrustedClock;

impl TrustedClock for SystemTrustedClock {
    fn now_ms(&self) -> Result<i64> {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| VerifierError::Clock)?
            .as_millis();
        i64::try_from(millis).map_err(|_| VerifierError::Clock)
    }
}

#[cfg(debug_assertions)]
pub(crate) struct FixedTrustedClock(pub(crate) i64);

#[cfg(debug_assertions)]
impl TrustedClock for FixedTrustedClock {
    fn now_ms(&self) -> Result<i64> {
        Ok(self.0)
    }
}
