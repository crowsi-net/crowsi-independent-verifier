use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use crate::{Result, VerifierError, schema};

pub struct EvidenceLedger {
    connection: Mutex<Connection>,
}

impl EvidenceLedger {
    /// Opens a process-local conformance evidence journal.
    ///
    /// # Errors
    ///
    /// Returns an error if `SQLite` initialization or schema validation fails.
    pub fn open_in_memory() -> Result<Self> {
        Self::finish_open(Connection::open_in_memory()?)
    }

    #[cfg(debug_assertions)]
    /// Opens a durable test journal without production path restrictions.
    ///
    /// # Errors
    ///
    /// Returns an error if `SQLite` initialization or schema validation fails.
    pub fn open_for_test(path: &Path) -> Result<Self> {
        Self::finish_open(Connection::open(path)?)
    }

    #[cfg(unix)]
    /// Opens a production journal in an owner-only canonical directory.
    ///
    /// # Errors
    ///
    /// Rejects unsafe paths, ownership, permissions, identity changes, or schema.
    pub fn open_secure(path: &Path) -> Result<Self> {
        Self::finish_open(crate::ledger_file::open(path)?)
    }

    fn finish_open(connection: Connection) -> Result<Self> {
        connection.pragma_update(None, "trusted_schema", "OFF")?;
        connection.pragma_update(None, "journal_mode", "DELETE")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        schema::migrate(&connection)?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    pub(crate) fn record(
        &self,
        observation_id: &str,
        digest: &str,
        artifact_json: &str,
        sensor_id: &str,
        observed_at_ms: i64,
        recorded_at_ms: i64,
    ) -> Result<()> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing = transaction
            .query_row(
                "SELECT evidence_digest FROM signed_evidence WHERE observation_id = ?1",
                [observation_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if let Some(stored) = existing {
            if stored != digest {
                return Err(VerifierError::ReplayConflict);
            }
            transaction.commit()?;
            return Ok(());
        }
        let watermark = transaction
            .query_row(
                "SELECT observed_at_ms FROM sensor_watermarks WHERE sensor_id = ?1",
                [sensor_id],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        if watermark.is_some_and(|value| observed_at_ms < value) {
            return Err(VerifierError::ClockRollback);
        }
        transaction.execute(
            "INSERT INTO signed_evidence (
               observation_id, evidence_digest, artifact_json, sensor_id,
               observed_at_ms, recorded_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                observation_id,
                digest,
                artifact_json,
                sensor_id,
                observed_at_ms,
                recorded_at_ms
            ],
        )?;
        transaction.execute(
            "INSERT INTO sensor_watermarks (sensor_id, observed_at_ms) VALUES (?1, ?2)
             ON CONFLICT(sensor_id) DO UPDATE SET observed_at_ms = excluded.observed_at_ms",
            params![sensor_id, observed_at_ms],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn observe_clock(&self, now_ms: i64) -> Result<()> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let previous = transaction
            .query_row(
                "SELECT observed_at_ms FROM trusted_clock_watermark WHERE singleton = 1",
                [],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        if previous.is_some_and(|value| now_ms < value) {
            return Err(VerifierError::TrustedClockRollback);
        }
        transaction.execute(
            "INSERT INTO trusted_clock_watermark (singleton, observed_at_ms) VALUES (1, ?1)
             ON CONFLICT(singleton) DO UPDATE SET observed_at_ms = excluded.observed_at_ms
             WHERE excluded.observed_at_ms > trusted_clock_watermark.observed_at_ms",
            [now_ms],
        )?;
        transaction.commit()?;
        Ok(())
    }

    fn lock(&self) -> Result<MutexGuard<'_, Connection>> {
        self.connection
            .lock()
            .map_err(|_| VerifierError::LedgerIntegrity)
    }
}
