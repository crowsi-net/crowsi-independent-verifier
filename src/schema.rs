use rusqlite::Connection;

use crate::{Result, VerifierError};

const APPLICATION_ID: i64 = 0x4352_4956;

pub(crate) fn migrate(connection: &Connection) -> Result<()> {
    let application_id: i64 =
        connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
    let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if !matches!(application_id, 0 | APPLICATION_ID) || !matches!(version, 0 | 2) {
        return Err(VerifierError::LedgerIntegrity);
    }
    connection.execute_batch(
        "BEGIN IMMEDIATE;
         CREATE TABLE IF NOT EXISTS signed_evidence (
           observation_id TEXT PRIMARY KEY,
           evidence_digest TEXT NOT NULL,
           artifact_json TEXT NOT NULL,
           sensor_id TEXT NOT NULL,
           observed_at_ms INTEGER NOT NULL,
           recorded_at_ms INTEGER NOT NULL
         ) STRICT;
         CREATE TABLE IF NOT EXISTS sensor_watermarks (
           sensor_id TEXT PRIMARY KEY,
           observed_at_ms INTEGER NOT NULL
         ) STRICT;
         CREATE TABLE IF NOT EXISTS trusted_clock_watermark (
           singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
           observed_at_ms INTEGER NOT NULL
         ) STRICT;
         PRAGMA application_id = 1129466198;
         PRAGMA user_version = 2;
         COMMIT;",
    )?;
    verify(connection)
}

fn verify(connection: &Connection) -> Result<()> {
    let expected = [
        (
            "sensor_watermarks",
            "CREATE TABLE sensor_watermarks (
              sensor_id TEXT PRIMARY KEY,
              observed_at_ms INTEGER NOT NULL
            ) STRICT",
        ),
        (
            "signed_evidence",
            "CREATE TABLE signed_evidence (
              observation_id TEXT PRIMARY KEY,
              evidence_digest TEXT NOT NULL,
              artifact_json TEXT NOT NULL,
              sensor_id TEXT NOT NULL,
              observed_at_ms INTEGER NOT NULL,
              recorded_at_ms INTEGER NOT NULL
            ) STRICT",
        ),
        (
            "trusted_clock_watermark",
            "CREATE TABLE trusted_clock_watermark (
              singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
              observed_at_ms INTEGER NOT NULL
            ) STRICT",
        ),
    ];
    let mut statement = connection.prepare(
        "SELECT name, sql FROM sqlite_schema
         WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%'
         ORDER BY name",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    let actual = rows.collect::<std::result::Result<Vec<_>, _>>()?;
    if actual.len() != expected.len()
        || actual
            .iter()
            .zip(expected)
            .any(|((name, sql), (expected_name, expected_sql))| {
                name != expected_name || normalized(sql) != normalized(expected_sql)
            })
    {
        return Err(VerifierError::LedgerIntegrity);
    }
    Ok(())
}

fn normalized(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use rusqlite::Connection;

    use super::migrate;
    use crate::VerifierError;

    #[test]
    fn precreated_weakened_schema_is_rejected() {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE signed_evidence (
                   observation_id TEXT PRIMARY KEY,
                   evidence_digest TEXT,
                   artifact_json TEXT,
                   sensor_id TEXT,
                   observed_at_ms INTEGER,
                   recorded_at_ms INTEGER
                 ) STRICT;
                 CREATE TABLE sensor_watermarks (
                   sensor_id TEXT PRIMARY KEY,
                   observed_at_ms INTEGER
                 ) STRICT;
                 PRAGMA application_id = 1129466198;
                 PRAGMA user_version = 1;",
            )
            .unwrap();
        assert!(matches!(
            migrate(&connection),
            Err(VerifierError::LedgerIntegrity)
        ));
    }
}
