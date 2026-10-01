use std::fs::{self, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use rusqlite::{Connection, OpenFlags};

use crate::{Result, VerifierError};

pub(crate) fn open(path: &Path) -> Result<Connection> {
    let parent = secure_parent(path)?;
    if !path.exists() {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|_| VerifierError::LedgerIntegrity)?;
    }
    let before = secure_file(path, &parent)?;
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_NOFOLLOW
        | OpenFlags::SQLITE_OPEN_PRIVATE_CACHE;
    let connection = Connection::open_with_flags(path, flags)?;
    let after = secure_file(path, &parent)?;
    if (before.dev(), before.ino()) != (after.dev(), after.ino()) {
        return Err(VerifierError::LedgerIntegrity);
    }
    Ok(connection)
}

fn secure_parent(path: &Path) -> Result<fs::Metadata> {
    if !path.is_absolute() || path.file_name().is_none() {
        return Err(VerifierError::LedgerIntegrity);
    }
    let parent = path.parent().ok_or(VerifierError::LedgerIntegrity)?;
    let canonical = fs::canonicalize(parent).map_err(|_| VerifierError::LedgerIntegrity)?;
    let metadata = fs::symlink_metadata(parent).map_err(|_| VerifierError::LedgerIntegrity)?;
    if canonical != parent
        || !metadata.is_dir()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.uid() != effective_uid()?
    {
        return Err(VerifierError::LedgerIntegrity);
    }
    Ok(metadata)
}

fn secure_file(path: &Path, parent: &fs::Metadata) -> Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path).map_err(|_| VerifierError::LedgerIntegrity)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.uid() != parent.uid()
    {
        return Err(VerifierError::LedgerIntegrity);
    }
    Ok(metadata)
}

fn effective_uid() -> Result<u32> {
    let status =
        fs::read_to_string("/proc/self/status").map_err(|_| VerifierError::LedgerIntegrity)?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|fields| fields.split_whitespace().nth(1))
        .and_then(|value| value.parse().ok())
        .ok_or(VerifierError::LedgerIntegrity)
}
