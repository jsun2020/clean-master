use crate::error::CoreError;
use crate::scanner::ScanOutcome;
use crate::types::{FileRecord, SkippedPath};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub const SESSION_VERSION: u32 = 1;
pub const DEFAULT_SESSION_FILE: &str = "clean-session.json";

/// Snapshot of one scan; `analyze`, `junk` and `dupes` operate on this.
#[derive(Debug, Serialize, Deserialize)]
pub struct Session {
    pub version: u32,
    pub root: String,
    pub created_unix: i64,
    pub records: Vec<FileRecord>,
    pub skipped: Vec<SkippedPath>,
}

impl Session {
    pub fn from_scan(root: &Path, outcome: ScanOutcome) -> Self {
        Session {
            version: SESSION_VERSION,
            root: root.display().to_string(),
            created_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0),
            records: outcome.records,
            skipped: outcome.skipped,
        }
    }

    pub fn save(&self, path: &Path) -> Result<(), CoreError> {
        let json = serde_json::to_string(self)
            .map_err(|e| CoreError::Session(format!("serialize: {e}")))?;
        std::fs::write(path, json).map_err(|e| CoreError::Io {
            path: path.display().to_string(),
            source: e,
        })
    }

    pub fn load(path: &Path) -> Result<Self, CoreError> {
        let data = std::fs::read_to_string(path).map_err(|e| CoreError::Io {
            path: path.display().to_string(),
            source: e,
        })?;
        let session: Session = serde_json::from_str(&data)
            .map_err(|e| CoreError::Session(format!("parse {}: {e}", path.display())))?;
        if session.version != SESSION_VERSION {
            return Err(CoreError::Session(format!(
                "unsupported session version {} (expected {}); re-run `clean scan`",
                session.version, SESSION_VERSION
            )));
        }
        Ok(session)
    }

    pub fn total_file_bytes(&self) -> u64 {
        self.records.iter().filter(|r| !r.is_dir).map(|r| r.size).sum()
    }

    pub fn file_count(&self) -> usize {
        self.records.iter().filter(|r| !r.is_dir).count()
    }

    pub fn dir_count(&self) -> usize {
        self.records.iter().filter(|r| r.is_dir).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::{ScanBackend, ScanOptions, WalkBackend};

    #[test]
    fn session_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("x.txt"), b"abc").unwrap();
        let outcome = WalkBackend
            .scan(dir.path(), &ScanOptions::default(), &|_| {})
            .unwrap();
        let session = Session::from_scan(dir.path(), outcome);

        let file = dir.path().join("s.json");
        session.save(&file).unwrap();
        let loaded = Session::load(&file).unwrap();

        assert_eq!(loaded.version, SESSION_VERSION);
        assert_eq!(loaded.records, session.records);
        assert_eq!(loaded.file_count(), 1); // s.json is not in records (written after scan)
    }

    #[test]
    fn load_missing_file_errors() {
        assert!(Session::load(Path::new("no-such-session.json")).is_err());
    }
}
