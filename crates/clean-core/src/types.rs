use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// A single file or directory captured during a scan.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FileRecord {
    /// Stable within one scan session (sequential).
    pub id: u64,
    /// Full path. Extended-length aware on Windows.
    pub path: String,
    pub name: String,
    /// Lowercased extension without the dot, if any (files only).
    pub ext: Option<String>,
    /// Size in bytes (0 for directories; directory totals are computed in reports).
    pub size: u64,
    /// Unix seconds; 0 when the filesystem does not report the value.
    pub created: i64,
    pub modified: i64,
    pub accessed: i64,
    pub is_dir: bool,
    /// Raw platform attribute bits (Windows: FILE_ATTRIBUTE_*; 0 elsewhere).
    pub attributes: u32,
}

/// A path the scanner could not read (access denied, broken entry, ...).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkippedPath {
    pub path: String,
    pub reason: String,
}

pub fn systime_to_unix(t: std::io::Result<SystemTime>) -> i64 {
    match t {
        Ok(st) => match st.duration_since(UNIX_EPOCH) {
            Ok(d) => d.as_secs() as i64,
            Err(e) => -(e.duration().as_secs() as i64),
        },
        Err(_) => 0,
    }
}
