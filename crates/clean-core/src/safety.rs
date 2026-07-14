//! Safety layer: protected paths, Recycle-Bin deletion, undo manifests.
//! Business rules (prd.md section 7): dry-run default, Recycle Bin first,
//! protected paths untouchable, every apply writes an undo manifest.

use crate::error::CoreError;
use crate::rules::expand_env;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Directories that user-initiated deletions (duplicates) must never touch.
/// Junk rules may whitelist their own base (e.g. C:\Windows\Temp) explicitly.
pub fn protected_roots() -> Vec<PathBuf> {
    ["%WINDIR%", "%ProgramFiles%", "%ProgramFiles(x86)%", "%ProgramData%"]
        .iter()
        .filter_map(|v| expand_env(v))
        .map(PathBuf::from)
        .collect()
}

/// True when `path` may be deleted: not under a protected root, unless it is
/// under one of `allowed_bases` (a junk rule's own documented base).
pub fn deletion_allowed(path: &Path, allowed_bases: &[PathBuf]) -> bool {
    if allowed_bases.iter().any(|b| path.starts_with(b)) {
        return true;
    }
    !protected_roots().iter().any(|root| path.starts_with(root))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
    RecycleBin,
    Permanent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Action {
    pub from: String,
    pub disposition: Disposition,
    pub size: u64,
    pub at_unix: i64,
}

/// Written on every apply; `clean undo` restores from it while the items
/// remain in the Recycle Bin.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ActionManifest {
    pub session_id: String,
    pub actions: Vec<Action>,
}

impl ActionManifest {
    pub fn new() -> Self {
        let id = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        ActionManifest {
            session_id: id.to_string(),
            actions: Vec::new(),
        }
    }

    pub fn file_name(&self) -> String {
        format!("clean-undo-{}.json", self.session_id)
    }

    pub fn save(&self, dir: &Path) -> Result<PathBuf, CoreError> {
        let path = dir.join(self.file_name());
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| CoreError::Session(format!("serialize manifest: {e}")))?;
        std::fs::write(&path, json).map_err(|e| CoreError::Io {
            path: path.display().to_string(),
            source: e,
        })?;
        Ok(path)
    }

    pub fn load(path: &Path) -> Result<Self, CoreError> {
        let data = std::fs::read_to_string(path).map_err(|e| CoreError::Io {
            path: path.display().to_string(),
            source: e,
        })?;
        serde_json::from_str(&data)
            .map_err(|e| CoreError::Session(format!("parse manifest {}: {e}", path.display())))
    }

    /// Most recent clean-undo-*.json in `dir`.
    pub fn latest_in(dir: &Path) -> Option<PathBuf> {
        let mut candidates: Vec<PathBuf> = std::fs::read_dir(dir)
            .ok()?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.starts_with("clean-undo-") && n.ends_with(".json"))
                    .unwrap_or(false)
            })
            .collect();
        candidates.sort();
        candidates.pop()
    }
}

pub struct ApplyOutcome {
    pub deleted: usize,
    pub bytes: u64,
    pub failed: Vec<(String, String)>, // (path, reason)
}

/// Move files to the Recycle Bin, recording each success in the manifest.
/// Locked or vanished files are reported, never fatal.
pub fn recycle_files(
    paths: &[(String, u64)],
    manifest: &mut ActionManifest,
    mut progress: impl FnMut(usize),
) -> ApplyOutcome {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let mut outcome = ApplyOutcome {
        deleted: 0,
        bytes: 0,
        failed: Vec::new(),
    };
    for (i, (path, size)) in paths.iter().enumerate() {
        // Absolutize so the manifest matches the Recycle Bin's original-path
        // records regardless of the working directory at apply time.
        let abs = std::path::absolute(path)
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| path.clone());
        match trash::delete(&abs) {
            Ok(()) => {
                outcome.deleted += 1;
                outcome.bytes += size;
                manifest.actions.push(Action {
                    from: abs,
                    disposition: Disposition::RecycleBin,
                    size: *size,
                    at_unix: now,
                });
            }
            Err(e) => outcome.failed.push((path.clone(), e.to_string())),
        }
        if i % 50 == 0 {
            progress(i);
        }
    }
    progress(paths.len());
    outcome
}

pub struct UndoOutcome {
    pub restored: usize,
    pub missing: usize,
}

/// Restore every manifest entry still present in the Recycle Bin.
#[cfg(windows)]
pub fn undo(manifest: &ActionManifest) -> Result<UndoOutcome, CoreError> {
    use std::collections::HashSet;
    // Windows paths are case-insensitive; compare lowercased.
    let wanted: HashSet<String> = manifest
        .actions
        .iter()
        .filter(|a| a.disposition == Disposition::RecycleBin)
        .map(|a| a.from.to_lowercase())
        .collect();
    let items = trash::os_limited::list()
        .map_err(|e| CoreError::Session(format!("cannot list Recycle Bin: {e}")))?;
    // The same original path can occur multiple times in the bin (deleted,
    // restored, deleted again - or an older session). Restore only the most
    // recently deleted twin, and never overwrite a file that exists again.
    let mut best: std::collections::HashMap<String, trash::TrashItem> =
        std::collections::HashMap::new();
    for item in items {
        let original = item.original_path();
        let key = original.display().to_string().to_lowercase();
        if !wanted.contains(&key) || original.exists() {
            continue;
        }
        match best.get(&key) {
            Some(existing) if existing.time_deleted >= item.time_deleted => {}
            _ => {
                best.insert(key, item);
            }
        }
    }
    // Restore one item at a time so a single locked/conflicting item cannot
    // abort the whole undo.
    let mut restored = 0;
    let mut failed = 0;
    for item in best.into_values() {
        match trash::os_limited::restore_all([item]) {
            Ok(()) => restored += 1,
            Err(_) => failed += 1,
        }
    }
    Ok(UndoOutcome {
        restored,
        missing: wanted.len() - restored - failed,
    })
}

#[cfg(not(windows))]
pub fn undo(_manifest: &ActionManifest) -> Result<UndoOutcome, CoreError> {
    Err(CoreError::Session(
        "undo is only supported on Windows in the MVP".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_roundtrip_and_latest() {
        let dir = tempfile::tempdir().unwrap();
        let mut m = ActionManifest::new();
        m.actions.push(Action {
            from: "C:\\x\\y.tmp".into(),
            disposition: Disposition::RecycleBin,
            size: 42,
            at_unix: 1,
        });
        let path = m.save(dir.path()).unwrap();
        let loaded = ActionManifest::load(&path).unwrap();
        assert_eq!(loaded.session_id, m.session_id);
        assert_eq!(loaded.actions.len(), 1);
        assert_eq!(loaded.actions[0].size, 42);
        assert_eq!(ActionManifest::latest_in(dir.path()).unwrap(), path);
    }

    #[test]
    fn latest_in_empty_dir_is_none() {
        let dir = tempfile::tempdir().unwrap();
        assert!(ActionManifest::latest_in(dir.path()).is_none());
    }

    #[cfg(windows)]
    #[test]
    fn protected_roots_block_deletion() {
        let win = expand_env("%WINDIR%").unwrap();
        let inside = Path::new(&win).join("System32").join("kernel32.dll");
        assert!(!deletion_allowed(&inside, &[]));
        // ...unless the exact base is whitelisted (junk rule case)
        let temp_base = Path::new(&win).join("Temp");
        let temp_file = temp_base.join("x.tmp");
        assert!(deletion_allowed(&temp_file, &[temp_base]));
        // whitelisting Temp does not open the rest of Windows
        assert!(!deletion_allowed(&inside, &[Path::new(&win).join("Temp")]));
    }

    #[test]
    fn user_files_are_deletable() {
        assert!(deletion_allowed(
            Path::new("C:\\Users\\someone\\Downloads\\dupe.iso"),
            &[]
        ));
    }

    #[test]
    fn recycle_reports_missing_files_as_failed() {
        let mut m = ActionManifest::new();
        let out = recycle_files(
            &[("C:\\definitely\\missing\\file-xyz.tmp".into(), 10)],
            &mut m,
            |_| {},
        );
        assert_eq!(out.deleted, 0);
        assert_eq!(out.failed.len(), 1);
        assert!(m.actions.is_empty());
    }
}
