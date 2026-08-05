//! Safety layer: protected paths, Recycle-Bin deletion, undo manifests.
//! Business rules (prd.md section 7): dry-run default, Recycle Bin first,
//! protected paths untouchable, every apply writes an undo manifest.

use crate::error::CoreError;
#[cfg(windows)]
use crate::rules::expand_env;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Directories that user-initiated deletions (duplicates) must never touch.
/// Junk rules may whitelist their own base (e.g. C:\Windows\Temp) explicitly.
#[cfg(windows)]
pub fn protected_roots() -> Vec<PathBuf> {
    [
        "%WINDIR%",
        "%ProgramFiles%",
        "%ProgramFiles(x86)%",
        "%ProgramData%",
    ]
    .iter()
    .filter_map(|v| expand_env(v))
    .map(PathBuf::from)
    .collect()
}

/// OS and installed applications. `/Library` is the system-wide library;
/// the per-user `~/Library` is intentionally NOT here (junk rule bases
/// live under it and are whitelisted per rule).
#[cfg(not(windows))]
pub fn protected_roots() -> Vec<PathBuf> {
    [
        "/System",
        "/Library",
        "/Applications",
        "/usr",
        "/bin",
        "/sbin",
        "/etc",
        "/private/etc",
        "/private/var/db",
    ]
    .iter()
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

    fn manifests_in(dir: &Path) -> Vec<PathBuf> {
        let mut candidates: Vec<PathBuf> = std::fs::read_dir(dir)
            .ok()
            .into_iter()
            .flatten()
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
        candidates
    }

    /// Most recent clean-undo-*.json in `dir`.
    pub fn latest_in(dir: &Path) -> Option<PathBuf> {
        Self::manifests_in(dir).pop()
    }

    /// Most recent manifest that still has something the Recycle Bin can
    /// give back. Permanent-delete manifests are kept as an audit record
    /// but must never be offered for undo (there is nothing to restore),
    /// nor hide an older restorable session behind them.
    pub fn latest_restorable_in(dir: &Path) -> Option<(PathBuf, ActionManifest)> {
        let mut candidates = Self::manifests_in(dir);
        while let Some(path) = candidates.pop() {
            if let Ok(m) = ActionManifest::load(&path) {
                if m.actions
                    .iter()
                    .any(|a| a.disposition == Disposition::RecycleBin)
                {
                    return Some((path, m));
                }
            }
        }
        None
    }
}

pub struct ApplyOutcome {
    pub deleted: usize,
    pub bytes: u64,
    pub failed: Vec<(String, String)>, // (path, reason)
}

/// Files per shell transaction. Each `trash::delete` call is a full COM
/// IFileOperation (~50-200 ms under corporate EDR), so recycling one file
/// at a time turns a 27k-file clean into tens of minutes. Batching like
/// Explorer does (select-all + Delete) amortizes that setup cost.
const RECYCLE_CHUNK: usize = 500;

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
    let mut processed = 0usize;
    for chunk in paths.chunks(RECYCLE_CHUNK) {
        // Absolutize so the manifest matches the Recycle Bin's original-path
        // records regardless of the working directory at apply time, and drop
        // already-missing files up front: the batch must only see files that
        // exist, so that "vanished after a failed batch" below can only mean
        // "the partial batch did recycle it".
        let mut batch: Vec<(&str, String, u64)> = Vec::new();
        for (path, size) in chunk {
            let abs = std::path::absolute(path)
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| path.clone());
            if std::fs::symlink_metadata(&abs).is_ok() {
                batch.push((path, abs, *size));
            } else {
                outcome
                    .failed
                    .push((path.clone(), "file no longer exists".into()));
            }
        }
        // One shell transaction for the whole chunk. A chunk containing a
        // locked file reports failure as a whole (IFileOperation flags any
        // aborted item) while still recycling the unlocked items.
        let batch_ok =
            batch.is_empty() || trash::delete_all(batch.iter().map(|(_, abs, _)| abs)).is_ok();
        for (path, abs, size) in batch {
            let gone = std::fs::symlink_metadata(&abs).is_err();
            if batch_ok || gone {
                outcome.deleted += 1;
                outcome.bytes += size;
                manifest.actions.push(Action {
                    from: abs,
                    disposition: Disposition::RecycleBin,
                    size,
                    at_unix: now,
                });
            } else {
                // Still on disk after a failed batch: retry alone to get the
                // per-file reason (usually held open by a running app). Only
                // the genuinely blocked files pay the per-call cost.
                match trash::delete(&abs) {
                    Ok(()) => {
                        outcome.deleted += 1;
                        outcome.bytes += size;
                        manifest.actions.push(Action {
                            from: abs,
                            disposition: Disposition::RecycleBin,
                            size,
                            at_unix: now,
                        });
                    }
                    Err(e) => outcome.failed.push((path.to_string(), e.to_string())),
                }
            }
        }
        processed += chunk.len();
        progress(processed);
    }
    progress(paths.len());
    outcome
}

/// Permanently delete files - no Recycle Bin, no undo. Opt-in fast path for
/// very large junk sets; every deletion is still recorded in the manifest
/// (as `Disposition::Permanent`) so the apply leaves an audit trail, but
/// undo intentionally skips these entries. Directories are refused (this is
/// for junk FILES; directory removal stays on the recycle path).
pub fn delete_files_permanently(
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
        let abs = std::path::absolute(path)
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| path.clone());
        match std::fs::remove_file(&abs) {
            Ok(()) => {
                outcome.deleted += 1;
                outcome.bytes += size;
                manifest.actions.push(Action {
                    from: abs,
                    disposition: Disposition::Permanent,
                    size: *size,
                    at_unix: now,
                });
            }
            Err(e) => outcome.failed.push((path.clone(), e.to_string())),
        }
        if i % 200 == 0 {
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

/// The `trash` crate cannot enumerate or restore Trash items on macOS,
/// so programmatic undo is Windows-only. Items are still recoverable by
/// hand: open the Trash in Finder and use "Put Back".
#[cfg(not(windows))]
pub fn undo(_manifest: &ActionManifest) -> Result<UndoOutcome, CoreError> {
    Err(CoreError::Session(
        "undo is not available on this platform; open the Trash in Finder and use Put Back".into(),
    ))
}

/// Names of running applications that hold open handles to any of `paths`
/// (the usual reason a Recycle-Bin move fails: Chromium-based apps keep
/// their %TEMP% files open without FILE_SHARE_DELETE for their lifetime).
/// One batched Restart Manager session - never call this per file during a
/// scan; it is for explaining failures after an apply.
#[cfg(windows)]
pub fn in_use_by(paths: &[String]) -> Vec<String> {
    use std::os::windows::ffi::OsStrExt;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct RmUniqueProcess {
        process_id: u32,
        start_time: [u32; 2],
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct RmProcessInfo {
        process: RmUniqueProcess,
        app_name: [u16; 256],
        service_short_name: [u16; 64],
        application_type: i32,
        app_status: u32,
        ts_session_id: u32,
        restartable: i32,
    }
    #[link(name = "rstrtmgr")]
    extern "system" {
        fn RmStartSession(handle: *mut u32, flags: u32, key: *mut u16) -> u32;
        fn RmEndSession(handle: u32) -> u32;
        fn RmRegisterResources(
            handle: u32,
            n_files: u32,
            file_names: *const *const u16,
            n_apps: u32,
            apps: *const RmUniqueProcess,
            n_services: u32,
            service_names: *const *const u16,
        ) -> u32;
        fn RmGetList(
            handle: u32,
            needed: *mut u32,
            count: *mut u32,
            info: *mut RmProcessInfo,
            reboot_reasons: *mut u32,
        ) -> u32;
    }

    const MAX_FILES: usize = 64; // a sample is enough to name the culprits
    const ERROR_MORE_DATA: u32 = 234;

    let wide: Vec<Vec<u16>> = paths
        .iter()
        .take(MAX_FILES)
        .map(|p| {
            std::ffi::OsStr::new(p)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect()
        })
        .collect();
    if wide.is_empty() {
        return Vec::new();
    }
    let ptrs: Vec<*const u16> = wide.iter().map(|w| w.as_ptr()).collect();

    let mut names = Vec::new();
    unsafe {
        let mut handle = 0u32;
        let mut key = [0u16; 33]; // CCH_RM_SESSION_KEY + 1
        if RmStartSession(&mut handle, 0, key.as_mut_ptr()) != 0 {
            return names;
        }
        if RmRegisterResources(
            handle,
            ptrs.len() as u32,
            ptrs.as_ptr(),
            0,
            std::ptr::null(),
            0,
            std::ptr::null(),
        ) == 0
        {
            let mut needed = 0u32;
            let mut count = 0u32;
            let mut reasons = 0u32;
            let rc = RmGetList(
                handle,
                &mut needed,
                &mut count,
                std::ptr::null_mut(),
                &mut reasons,
            );
            if (rc == ERROR_MORE_DATA || rc == 0) && needed > 0 {
                let cap = needed.min(64) as usize;
                let mut infos = vec![
                    RmProcessInfo {
                        process: RmUniqueProcess {
                            process_id: 0,
                            start_time: [0; 2],
                        },
                        app_name: [0; 256],
                        service_short_name: [0; 64],
                        application_type: 0,
                        app_status: 0,
                        ts_session_id: 0,
                        restartable: 0,
                    };
                    cap
                ];
                let mut count = cap as u32;
                if RmGetList(
                    handle,
                    &mut needed,
                    &mut count,
                    infos.as_mut_ptr(),
                    &mut reasons,
                ) == 0
                {
                    for info in infos.iter().take(count as usize) {
                        let len = info
                            .app_name
                            .iter()
                            .position(|&c| c == 0)
                            .unwrap_or(info.app_name.len());
                        let name = String::from_utf16_lossy(&info.app_name[..len]);
                        let name = if name.is_empty() {
                            format!("PID {}", info.process.process_id)
                        } else {
                            name
                        };
                        if !names.contains(&name) {
                            names.push(name);
                        }
                    }
                }
            }
        }
        RmEndSession(handle);
    }
    names
}

#[cfg(not(windows))]
pub fn in_use_by(_paths: &[String]) -> Vec<String> {
    Vec::new()
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

    #[cfg(not(windows))]
    #[test]
    fn protected_roots_block_deletion_unix() {
        assert!(!deletion_allowed(
            Path::new("/System/Library/CoreServices/Finder.app"),
            &[]
        ));
        assert!(!deletion_allowed(Path::new("/usr/lib/dyld"), &[]));
        // Per-user Library stays deletable (junk rule bases live there).
        assert!(deletion_allowed(
            Path::new("/Users/someone/Library/Caches/app/blob"),
            &[]
        ));
    }

    #[test]
    fn user_files_are_deletable() {
        assert!(deletion_allowed(
            Path::new("C:\\Users\\someone\\Downloads\\dupe.iso"),
            &[]
        ));
    }

    #[cfg(windows)]
    #[test]
    fn in_use_by_names_the_holding_process() {
        use std::os::windows::fs::OpenOptionsExt;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("held-open.bin");
        std::fs::write(&p, b"x").unwrap();
        // Hold the file open WITHOUT FILE_SHARE_DELETE - the exact state
        // Chromium apps leave their %TEMP% files in (blocks recycling).
        let _guard = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0x1 | 0x2) // read + write, no delete
            .open(&p)
            .unwrap();
        let holders = in_use_by(&[p.display().to_string()]);
        assert!(!holders.is_empty(), "expected the test process as holder");
        // A file nobody holds reports no holders.
        let free = dir.path().join("free.bin");
        std::fs::write(&free, b"y").unwrap();
        assert!(in_use_by(&[free.display().to_string()]).is_empty());
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

    #[test]
    fn recycle_chunks_report_all_missing_and_final_progress() {
        // More paths than one chunk, all missing: exercises the chunk loop
        // without touching the real Recycle Bin.
        let paths: Vec<(String, u64)> = (0..(super::RECYCLE_CHUNK + 3))
            .map(|i| (format!("C:\\definitely\\missing\\f{i}.tmp"), 1))
            .collect();
        let mut m = ActionManifest::new();
        let mut last = 0usize;
        let out = recycle_files(&paths, &mut m, |done| last = done);
        assert_eq!(out.deleted, 0);
        assert_eq!(out.failed.len(), paths.len());
        assert_eq!(last, paths.len());
        assert!(m.actions.is_empty());
    }

    #[test]
    fn permanent_delete_removes_and_records() {
        let dir = tempfile::tempdir().unwrap();
        let mut paths = Vec::new();
        for i in 0..3 {
            let p = dir.path().join(format!("junk-{i}.tmp"));
            std::fs::write(&p, b"x").unwrap();
            paths.push((p.display().to_string(), 1));
        }
        paths.push(("C:\\definitely\\missing\\gone.tmp".into(), 1));
        let mut m = ActionManifest::new();
        let out = delete_files_permanently(&paths, &mut m, |_| {});
        assert_eq!(out.deleted, 3);
        assert_eq!(out.bytes, 3);
        assert_eq!(out.failed.len(), 1);
        assert_eq!(m.actions.len(), 3);
        assert!(m
            .actions
            .iter()
            .all(|a| a.disposition == Disposition::Permanent));
        for (p, _) in &paths[..3] {
            assert!(!Path::new(p).exists());
        }
    }

    #[test]
    fn permanent_delete_refuses_directories() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("subdir");
        std::fs::create_dir(&sub).unwrap();
        let mut m = ActionManifest::new();
        let out = delete_files_permanently(&[(sub.display().to_string(), 0)], &mut m, |_| {});
        assert_eq!(out.deleted, 0);
        assert_eq!(out.failed.len(), 1);
        assert!(sub.exists());
    }

    #[test]
    fn latest_restorable_skips_permanent_manifests() {
        let dir = tempfile::tempdir().unwrap();
        let mut older = ActionManifest::new();
        older.session_id = "100".into();
        older.actions.push(Action {
            from: "C:\\x\\recycled.tmp".into(),
            disposition: Disposition::RecycleBin,
            size: 5,
            at_unix: 1,
        });
        older.save(dir.path()).unwrap();
        let mut newer = ActionManifest::new();
        newer.session_id = "200".into();
        newer.actions.push(Action {
            from: "C:\\x\\deleted.tmp".into(),
            disposition: Disposition::Permanent,
            size: 7,
            at_unix: 2,
        });
        let newer_path = newer.save(dir.path()).unwrap();
        // latest_in sees the permanent manifest, but the restorable lookup
        // must fall through to the older recycle session behind it.
        assert_eq!(ActionManifest::latest_in(dir.path()).unwrap(), newer_path);
        let (path, m) = ActionManifest::latest_restorable_in(dir.path()).unwrap();
        assert!(path.display().to_string().contains("clean-undo-100"));
        assert_eq!(m.actions[0].size, 5);
        // A dir with only permanent manifests offers nothing to restore.
        let dir2 = tempfile::tempdir().unwrap();
        newer.save(dir2.path()).unwrap();
        assert!(ActionManifest::latest_restorable_in(dir2.path()).is_none());
    }
}
