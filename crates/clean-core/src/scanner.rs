use crate::error::CoreError;
use crate::types::{systime_to_unix, FileRecord, SkippedPath};
use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use rayon::prelude::*;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

#[derive(Debug, Clone, Default)]
pub struct ScanOptions {
    /// Glob patterns excluded from the scan (matched against the full path,
    /// case-insensitive; `*` may cross directory separators).
    pub excludes: Vec<String>,
}

#[derive(Debug, Default)]
pub struct ScanOutcome {
    pub records: Vec<FileRecord>,
    pub skipped: Vec<SkippedPath>,
}

/// Abstraction over scan strategies. MVP ships the directory-walk backend;
/// V2 adds an NTFS MFT backend behind this same trait.
pub trait ScanBackend {
    fn scan(
        &self,
        root: &Path,
        opts: &ScanOptions,
        progress: &(dyn Fn(u64) + Sync),
    ) -> Result<ScanOutcome, CoreError>;
}

/// Rayon-parallel recursive directory walker.
///
/// Uses `std::fs::DirEntry::metadata()`, which on Windows is served from the
/// directory enumeration itself - no per-file open. (A per-file stat syscall
/// is catastrophically slow under corporate endpoint-protection hooks.)
/// Never follows symlinks, junctions, or other reparse points.
pub struct WalkBackend;

fn build_globset(patterns: &[String]) -> Result<Option<GlobSet>, CoreError> {
    if patterns.is_empty() {
        return Ok(None);
    }
    let mut builder = GlobSetBuilder::new();
    for p in patterns {
        let glob = GlobBuilder::new(p)
            .case_insensitive(true)
            .build()
            .map_err(|e| CoreError::InvalidPattern {
                pattern: p.clone(),
                message: e.to_string(),
            })?;
        builder.add(glob);
    }
    let set = builder.build().map_err(|e| CoreError::InvalidPattern {
        pattern: patterns.join(", "),
        message: e.to_string(),
    })?;
    Ok(Some(set))
}

struct WalkCtx<'a> {
    excludes: Option<GlobSet>,
    sink: Mutex<ScanOutcome>,
    seen: AtomicU64,
    progress: &'a (dyn Fn(u64) + Sync),
}

fn walk_dir(dir: &Path, ctx: &WalkCtx) {
    let read = match std::fs::read_dir(dir) {
        Ok(r) => r,
        Err(e) => {
            ctx.sink.lock().unwrap().skipped.push(SkippedPath {
                path: dir.display().to_string(),
                reason: e.to_string(),
            });
            return;
        }
    };

    let mut records: Vec<FileRecord> = Vec::new();
    let mut skipped: Vec<SkippedPath> = Vec::new();
    let mut subdirs: Vec<PathBuf> = Vec::new();

    for entry in read {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                skipped.push(SkippedPath {
                    path: dir.display().to_string(),
                    reason: e.to_string(),
                });
                continue;
            }
        };
        let path = entry.path();
        if let Some(set) = &ctx.excludes {
            if set.is_match(&path) {
                continue;
            }
        }
        let file_type = match entry.file_type() {
            Ok(t) => t,
            Err(e) => {
                skipped.push(SkippedPath {
                    path: path.display().to_string(),
                    reason: e.to_string(),
                });
                continue;
            }
        };
        // Skip reparse points entirely: following a junction would loop or
        // double-count; recording it as a dir would misattribute sizes.
        if file_type.is_symlink() {
            continue;
        }
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(e) => {
                skipped.push(SkippedPath {
                    path: path.display().to_string(),
                    reason: e.to_string(),
                });
                continue;
            }
        };

        let is_dir = file_type.is_dir();
        let name = entry.file_name().to_string_lossy().into_owned();
        let ext = if is_dir {
            None
        } else {
            path.extension().map(|e| e.to_string_lossy().to_lowercase())
        };

        #[cfg(windows)]
        let attributes = {
            use std::os::windows::fs::MetadataExt;
            meta.file_attributes()
        };
        #[cfg(not(windows))]
        let attributes = 0u32;

        records.push(FileRecord {
            id: 0, // renumbered once after the walk
            path: path.display().to_string(),
            name,
            ext,
            size: if is_dir { 0 } else { meta.len() },
            created: systime_to_unix(meta.created()),
            modified: systime_to_unix(meta.modified()),
            accessed: systime_to_unix(meta.accessed()),
            is_dir,
            attributes,
        });
        if is_dir {
            subdirs.push(path);
        }
    }

    let batch = records.len() as u64;
    {
        let mut sink = ctx.sink.lock().unwrap();
        sink.records.append(&mut records);
        sink.skipped.append(&mut skipped);
    }
    let seen = ctx.seen.fetch_add(batch, Ordering::Relaxed) + batch;
    (ctx.progress)(seen);

    subdirs.par_iter().for_each(|d| walk_dir(d, ctx));
}

impl ScanBackend for WalkBackend {
    fn scan(
        &self,
        root: &Path,
        opts: &ScanOptions,
        progress: &(dyn Fn(u64) + Sync),
    ) -> Result<ScanOutcome, CoreError> {
        if !root.exists() {
            return Err(CoreError::InvalidRoot(root.display().to_string()));
        }
        let ctx = WalkCtx {
            excludes: build_globset(&opts.excludes)?,
            sink: Mutex::new(ScanOutcome::default()),
            seen: AtomicU64::new(0),
            progress,
        };
        walk_dir(root, &ctx);
        let mut outcome = ctx.sink.into_inner().unwrap();
        // Deterministic order + sequential ids regardless of thread timing.
        outcome.records.sort_by(|a, b| a.path.cmp(&b.path));
        for (i, r) in outcome.records.iter_mut().enumerate() {
            r.id = i as u64;
        }
        Ok(outcome)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn fixture() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::create_dir_all(root.join("docs")).unwrap();
        fs::create_dir_all(root.join("cache").join("deep")).unwrap();
        fs::write(root.join("a.txt"), b"hello").unwrap();
        fs::write(root.join("docs").join("report.pdf"), vec![0u8; 1024]).unwrap();
        fs::write(root.join("cache").join("tmp.log"), vec![1u8; 2048]).unwrap();
        fs::write(
            root.join("cache").join("deep").join("blob.bin"),
            vec![2u8; 4096],
        )
        .unwrap();
        dir
    }

    fn scan(root: &Path, excludes: &[&str]) -> ScanOutcome {
        let opts = ScanOptions {
            excludes: excludes.iter().map(|s| s.to_string()).collect(),
        };
        WalkBackend.scan(root, &opts, &|_| {}).unwrap()
    }

    #[test]
    fn scans_all_files_and_dirs() {
        let dir = fixture();
        let out = scan(dir.path(), &[]);
        let files: Vec<_> = out.records.iter().filter(|r| !r.is_dir).collect();
        let dirs: Vec<_> = out.records.iter().filter(|r| r.is_dir).collect();
        assert_eq!(files.len(), 4);
        assert_eq!(dirs.len(), 3);
        assert!(out.skipped.is_empty());
        let total: u64 = files.iter().map(|r| r.size).sum();
        assert_eq!(total, 5 + 1024 + 2048 + 4096);
    }

    #[test]
    fn captures_metadata() {
        let dir = fixture();
        let out = scan(dir.path(), &[]);
        let pdf = out.records.iter().find(|r| r.name == "report.pdf").unwrap();
        assert_eq!(pdf.ext.as_deref(), Some("pdf"));
        assert_eq!(pdf.size, 1024);
        assert!(pdf.modified > 0);
        assert!(!pdf.is_dir);
    }

    #[test]
    fn exclude_globs_filter_paths() {
        let dir = fixture();
        let out = scan(dir.path(), &["*.log"]);
        assert!(out.records.iter().all(|r| r.name != "tmp.log"));
        assert!(out.records.iter().any(|r| r.name == "blob.bin"));
    }

    #[test]
    fn exclude_directory_subtree() {
        let dir = fixture();
        let out = scan(dir.path(), &["*cache*"]);
        assert!(out.records.iter().all(|r| !r.path.contains("cache")));
        assert!(out.records.iter().any(|r| r.name == "a.txt"));
    }

    #[test]
    fn invalid_root_errors() {
        let err = WalkBackend
            .scan(
                Path::new("Z:\\definitely\\missing\\root"),
                &ScanOptions::default(),
                &|_| {},
            )
            .unwrap_err();
        matches!(err, CoreError::InvalidRoot(_));
    }

    #[test]
    fn ids_are_sequential_and_order_deterministic() {
        let dir = fixture();
        let out1 = scan(dir.path(), &[]);
        let out2 = scan(dir.path(), &[]);
        for (i, r) in out1.records.iter().enumerate() {
            assert_eq!(r.id, i as u64);
        }
        let paths1: Vec<_> = out1.records.iter().map(|r| &r.path).collect();
        let paths2: Vec<_> = out2.records.iter().map(|r| &r.path).collect();
        assert_eq!(paths1, paths2);
    }

    #[test]
    fn progress_reports_growing_counts() {
        let dir = fixture();
        let max_seen = AtomicU64::new(0);
        WalkBackend
            .scan(dir.path(), &ScanOptions::default(), &|n| {
                max_seen.fetch_max(n, Ordering::Relaxed);
            })
            .unwrap();
        assert_eq!(max_seen.load(Ordering::Relaxed), 7);
    }
}
