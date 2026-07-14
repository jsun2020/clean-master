use crate::error::CoreError;
use crate::types::{systime_to_unix, FileRecord, SkippedPath};
use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use std::path::Path;

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
        progress: &mut dyn FnMut(u64),
    ) -> Result<ScanOutcome, CoreError>;
}

/// Parallel directory traversal backend (jwalk/rayon).
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

impl ScanBackend for WalkBackend {
    fn scan(
        &self,
        root: &Path,
        opts: &ScanOptions,
        progress: &mut dyn FnMut(u64),
    ) -> Result<ScanOutcome, CoreError> {
        if !root.exists() {
            return Err(CoreError::InvalidRoot(root.display().to_string()));
        }
        let excludes = build_globset(&opts.excludes)?;

        let mut outcome = ScanOutcome::default();
        let mut next_id: u64 = 0;
        let mut seen: u64 = 0;

        let walker = jwalk::WalkDir::new(root)
            .skip_hidden(false)
            .follow_links(false);

        for entry in walker {
            seen += 1;
            if seen % 512 == 0 {
                progress(seen);
            }
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    outcome.skipped.push(SkippedPath {
                        path: e
                            .path()
                            .map(|p| p.display().to_string())
                            .unwrap_or_default(),
                        reason: e.to_string(),
                    });
                    continue;
                }
            };
            let path = entry.path();
            if path == root {
                continue;
            }
            if let Some(set) = &excludes {
                if set.is_match(&path) {
                    continue;
                }
            }

            let file_type = entry.file_type();
            // Do not record reparse points / symlinks; jwalk (follow_links=false)
            // already refuses to descend into them, and treating a junction as a
            // real directory would double-count content in reports.
            if file_type.is_symlink() {
                continue;
            }

            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(e) => {
                    outcome.skipped.push(SkippedPath {
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
                path.extension()
                    .map(|e| e.to_string_lossy().to_lowercase())
            };

            #[cfg(windows)]
            let attributes = {
                use std::os::windows::fs::MetadataExt;
                meta.file_attributes()
            };
            #[cfg(not(windows))]
            let attributes = 0u32;

            outcome.records.push(FileRecord {
                id: next_id,
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
            next_id += 1;
        }
        progress(seen);
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
        fs::write(root.join("cache").join("deep").join("blob.bin"), vec![2u8; 4096]).unwrap();
        dir
    }

    fn scan(root: &Path, excludes: &[&str]) -> ScanOutcome {
        let opts = ScanOptions {
            excludes: excludes.iter().map(|s| s.to_string()).collect(),
        };
        WalkBackend.scan(root, &opts, &mut |_| {}).unwrap()
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
        let pdf = out
            .records
            .iter()
            .find(|r| r.name == "report.pdf")
            .unwrap();
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
        // everything else still present
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
                &mut |_| {},
            )
            .unwrap_err();
        matches!(err, CoreError::InvalidRoot(_));
    }

    #[test]
    fn ids_are_sequential_and_unique() {
        let dir = fixture();
        let out = scan(dir.path(), &[]);
        for (i, r) in out.records.iter().enumerate() {
            assert_eq!(r.id, i as u64);
        }
    }
}
