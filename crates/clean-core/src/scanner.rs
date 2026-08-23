use crate::error::CoreError;
use crate::types::{systime_to_unix, FileRecord, SkippedPath};
use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
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

/// One directory's direct children, as the walker sees them.
struct DirListing {
    records: Vec<FileRecord>,
    skipped: Vec<SkippedPath>,
    subdirs: Vec<PathBuf>,
}

/// Enumerate one directory (no recursion). Metadata comes from the
/// enumeration itself - no per-file open. Err = read_dir itself failed.
fn enumerate_dir(dir: &Path, excludes: Option<&GlobSet>) -> Result<DirListing, String> {
    let read = std::fs::read_dir(dir).map_err(|e| e.to_string())?;

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
        if let Some(set) = excludes {
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

    Ok(DirListing {
        records,
        skipped,
        subdirs,
    })
}

fn walk_dir(dir: &Path, ctx: &WalkCtx) {
    let listing = match enumerate_dir(dir, ctx.excludes.as_ref()) {
        Ok(l) => l,
        Err(reason) => {
            ctx.sink.lock().unwrap().skipped.push(SkippedPath {
                path: dir.display().to_string(),
                reason,
            });
            return;
        }
    };
    let mut records = listing.records;
    let mut skipped = listing.skipped;

    let batch = records.len() as u64;
    {
        let mut sink = ctx.sink.lock().unwrap();
        sink.records.append(&mut records);
        sink.skipped.append(&mut skipped);
    }
    let seen = ctx.seen.fetch_add(batch, Ordering::Relaxed) + batch;
    (ctx.progress)(seen);

    listing.subdirs.par_iter().for_each(|d| walk_dir(d, ctx));
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
        finalize(&mut outcome);
        Ok(outcome)
    }
}

/// Deterministic order + sequential ids regardless of thread timing.
fn finalize(outcome: &mut ScanOutcome) {
    outcome.records.sort_by(|a, b| a.path.cmp(&b.path));
    for (i, r) in outcome.records.iter_mut().enumerate() {
        r.id = i as u64;
    }
}

// ---------------------------------------------------------- merge scan --

struct MergeCtx<'a> {
    excludes: Option<GlobSet>,
    /// Snapshot records indexed by their parent directory (lowercased path).
    children: HashMap<String, Vec<&'a FileRecord>>,
    /// Lowercased paths of every directory the snapshot knows (plus root).
    snap_dirs: HashSet<String>,
    /// Lowercased paths of directories whose direct children changed.
    dirty: &'a HashSet<String>,
    sink: Mutex<ScanOutcome>,
    /// Directories re-enumerated live this run (lowercased).
    live_visited: Mutex<HashSet<String>>,
    seen: AtomicU64,
    progress: &'a (dyn Fn(u64) + Sync),
}

fn merge_visit(dir: &str, ctx: &MergeCtx) {
    let lower = dir.to_lowercase();
    // A directory is walked live when the journal marked it dirty OR the
    // snapshot has never seen it (i.e. it appeared since the snapshot).
    // Everything else is served straight from the snapshot. Dirty paths are
    // only ever consulted as a test - visits always flow down from the root,
    // so deleted or excluded directories are simply never reached.
    let live = ctx.dirty.contains(&lower) || !ctx.snap_dirs.contains(&lower);

    let (mut records, mut skipped, subdirs): (Vec<FileRecord>, Vec<SkippedPath>, Vec<String>) =
        if live {
            ctx.live_visited.lock().unwrap().insert(lower);
            match enumerate_dir(Path::new(dir), ctx.excludes.as_ref()) {
                Ok(l) => {
                    let subdirs = l.subdirs.iter().map(|p| p.display().to_string()).collect();
                    (l.records, l.skipped, subdirs)
                }
                Err(reason) => {
                    // The dirty directory itself is gone (deleted after the
                    // journal read); its snapshot subtree is dropped simply by
                    // not emitting it.
                    ctx.sink.lock().unwrap().skipped.push(SkippedPath {
                        path: dir.to_string(),
                        reason,
                    });
                    return;
                }
            }
        } else {
            let recs: Vec<FileRecord> = ctx
                .children
                .get(&lower)
                .map(|v| v.iter().map(|r| (*r).clone()).collect())
                .unwrap_or_default();
            let subdirs = recs
                .iter()
                .filter(|r| r.is_dir)
                .map(|r| r.path.clone())
                .collect();
            (recs, Vec::new(), subdirs)
        };

    let batch = records.len() as u64;
    {
        let mut sink = ctx.sink.lock().unwrap();
        sink.records.append(&mut records);
        sink.skipped.append(&mut skipped);
    }
    let seen = ctx.seen.fetch_add(batch, Ordering::Relaxed) + batch;
    (ctx.progress)(seen);

    subdirs.par_iter().for_each(|d| merge_visit(d, ctx));
}

/// Differential rescan: rebuild a full `ScanOutcome` for `root`, re-reading
/// only the directories in `dirty_lower` (lowercased full paths, typically
/// from the USN journal) and serving every other directory from `snapshot`.
///
/// Correctness contract: with an accurate dirty set this returns exactly what
/// a fresh full scan would (modulo access times) - the equivalence tests
/// below and in tests/delta_e2e.rs enforce it.
///
/// Returns the outcome plus how many directories were enumerated live.
pub fn merge_scan(
    root: &Path,
    opts: &ScanOptions,
    snapshot: &ScanOutcome,
    dirty_lower: &HashSet<String>,
    progress: &(dyn Fn(u64) + Sync),
) -> Result<(ScanOutcome, u64), CoreError> {
    if !root.exists() {
        return Err(CoreError::InvalidRoot(root.display().to_string()));
    }
    let root_str = root.display().to_string();
    let root_lower = root_str.to_lowercase();

    let mut children: HashMap<String, Vec<&FileRecord>> = HashMap::new();
    let mut snap_dirs: HashSet<String> = HashSet::new();
    snap_dirs.insert(root_lower.clone());
    for r in &snapshot.records {
        if r.is_dir {
            snap_dirs.insert(r.path.to_lowercase());
        }
        if let Some(parent) = Path::new(&r.path).parent() {
            children
                .entry(parent.display().to_string().to_lowercase())
                .or_default()
                .push(r);
        }
    }

    let ctx = MergeCtx {
        excludes: build_globset(&opts.excludes)?,
        children,
        snap_dirs,
        dirty: dirty_lower,
        sink: Mutex::new(ScanOutcome::default()),
        live_visited: Mutex::new(HashSet::new()),
        seen: AtomicU64::new(0),
        progress,
    };
    merge_visit(&root_str, &ctx);

    let live_visited = ctx.live_visited.into_inner().unwrap();
    let mut outcome = ctx.sink.into_inner().unwrap();
    // Carry forward unreadable-path notes from the snapshot, except where the
    // directory was re-enumerated live (which re-reports if still unreadable).
    for s in &snapshot.skipped {
        let lower = s.path.to_lowercase();
        let parent_lower = Path::new(&s.path)
            .parent()
            .map(|p| p.display().to_string().to_lowercase());
        let revisited = live_visited.contains(&lower)
            || parent_lower.is_some_and(|p| live_visited.contains(&p));
        if !revisited {
            outcome.skipped.push(s.clone());
        }
    }
    finalize(&mut outcome);
    Ok((outcome, live_visited.len() as u64))
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

    // ------------------------------------------------------- merge scan --

    /// Every FileRecord field except `accessed`, in declaration order.
    type RecordSansAtime = (String, String, Option<String>, u64, i64, i64, bool, u32);

    /// Access times can drift between two scans (AV/indexer touches); every
    /// other field must match exactly, so equivalence ignores `accessed`.
    fn strip_atime(out: &ScanOutcome) -> Vec<RecordSansAtime> {
        out.records
            .iter()
            .map(|r| {
                (
                    r.path.clone(),
                    r.name.clone(),
                    r.ext.clone(),
                    r.size,
                    r.created,
                    r.modified,
                    r.is_dir,
                    r.attributes,
                )
            })
            .collect()
    }

    fn merge(root: &Path, snapshot: &ScanOutcome, dirty: &[String]) -> (ScanOutcome, u64) {
        let set: HashSet<String> = dirty.iter().map(|s| s.to_lowercase()).collect();
        merge_scan(root, &ScanOptions::default(), snapshot, &set, &|_| {}).unwrap()
    }

    fn lower(p: &Path) -> String {
        p.display().to_string().to_lowercase()
    }

    #[test]
    fn merge_with_all_dirs_dirty_equals_full_scan() {
        let dir = fixture();
        let snap = scan(dir.path(), &[]);
        let mut dirty: Vec<String> = snap
            .records
            .iter()
            .filter(|r| r.is_dir)
            .map(|r| r.path.clone())
            .collect();
        dirty.push(dir.path().display().to_string());
        let (merged, live) = merge(dir.path(), &snap, &dirty);
        // Compare against a fresh walk, not the snapshot: NTFS keeps a
        // lazily-updated duplicate of timestamps in the parent directory
        // index, so the very first walk after fixture creation can read a
        // stale directory mtime that later walks see refreshed (flaked on
        // the GitHub runner). merged and fresh are both post-first-walk.
        let fresh = scan(dir.path(), &[]);
        assert_eq!(strip_atime(&merged), strip_atime(&fresh));
        assert_eq!(live, 4, "root + 3 subdirs all enumerated live");
    }

    #[test]
    fn merge_with_nothing_dirty_serves_snapshot_verbatim() {
        let dir = fixture();
        let snap = scan(dir.path(), &[]);
        let (merged, live) = merge(dir.path(), &snap, &[]);
        assert_eq!(merged.records, snap.records);
        assert_eq!(live, 0, "no directory may be touched");
    }

    /// Control: with an empty dirty set, a mutation must NOT show up - proof
    /// the merge really reads the snapshot rather than sneaking a full walk.
    #[test]
    fn merge_without_dirty_mark_stays_stale() {
        let dir = fixture();
        let snap = scan(dir.path(), &[]);
        fs::write(dir.path().join("cache").join("tmp.log"), vec![9u8; 9999]).unwrap();
        let (merged, _) = merge(dir.path(), &snap, &[]);
        let old = merged.records.iter().find(|r| r.name == "tmp.log").unwrap();
        assert_eq!(old.size, 2048, "stale by design without a dirty mark");
    }

    #[test]
    fn merge_picks_up_modified_file_in_dirty_dir() {
        let dir = fixture();
        let snap = scan(dir.path(), &[]);
        fs::write(dir.path().join("cache").join("tmp.log"), vec![9u8; 9999]).unwrap();
        let (merged, live) = merge(dir.path(), &snap, &[lower(&dir.path().join("cache"))]);
        let fresh = scan(dir.path(), &[]);
        assert_eq!(strip_atime(&merged), strip_atime(&fresh));
        assert_eq!(live, 1);
        let rec = merged.records.iter().find(|r| r.name == "tmp.log").unwrap();
        assert_eq!(rec.size, 9999);
    }

    #[test]
    fn merge_picks_up_added_and_deleted_files() {
        let dir = fixture();
        let snap = scan(dir.path(), &[]);
        fs::remove_file(dir.path().join("a.txt")).unwrap();
        fs::write(dir.path().join("docs").join("new.bin"), vec![3u8; 12]).unwrap();
        let (merged, _) = merge(
            dir.path(),
            &snap,
            &[lower(dir.path()), lower(&dir.path().join("docs"))],
        );
        let fresh = scan(dir.path(), &[]);
        assert_eq!(strip_atime(&merged), strip_atime(&fresh));
        assert!(merged.records.iter().all(|r| r.name != "a.txt"));
        assert!(merged.records.iter().any(|r| r.name == "new.bin"));
    }

    #[test]
    fn merge_walks_brand_new_subtree() {
        let dir = fixture();
        let snap = scan(dir.path(), &[]);
        let deep = dir.path().join("cache").join("newdir").join("sub");
        fs::create_dir_all(&deep).unwrap();
        fs::write(deep.join("fresh.dat"), vec![7u8; 42]).unwrap();
        // Only the immediate parent is dirty; the new subtree must be walked
        // live because the snapshot has never seen it.
        let (merged, live) = merge(dir.path(), &snap, &[lower(&dir.path().join("cache"))]);
        let fresh = scan(dir.path(), &[]);
        assert_eq!(strip_atime(&merged), strip_atime(&fresh));
        assert_eq!(live, 3, "cache + newdir + sub");
        assert!(merged.records.iter().any(|r| r.name == "fresh.dat"));
    }

    #[test]
    fn merge_handles_renamed_directory() {
        let dir = fixture();
        let snap = scan(dir.path(), &[]);
        fs::rename(dir.path().join("docs"), dir.path().join("papers")).unwrap();
        let (merged, _) = merge(dir.path(), &snap, &[lower(dir.path())]);
        let fresh = scan(dir.path(), &[]);
        assert_eq!(strip_atime(&merged), strip_atime(&fresh));
        assert!(merged.records.iter().all(|r| !r.path.contains("docs")));
        assert!(merged.records.iter().any(|r| r.name == "papers"));
    }

    #[test]
    fn merge_drops_deleted_subtree() {
        let dir = fixture();
        let snap = scan(dir.path(), &[]);
        fs::remove_dir_all(dir.path().join("cache")).unwrap();
        let (merged, _) = merge(dir.path(), &snap, &[lower(dir.path())]);
        let fresh = scan(dir.path(), &[]);
        assert_eq!(strip_atime(&merged), strip_atime(&fresh));
        assert!(merged.records.iter().all(|r| !r.path.contains("cache")));
    }

    #[test]
    fn merge_dirty_lookup_is_case_insensitive() {
        let dir = fixture();
        fs::create_dir_all(dir.path().join("MixedCase")).unwrap();
        fs::write(dir.path().join("MixedCase").join("x.txt"), b"1").unwrap();
        let snap = scan(dir.path(), &[]);
        fs::write(dir.path().join("MixedCase").join("x.txt"), b"12345").unwrap();
        // Dirty sets are lowercased by contract (USN resolution lowercases);
        // the snapshot path keeps its real casing - the lookup must match.
        let (merged, _) = merge(dir.path(), &snap, &[lower(&dir.path().join("MixedCase"))]);
        let rec = merged.records.iter().find(|r| r.name == "x.txt").unwrap();
        assert_eq!(rec.size, 5);
    }
}
