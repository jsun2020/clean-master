use crate::types::FileRecord;
use rayon::prelude::*;
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

pub const DEFAULT_MIN_SIZE: u64 = 1024 * 1024; // 1 MiB

#[derive(Debug, Clone)]
pub struct DupeOptions {
    /// Files smaller than this are ignored (dedup value is negligible).
    pub min_size: u64,
    /// Directory prefixes in priority order; the surviving copy is chosen
    /// from the highest-priority location first.
    pub keep_priority: Vec<String>,
}

impl Default for DupeOptions {
    fn default() -> Self {
        DupeOptions {
            min_size: DEFAULT_MIN_SIZE,
            keep_priority: Vec::new(),
        }
    }
}

/// A set of content-identical files (full BLAKE3 verified).
#[derive(Debug, Clone)]
pub struct DupeGroup {
    /// Hex BLAKE3 of the full content.
    pub hash: String,
    pub size: u64,
    /// Always >= 2 members.
    pub members: Vec<FileRecord>,
    /// Index into `members` of the copy that should survive.
    pub suggested_keep: usize,
}

impl DupeGroup {
    /// Members that may be deleted. By construction this can never contain
    /// every member: the suggested keeper is always excluded (business rule:
    /// one copy always survives).
    pub fn deletable(&self) -> Vec<&FileRecord> {
        self.members
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != self.suggested_keep)
            .map(|(_, r)| r)
            .collect()
    }

    /// Bytes reclaimable if all deletable members are removed.
    pub fn wasted_bytes(&self) -> u64 {
        self.size * (self.members.len() as u64 - 1)
    }
}

const PARTIAL_CHUNK: usize = 4096;

/// Hash of first and last 4 KiB - cheap discriminator before full hashing.
fn partial_hash(path: &Path, size: u64) -> std::io::Result<[u8; 32]> {
    let mut f = File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = [0u8; PARTIAL_CHUNK];

    let head = f.read(&mut buf)?;
    hasher.update(&buf[..head]);

    if size > (PARTIAL_CHUNK * 2) as u64 {
        f.seek(SeekFrom::End(-(PARTIAL_CHUNK as i64)))?;
        let tail = f.read(&mut buf)?;
        hasher.update(&buf[..tail]);
    }
    Ok(*hasher.finalize().as_bytes())
}

fn full_hash(path: &Path) -> std::io::Result<[u8; 32]> {
    let mut f = File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(*hasher.finalize().as_bytes())
}

fn keep_score(record: &FileRecord, priority: &[String]) -> (usize, i64, String) {
    let rank = priority
        .iter()
        .position(|p| {
            let rp = Path::new(p);
            Path::new(&record.path).starts_with(rp)
        })
        .unwrap_or(usize::MAX);
    // Lower tuple wins: better priority rank, then older file, then path order.
    let age = if record.created != 0 {
        record.created
    } else {
        record.modified
    };
    (rank, age, record.path.clone())
}

/// 3-stage funnel: size buckets -> head/tail hash -> full BLAKE3.
/// Files that cannot be read (locked, vanished since scan) drop out silently;
/// a group is only ever formed from full-hash-verified content.
pub fn find_duplicates(records: &[FileRecord], opts: &DupeOptions) -> Vec<DupeGroup> {
    // Stage A: size buckets
    let mut by_size: HashMap<u64, Vec<&FileRecord>> = HashMap::new();
    for r in records {
        if r.is_dir || r.size < opts.min_size {
            continue;
        }
        by_size.entry(r.size).or_default().push(r);
    }
    let candidates: Vec<(u64, Vec<&FileRecord>)> = by_size
        .into_iter()
        .filter(|(_, v)| v.len() >= 2)
        .collect();

    // Stage B: partial hash within each size bucket (parallel)
    let partial_groups: Vec<(u64, Vec<&FileRecord>)> = candidates
        .par_iter()
        .flat_map(|(size, group)| {
            let mut by_partial: HashMap<[u8; 32], Vec<&FileRecord>> = HashMap::new();
            for r in group {
                if let Ok(h) = partial_hash(Path::new(&r.path), r.size) {
                    by_partial.entry(h).or_default().push(r);
                }
            }
            by_partial
                .into_values()
                .filter(|v| v.len() >= 2)
                .map(|v| (*size, v))
                .collect::<Vec<_>>()
        })
        .collect();

    // Stage C: full hash (parallel), groups keyed by verified content hash
    let mut groups: Vec<DupeGroup> = partial_groups
        .par_iter()
        .flat_map(|(size, group)| {
            let mut by_full: HashMap<[u8; 32], Vec<&FileRecord>> = HashMap::new();
            for r in group {
                if let Ok(h) = full_hash(Path::new(&r.path)) {
                    by_full.entry(h).or_default().push(r);
                }
            }
            by_full
                .into_iter()
                .filter(|(_, v)| v.len() >= 2)
                .map(|(hash, v)| {
                    let mut members: Vec<FileRecord> = v.into_iter().cloned().collect();
                    members.sort_by(|a, b| a.path.cmp(&b.path));
                    let suggested_keep = members
                        .iter()
                        .enumerate()
                        .min_by_key(|(_, r)| keep_score(r, &opts.keep_priority))
                        .map(|(i, _)| i)
                        .unwrap_or(0);
                    DupeGroup {
                        hash: hex(&hash),
                        size: *size,
                        members,
                        suggested_keep,
                    }
                })
                .collect::<Vec<_>>()
        })
        .collect();

    groups.sort_by(|a, b| b.wasted_bytes().cmp(&a.wasted_bytes()).then_with(|| a.hash.cmp(&b.hash)));
    groups
}

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::{ScanBackend, ScanOptions, WalkBackend};
    use std::fs;

    fn scan(root: &Path) -> Vec<FileRecord> {
        WalkBackend
            .scan(root, &ScanOptions::default(), &mut |_| {})
            .unwrap()
            .records
    }

    fn opts(min_size: u64, keep: &[&str]) -> DupeOptions {
        DupeOptions {
            min_size,
            keep_priority: keep.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn finds_content_identical_files_across_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let content = vec![7u8; 10_000];
        fs::create_dir_all(dir.path().join("a")).unwrap();
        fs::create_dir_all(dir.path().join("b")).unwrap();
        fs::write(dir.path().join("a").join("x.bin"), &content).unwrap();
        fs::write(dir.path().join("b").join("copy.bin"), &content).unwrap();
        fs::write(dir.path().join("b").join("different.bin"), vec![9u8; 10_000]).unwrap();

        let groups = find_duplicates(&scan(dir.path()), &opts(1, &[]));
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].members.len(), 2);
        assert_eq!(groups[0].size, 10_000);
        assert_eq!(groups[0].wasted_bytes(), 10_000);
    }

    #[test]
    fn same_size_same_edges_different_middle_not_grouped() {
        // Defeats size and head/tail stages; only the full hash can tell apart.
        let dir = tempfile::tempdir().unwrap();
        let mut a = vec![0u8; 20_000];
        let mut b = vec![0u8; 20_000];
        a[10_000] = 1;
        b[10_000] = 2;
        fs::write(dir.path().join("a.bin"), &a).unwrap();
        fs::write(dir.path().join("b.bin"), &b).unwrap();

        let groups = find_duplicates(&scan(dir.path()), &opts(1, &[]));
        assert!(groups.is_empty());
    }

    #[test]
    fn min_size_filters_small_files() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("s1.txt"), b"same").unwrap();
        fs::write(dir.path().join("s2.txt"), b"same").unwrap();
        let groups = find_duplicates(&scan(dir.path()), &opts(1024, &[]));
        assert!(groups.is_empty());
    }

    #[test]
    fn keep_priority_selects_survivor() {
        let dir = tempfile::tempdir().unwrap();
        let content = vec![3u8; 5_000];
        let docs = dir.path().join("Documents");
        let downloads = dir.path().join("Downloads");
        fs::create_dir_all(&docs).unwrap();
        fs::create_dir_all(&downloads).unwrap();
        fs::write(docs.join("keep.bin"), &content).unwrap();
        fs::write(downloads.join("dupe.bin"), &content).unwrap();

        let groups = find_duplicates(
            &scan(dir.path()),
            &opts(1, &[docs.to_str().unwrap()]),
        );
        assert_eq!(groups.len(), 1);
        let keeper = &groups[0].members[groups[0].suggested_keep];
        assert!(keeper.path.contains("Documents"));
    }

    #[test]
    fn one_copy_always_survives() {
        let dir = tempfile::tempdir().unwrap();
        let content = vec![5u8; 4_000];
        for name in ["a.bin", "b.bin", "c.bin"] {
            fs::write(dir.path().join(name), &content).unwrap();
        }
        let groups = find_duplicates(&scan(dir.path()), &opts(1, &[]));
        assert_eq!(groups.len(), 1);
        let g = &groups[0];
        assert_eq!(g.members.len(), 3);
        assert_eq!(g.deletable().len(), 2); // never all 3
        assert!(g.suggested_keep < g.members.len());
        assert_eq!(g.wasted_bytes(), 8_000);
    }
}
