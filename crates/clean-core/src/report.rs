use crate::types::FileRecord;
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, PartialEq)]
pub struct ExtStat {
    pub ext: String, // "(none)" for files without extension
    pub count: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DirStat {
    pub path: String,
    /// Cumulative bytes of all files anywhere below this directory.
    pub bytes: u64,
    pub files: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AgeBucket {
    pub label: &'static str,
    pub count: u64,
    pub bytes: u64,
}

const DAY: i64 = 86_400;

/// Largest files, descending by size.
pub fn top_files(records: &[FileRecord], n: usize) -> Vec<&FileRecord> {
    let mut files: Vec<&FileRecord> = records.iter().filter(|r| !r.is_dir).collect();
    files.sort_by(|a, b| b.size.cmp(&a.size).then_with(|| a.path.cmp(&b.path)));
    files.truncate(n);
    files
}

/// Cumulative directory sizes (a file counts toward every ancestor under `root`).
pub fn top_dirs(records: &[FileRecord], root: &str, n: usize) -> Vec<DirStat> {
    let root_path = Path::new(root);
    let mut acc: HashMap<String, (u64, u64)> = HashMap::new(); // path -> (bytes, files)
    for r in records.iter().filter(|r| !r.is_dir) {
        let mut cur = Path::new(&r.path).parent();
        while let Some(dir) = cur {
            if !dir.starts_with(root_path) || dir == root_path {
                break;
            }
            let entry = acc.entry(dir.display().to_string()).or_insert((0, 0));
            entry.0 += r.size;
            entry.1 += 1;
            cur = dir.parent();
        }
    }
    let mut stats: Vec<DirStat> = acc
        .into_iter()
        .map(|(path, (bytes, files))| DirStat { path, bytes, files })
        .collect();
    stats.sort_by(|a, b| b.bytes.cmp(&a.bytes).then_with(|| a.path.cmp(&b.path)));
    stats.truncate(n);
    stats
}

/// Bytes and counts grouped by extension, descending by bytes.
pub fn by_extension(records: &[FileRecord], n: usize) -> Vec<ExtStat> {
    let mut acc: HashMap<String, (u64, u64)> = HashMap::new();
    for r in records.iter().filter(|r| !r.is_dir) {
        let key = r.ext.clone().unwrap_or_else(|| "(none)".to_string());
        let entry = acc.entry(key).or_insert((0, 0));
        entry.0 += 1;
        entry.1 += r.size;
    }
    let mut stats: Vec<ExtStat> = acc
        .into_iter()
        .map(|(ext, (count, bytes))| ExtStat { ext, count, bytes })
        .collect();
    stats.sort_by(|a, b| b.bytes.cmp(&a.bytes).then_with(|| a.ext.cmp(&b.ext)));
    stats.truncate(n);
    stats
}

/// Files bucketed by age of last modification relative to `now_unix`.
pub fn by_age(records: &[FileRecord], now_unix: i64) -> Vec<AgeBucket> {
    let mut buckets = [
        AgeBucket {
            label: "< 30 days",
            count: 0,
            bytes: 0,
        },
        AgeBucket {
            label: "30-90 days",
            count: 0,
            bytes: 0,
        },
        AgeBucket {
            label: "90-365 days",
            count: 0,
            bytes: 0,
        },
        AgeBucket {
            label: "1-2 years",
            count: 0,
            bytes: 0,
        },
        AgeBucket {
            label: "> 2 years",
            count: 0,
            bytes: 0,
        },
    ];
    for r in records.iter().filter(|r| !r.is_dir) {
        let age_days = (now_unix - r.modified) / DAY;
        let idx = match age_days {
            d if d < 30 => 0,
            d if d < 90 => 1,
            d if d < 365 => 2,
            d if d < 730 => 3,
            _ => 4,
        };
        buckets[idx].count += 1;
        buckets[idx].bytes += r.size;
    }
    buckets.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(id: u64, path: &str, size: u64, modified: i64, is_dir: bool) -> FileRecord {
        let p = Path::new(path);
        FileRecord {
            id,
            path: path.to_string(),
            name: p
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
            ext: if is_dir {
                None
            } else {
                p.extension().map(|e| e.to_string_lossy().to_lowercase())
            },
            size,
            created: modified,
            modified,
            accessed: modified,
            is_dir,
            attributes: 0,
        }
    }

    const NOW: i64 = 1_800_000_000;

    // Forward slashes are valid separators on Windows too; backslash paths
    // would be a single opaque component on unix and break these tests.
    fn fixture() -> Vec<FileRecord> {
        vec![
            rec(0, "/root/docs", 0, NOW, true),
            rec(1, "/root/docs/big.pdf", 5000, NOW - 10 * 86400, false),
            rec(2, "/root/docs/old.pdf", 3000, NOW - 400 * 86400, false),
            rec(3, "/root/cache", 0, NOW, true),
            rec(4, "/root/cache/a.log", 1000, NOW - 50 * 86400, false),
            rec(5, "/root/noext", 200, NOW - 900 * 86400, false),
        ]
    }

    #[test]
    fn top_files_sorted_desc() {
        let recs = fixture();
        let top = top_files(&recs, 2);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].name, "big.pdf");
        assert_eq!(top[1].name, "old.pdf");
    }

    #[test]
    fn top_dirs_cumulative() {
        let recs = fixture();
        let dirs = top_dirs(&recs, "/root", 10);
        let docs = dirs.iter().find(|d| d.path.ends_with("docs")).unwrap();
        assert_eq!(docs.bytes, 8000);
        assert_eq!(docs.files, 2);
        let cache = dirs.iter().find(|d| d.path.ends_with("cache")).unwrap();
        assert_eq!(cache.bytes, 1000);
        // root itself is excluded, loose file has no dir entry
        assert_eq!(dirs.len(), 2);
        // sorted desc
        assert_eq!(dirs[0].path, docs.path);
    }

    #[test]
    fn by_extension_groups_and_sorts() {
        let recs = fixture();
        let exts = by_extension(&recs, 10);
        assert_eq!(exts[0].ext, "pdf");
        assert_eq!(exts[0].count, 2);
        assert_eq!(exts[0].bytes, 8000);
        assert!(exts.iter().any(|e| e.ext == "(none)" && e.bytes == 200));
    }

    #[test]
    fn by_age_buckets() {
        let recs = fixture();
        let ages = by_age(&recs, NOW);
        assert_eq!(ages[0].bytes, 5000); // big.pdf, 10 days old
        assert_eq!(ages[1].bytes, 1000); // a.log, 50 days old
        assert_eq!(ages[3].bytes, 3000); // old.pdf, 400 days old
        assert_eq!(ages[4].bytes, 200); // noext, 900 days old
        assert_eq!(ages[2].bytes, 0);
    }
}
