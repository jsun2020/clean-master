//! Persisted scan snapshots so a re-analysis does not start from zero.
//!
//! A snapshot is the full record list of one scan plus the USN-journal
//! checkpoint taken just before it. The next scan loads the snapshot, asks
//! the journal which directories changed, and re-enumerates only those
//! (`scanner::merge_scan`); the cached copy also renders instantly in the UI
//! while the refresh runs.
//!
//! Format: hand-rolled little-endian binary, paths prefix-compressed against
//! the previous (sorted) record, blake3-checksummed. Any parse failure -
//! corruption, version bump, truncation - loads as `None`; the caller falls
//! back to a full scan. A cache can slow us down but never lie to us.

use crate::scanner::ScanOutcome;
use crate::types::{FileRecord, SkippedPath};
use crate::usn::UsnCheckpoint;
use std::io::Write;
use std::path::{Path, PathBuf};

const MAGIC: &[u8; 4] = b"CMSC";
const FORMAT_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq)]
pub struct SnapshotMeta {
    /// The scanned root exactly as requested.
    pub root: String,
    /// Exclude globs the scan ran with; a request with different excludes
    /// hashes to a different cache file and never sees this snapshot.
    pub excludes: Vec<String>,
    pub created_unix: i64,
    /// Journal position at scan start; None on non-NTFS / non-Windows.
    pub usn: Option<UsnCheckpoint>,
}

#[derive(Debug)]
pub struct Snapshot {
    pub meta: SnapshotMeta,
    pub outcome: ScanOutcome,
}

/// Stable cache file path for one (root, excludes) request.
pub fn cache_file(dir: &Path, root: &str, excludes: &[String]) -> PathBuf {
    let mut hasher = blake3::Hasher::new();
    hasher.update(root.to_lowercase().as_bytes());
    for e in excludes {
        hasher.update(b"\x00");
        hasher.update(e.as_bytes());
    }
    let hex = hasher.finalize().to_hex();
    dir.join(format!("{}.cmsc", &hex.as_str()[..24]))
}

/// Delete all but the `keep` most recently modified snapshots.
pub fn prune(dir: &Path, keep: usize) {
    let Ok(read) = std::fs::read_dir(dir) else {
        return;
    };
    let mut files: Vec<(std::time::SystemTime, PathBuf)> = read
        .flatten()
        .filter(|e| e.path().extension().is_some_and(|x| x == "cmsc"))
        .filter_map(|e| {
            let t = e.metadata().ok()?.modified().ok()?;
            Some((t, e.path()))
        })
        .collect();
    files.sort_by_key(|(t, _)| std::cmp::Reverse(*t));
    for (_, path) in files.into_iter().skip(keep) {
        let _ = std::fs::remove_file(path);
    }
}

// -------------------------------------------------------------- writing --

fn put_str(buf: &mut Vec<u8>, s: &str) {
    buf.extend_from_slice(&(s.len() as u32).to_le_bytes());
    buf.extend_from_slice(s.as_bytes());
}

/// UTF-8-safe length of the common prefix of two strings, capped at u16.
fn common_prefix(a: &str, b: &str) -> usize {
    let max = a.len().min(b.len()).min(u16::MAX as usize);
    let mut n = a
        .as_bytes()
        .iter()
        .zip(b.as_bytes())
        .take(max)
        .take_while(|(x, y)| x == y)
        .count();
    while n > 0 && !b.is_char_boundary(n) {
        n -= 1;
    }
    n
}

pub fn save(path: &Path, snap: &Snapshot) -> std::io::Result<()> {
    let mut payload: Vec<u8> = Vec::with_capacity(64 * snap.outcome.records.len() + 1024);
    put_str(&mut payload, &snap.meta.root);
    payload.extend_from_slice(&(snap.meta.excludes.len() as u32).to_le_bytes());
    for e in &snap.meta.excludes {
        put_str(&mut payload, e);
    }
    payload.extend_from_slice(&snap.meta.created_unix.to_le_bytes());
    match &snap.meta.usn {
        Some(cp) => {
            payload.push(1);
            payload.extend_from_slice(&cp.journal_id.to_le_bytes());
            payload.extend_from_slice(&cp.next_usn.to_le_bytes());
            payload.extend_from_slice(&cp.volume_serial.to_le_bytes());
        }
        None => payload.push(0),
    }

    payload.extend_from_slice(&(snap.outcome.records.len() as u64).to_le_bytes());
    let mut prev = "";
    for r in &snap.outcome.records {
        let shared = common_prefix(prev, &r.path);
        let rest = &r.path[shared..];
        payload.extend_from_slice(&(shared as u16).to_le_bytes());
        put_str(&mut payload, rest);
        payload.extend_from_slice(&r.size.to_le_bytes());
        payload.extend_from_slice(&r.created.to_le_bytes());
        payload.extend_from_slice(&r.modified.to_le_bytes());
        payload.extend_from_slice(&r.accessed.to_le_bytes());
        payload.push(u8::from(r.is_dir));
        payload.extend_from_slice(&r.attributes.to_le_bytes());
        prev = &r.path;
    }

    payload.extend_from_slice(&(snap.outcome.skipped.len() as u32).to_le_bytes());
    for s in &snap.outcome.skipped {
        put_str(&mut payload, &s.path);
        put_str(&mut payload, &s.reason);
    }

    let hash = blake3::hash(&payload);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    // Write-then-rename so a crash mid-save cannot leave a torn cache under
    // the real name (a torn file would just load as None, but why risk it).
    let tmp = path.with_extension("cmsc.tmp");
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(MAGIC)?;
        f.write_all(&FORMAT_VERSION.to_le_bytes())?;
        f.write_all(hash.as_bytes())?;
        f.write_all(&payload)?;
        f.flush()?;
    }
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(_) => {
            // Windows rename does not replace an existing file atomically in
            // every case; fall back to remove + rename.
            let _ = std::fs::remove_file(path);
            std::fs::rename(&tmp, path)
        }
    }
}

// -------------------------------------------------------------- reading --

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        if end > self.buf.len() {
            return None;
        }
        let out = &self.buf[self.pos..end];
        self.pos = end;
        Some(out)
    }
    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes(self.take(2)?.try_into().ok()?))
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }
    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }
    fn i64(&mut self) -> Option<i64> {
        Some(i64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }
    fn str(&mut self) -> Option<String> {
        let len = self.u32()? as usize;
        std::str::from_utf8(self.take(len)?)
            .ok()
            .map(str::to_string)
    }
}

/// Recompute the name/ext fields the walker derives at scan time. Both use
/// the same lossy path string, so the round trip is exact.
fn derive_name_ext(path: &str, is_dir: bool) -> (String, Option<String>) {
    let p = Path::new(path);
    let name = p
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_string());
    let ext = if is_dir {
        None
    } else {
        p.extension().map(|e| e.to_string_lossy().to_lowercase())
    };
    (name, ext)
}

pub fn load(path: &Path) -> Option<Snapshot> {
    let data = std::fs::read(path).ok()?;
    if data.len() < 40 || &data[0..4] != MAGIC {
        return None;
    }
    if u32::from_le_bytes(data[4..8].try_into().ok()?) != FORMAT_VERSION {
        return None;
    }
    let stored_hash: [u8; 32] = data[8..40].try_into().ok()?;
    let payload = &data[40..];
    if blake3::hash(payload).as_bytes() != &stored_hash {
        return None;
    }

    let mut r = Reader {
        buf: payload,
        pos: 0,
    };
    let root = r.str()?;
    let n_excl = r.u32()? as usize;
    let mut excludes = Vec::with_capacity(n_excl.min(1024));
    for _ in 0..n_excl {
        excludes.push(r.str()?);
    }
    let created_unix = r.i64()?;
    let usn = match r.u8()? {
        1 => Some(UsnCheckpoint {
            journal_id: r.u64()?,
            next_usn: r.i64()?,
            volume_serial: r.u32()?,
        }),
        0 => None,
        _ => return None,
    };

    let n_records = r.u64()? as usize;
    let mut records: Vec<FileRecord> = Vec::with_capacity(n_records.min(4_000_000));
    let mut prev = String::new();
    for i in 0..n_records {
        let shared = r.u16()? as usize;
        if shared > prev.len() || !prev.is_char_boundary(shared) {
            return None;
        }
        let rest = r.str()?;
        let mut path = String::with_capacity(shared + rest.len());
        path.push_str(&prev[..shared]);
        path.push_str(&rest);
        let size = r.u64()?;
        let created = r.i64()?;
        let modified = r.i64()?;
        let accessed = r.i64()?;
        let is_dir = match r.u8()? {
            0 => false,
            1 => true,
            _ => return None,
        };
        let attributes = r.u32()?;
        let (name, ext) = derive_name_ext(&path, is_dir);
        prev = path.clone();
        records.push(FileRecord {
            id: i as u64,
            path,
            name,
            ext,
            size,
            created,
            modified,
            accessed,
            is_dir,
            attributes,
        });
    }

    let n_skipped = r.u32()? as usize;
    let mut skipped = Vec::with_capacity(n_skipped.min(100_000));
    for _ in 0..n_skipped {
        skipped.push(SkippedPath {
            path: r.str()?,
            reason: r.str()?,
        });
    }
    if r.pos != payload.len() {
        return None;
    }

    Some(Snapshot {
        meta: SnapshotMeta {
            root,
            excludes,
            created_unix,
            usn,
        },
        outcome: ScanOutcome { records, skipped },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::{ScanBackend, ScanOptions, WalkBackend};
    use std::fs;

    fn fixture_scan() -> (tempfile::TempDir, ScanOutcome) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::create_dir_all(root.join("docs").join("嵌套目录")).unwrap();
        fs::create_dir_all(root.join("empty")).unwrap();
        fs::write(root.join("a.txt"), b"hello").unwrap();
        fs::write(root.join("docs").join("Report.PDF"), vec![0u8; 1024]).unwrap();
        fs::write(
            root.join("docs").join("嵌套目录").join("中文文件.log"),
            vec![1u8; 77],
        )
        .unwrap();
        fs::write(root.join("noext"), b"x").unwrap();
        let out = WalkBackend
            .scan(root, &ScanOptions::default(), &|_| {})
            .unwrap();
        (dir, out)
    }

    fn snap(outcome: ScanOutcome, root: &str) -> Snapshot {
        Snapshot {
            meta: SnapshotMeta {
                root: root.to_string(),
                excludes: vec!["*.tmp".into()],
                created_unix: 1_755_700_000,
                usn: Some(UsnCheckpoint {
                    journal_id: 0x0123_4567_89AB_CDEF,
                    next_usn: 42_000_000_007,
                    volume_serial: 0xCAFE_F00D,
                }),
            },
            outcome,
        }
    }

    #[test]
    fn roundtrip_is_exact() {
        let (dir, out) = fixture_scan();
        let mut with_skips = out;
        with_skips.skipped.push(SkippedPath {
            path: "C:\\locked".into(),
            reason: "Access is denied. (os error 5)".into(),
        });
        let s = snap(with_skips, &dir.path().display().to_string());
        let file = dir.path().join("snap.cmsc");
        save(&file, &s).unwrap();
        let loaded = load(&file).expect("snapshot must load");
        assert_eq!(loaded.meta, s.meta);
        assert_eq!(loaded.outcome.records, s.outcome.records);
        assert_eq!(loaded.outcome.skipped.len(), 1);
        assert_eq!(loaded.outcome.skipped[0].path, "C:\\locked");
    }

    #[test]
    fn roundtrip_without_usn_checkpoint() {
        let (dir, out) = fixture_scan();
        let mut s = snap(out, "r");
        s.meta.usn = None;
        let file = dir.path().join("snap.cmsc");
        save(&file, &s).unwrap();
        assert_eq!(load(&file).unwrap().meta.usn, None);
    }

    #[test]
    fn corrupt_payload_loads_as_none() {
        let (dir, out) = fixture_scan();
        let s = snap(out, "r");
        let file = dir.path().join("snap.cmsc");
        save(&file, &s).unwrap();
        let mut bytes = fs::read(&file).unwrap();
        let mid = 40 + (bytes.len() - 40) / 2;
        bytes[mid] ^= 0xFF;
        fs::write(&file, bytes).unwrap();
        assert!(load(&file).is_none(), "corrupt snapshot must not load");
    }

    #[test]
    fn truncated_file_loads_as_none() {
        let (dir, out) = fixture_scan();
        let s = snap(out, "r");
        let file = dir.path().join("snap.cmsc");
        save(&file, &s).unwrap();
        let bytes = fs::read(&file).unwrap();
        fs::write(&file, &bytes[..bytes.len() - 9]).unwrap();
        assert!(load(&file).is_none());
    }

    #[test]
    fn future_format_version_loads_as_none() {
        let (dir, out) = fixture_scan();
        let s = snap(out, "r");
        let file = dir.path().join("snap.cmsc");
        save(&file, &s).unwrap();
        let mut bytes = fs::read(&file).unwrap();
        bytes[4] = 99;
        fs::write(&file, bytes).unwrap();
        assert!(load(&file).is_none());
    }

    #[test]
    fn cache_file_keyed_by_root_and_excludes() {
        let d = Path::new("cache");
        let a = cache_file(d, "C:\\Users\\x", &[]);
        let b = cache_file(d, "C:\\Users\\y", &[]);
        let c = cache_file(d, "C:\\Users\\x", &["*.log".into()]);
        let a2 = cache_file(d, "c:\\users\\X", &[]);
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_eq!(a, a2, "root casing must not fragment the cache");
    }

    #[test]
    fn prune_keeps_newest() {
        let dir = tempfile::tempdir().unwrap();
        for (i, age) in [("a", 300), ("b", 200), ("c", 100)] {
            let p = dir.path().join(format!("{i}.cmsc"));
            fs::write(&p, b"x").unwrap();
            let t = std::time::SystemTime::now() - std::time::Duration::from_secs(age);
            let f = fs::OpenOptions::new().write(true).open(&p).unwrap();
            f.set_modified(t).unwrap();
        }
        prune(dir.path(), 2);
        assert!(!dir.path().join("a.cmsc").exists(), "oldest must be pruned");
        assert!(dir.path().join("b.cmsc").exists());
        assert!(dir.path().join("c.cmsc").exists());
    }

    #[test]
    fn save_overwrites_existing_snapshot() {
        let (dir, out) = fixture_scan();
        let file = dir.path().join("snap.cmsc");
        let s1 = snap(out, "first");
        save(&file, &s1).unwrap();
        let (_dir2, out2) = fixture_scan();
        let s2 = snap(out2, "second");
        save(&file, &s2).unwrap();
        assert_eq!(load(&file).unwrap().meta.root, "second");
    }
}
