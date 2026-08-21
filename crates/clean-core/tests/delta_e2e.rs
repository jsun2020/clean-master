//! End-to-end proof of the differential rescan: scan a real directory, save
//! the snapshot with a live USN checkpoint, mutate the tree, ask the real
//! journal what changed, merge - and the result must equal a fresh full scan.
//!
//! On machines without a readable USN journal (non-NTFS temp, exotic CI) the
//! test degrades to a skip with a message rather than a false failure.

#![cfg(windows)]

use clean_core::scan_cache::{self, Snapshot, SnapshotMeta};
use clean_core::scanner::{merge_scan, ScanBackend, ScanOptions, ScanOutcome, WalkBackend};
use clean_core::usn::{self, DeltaVerdict};
use std::fs;
use std::path::Path;

/// Access times may drift between scans; everything else must match exactly.
fn strip_atime(out: &ScanOutcome) -> Vec<(String, u64, i64, bool)> {
    out.records
        .iter()
        .map(|r| (r.path.clone(), r.size, r.modified, r.is_dir))
        .collect()
}

#[test]
fn usn_delta_rescan_matches_full_scan() {
    let tmp = tempfile::tempdir().unwrap();
    // The walker builds paths from the root string while the journal resolves
    // FRNs to long real-cased paths; canonicalize so both speak the same form.
    let canon = fs::canonicalize(tmp.path()).unwrap();
    let root_str = canon.display().to_string();
    let root_str = root_str
        .strip_prefix("\\\\?\\")
        .unwrap_or(&root_str)
        .to_string();
    let root = Path::new(&root_str);

    fs::create_dir_all(root.join("keep").join("deep")).unwrap();
    fs::create_dir_all(root.join("mutate")).unwrap();
    fs::write(root.join("keep").join("stable.txt"), vec![1u8; 100]).unwrap();
    fs::write(
        root.join("keep").join("deep").join("blob.bin"),
        vec![2u8; 555],
    )
    .unwrap();
    fs::write(root.join("mutate").join("grow.log"), vec![3u8; 10]).unwrap();

    // Checkpoint BEFORE the scan so changes racing the scan are re-processed
    // next time instead of lost.
    let Some(cp) = usn::checkpoint_for(root) else {
        eprintln!("SKIP: no readable USN journal for {root_str}");
        return;
    };
    let baseline = WalkBackend
        .scan(root, &ScanOptions::default(), &|_| {})
        .unwrap();

    // Persist + reload through the real cache format, like the app does.
    let cache = root.join("snap.cmsc");
    scan_cache::save(
        &cache,
        &Snapshot {
            meta: SnapshotMeta {
                root: root_str.clone(),
                excludes: vec![],
                created_unix: 0,
                usn: Some(cp),
            },
            outcome: baseline,
        },
    )
    .unwrap();
    let snapshot = scan_cache::load(&cache).expect("snapshot must reload");
    let cp = snapshot
        .meta
        .usn
        .expect("checkpoint must survive the roundtrip");

    // Mutations of every interesting kind.
    fs::write(root.join("mutate").join("grow.log"), vec![9u8; 4096]).unwrap(); // modify
    fs::write(root.join("mutate").join("added.txt"), b"new").unwrap(); // add
    fs::remove_file(root.join("keep").join("stable.txt")).unwrap(); // delete
    let fresh_dir = root.join("mutate").join("fresh").join("sub");
    fs::create_dir_all(&fresh_dir).unwrap(); // new subtree
    fs::write(fresh_dir.join("inner.dat"), vec![7u8; 77]).unwrap();
    fs::rename(
        root.join("keep").join("deep"),
        root.join("keep").join("renamed"),
    )
    .unwrap();

    let dirty = match usn::changed_dirs_since(root, &cp, 10_000) {
        DeltaVerdict::Dirty(d) => d,
        DeltaVerdict::Unavailable(reason) => {
            eprintln!("SKIP: journal delta unavailable ({reason})");
            return;
        }
    };
    // The journal must have flagged the directories we touched. The snapshot
    // cache file itself lives under root, so `root` is dirty too.
    for must in [
        root_str.to_lowercase(),
        root.join("mutate").display().to_string().to_lowercase(),
        root.join("keep").display().to_string().to_lowercase(),
    ] {
        assert!(
            dirty.contains(&must),
            "journal missed dirty dir {must}; got {dirty:?}"
        );
    }

    let (merged, live) = merge_scan(
        root,
        &ScanOptions::default(),
        &snapshot.outcome,
        &dirty,
        &|_| {},
    )
    .unwrap();
    let fresh = WalkBackend
        .scan(root, &ScanOptions::default(), &|_| {})
        .unwrap();
    assert_eq!(
        strip_atime(&merged),
        strip_atime(&fresh),
        "delta rescan must equal a fresh full scan"
    );
    // Sanity that the delta actually took the delta path: some directories
    // were reread live, but not necessarily all of them.
    assert!(live >= 2, "expected live re-enumeration, got {live}");
    let untouched = merged
        .records
        .iter()
        .find(|r| r.name == "blob.bin")
        .expect("renamed-dir content present");
    assert_eq!(untouched.size, 555);
    println!(
        "delta OK: {} dirty dirs volume-filtered to root, {live} live re-enumerations, {} records",
        dirty.len(),
        merged.records.len()
    );
}
