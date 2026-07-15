//! E2E probe: recycle a whole directory then restore it via the undo path,
//! proving developer-artifact cleanup (directory-level) round-trips.
//! Usage: cargo run -p clean-core --example dir_roundtrip -- <dir>

use clean_core::safety::{recycle_files, undo, ActionManifest};

fn count(dir: &std::path::Path) -> usize {
    walkdir(dir)
}
fn walkdir(dir: &std::path::Path) -> usize {
    let mut n = 0;
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                n += walkdir(&p);
            } else {
                n += 1;
            }
        }
    }
    n
}

fn main() {
    let dir = std::env::args().nth(1).expect("usage: dir_roundtrip <dir>");
    let path = std::path::Path::new(&dir);
    let before = count(path);
    println!("before: {before} files, exists={}", path.exists());

    let mut manifest = ActionManifest::new();
    let out = recycle_files(&[(dir.clone(), 0)], &mut manifest, |_| {});
    println!(
        "recycled: deleted={} failed={} exists_now={}",
        out.deleted,
        out.failed.len(),
        path.exists()
    );

    let res = undo(&manifest).expect("undo");
    let after = count(path);
    println!(
        "undo: restored={} missing={} exists={} files={}",
        res.restored,
        res.missing,
        path.exists(),
        after
    );
    println!(
        "RESULT: {}",
        if !path.exists() {
            "FAIL (not restored)"
        } else if after == before {
            "PASS (directory + contents round-tripped)"
        } else {
            "PARTIAL (restored but file count differs)"
        }
    );
}
