//! Manual probe: time batched recycle_files against the REAL Recycle Bin,
//! with one file held open (no FILE_SHARE_DELETE) to prove the failed-batch
//! fallback still recycles the rest and names the locked file.
//! Self-cleaning: purges its own items from the bin afterward (Windows).
//!
//!     cargo run --release -p clean-core --example recycle_bench [n_files]

use clean_core::safety::{recycle_files, ActionManifest};
use std::time::Instant;

fn main() {
    let n: usize = std::env::args()
        .nth(1)
        .and_then(|a| a.parse().ok())
        .unwrap_or(2000);
    let dir = std::env::temp_dir().join(format!("clean-recycle-bench-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create bench dir");

    let mut paths: Vec<(String, u64)> = Vec::with_capacity(n);
    for i in 0..n {
        let p = dir.join(format!("bench-{i:05}.tmp"));
        std::fs::write(&p, b"bench").expect("write bench file");
        paths.push((p.display().to_string(), 5));
    }

    // Hold the first file open the way Chromium apps hold %TEMP% files:
    // readable, writable, but no FILE_SHARE_DELETE.
    #[cfg(windows)]
    let _guard = {
        use std::os::windows::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0x1 | 0x2)
            .open(&paths[0].0)
            .expect("lock first file")
    };

    let mut manifest = ActionManifest::new();
    let start = Instant::now();
    let out = recycle_files(&paths, &mut manifest, |done| {
        if done % 1000 == 0 {
            println!("  progress {done}/{n}");
        }
    });
    let elapsed = start.elapsed();
    println!(
        "recycled {} / {} files in {:.2}s ({:.1} files/s), {} failed",
        out.deleted,
        n,
        elapsed.as_secs_f64(),
        out.deleted as f64 / elapsed.as_secs_f64().max(0.001),
        out.failed.len()
    );
    for (p, why) in out.failed.iter().take(3) {
        println!("  failed: {p}: {why}");
    }

    // Clean up: purge our bench items from the bin, then remove the dir.
    #[cfg(windows)]
    {
        drop(_guard);
        let marker = dir.display().to_string().to_lowercase();
        match trash::os_limited::list() {
            Ok(items) => {
                let ours: Vec<_> = items
                    .into_iter()
                    .filter(|i| {
                        i.original_path()
                            .display()
                            .to_string()
                            .to_lowercase()
                            .starts_with(&marker)
                    })
                    .collect();
                let count = ours.len();
                match trash::os_limited::purge_all(ours) {
                    Ok(()) => println!("purged {count} bench items from the bin"),
                    Err(e) => println!("purge failed (clean the bin by hand): {e}"),
                }
            }
            Err(e) => println!("cannot list bin for cleanup: {e}"),
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}
