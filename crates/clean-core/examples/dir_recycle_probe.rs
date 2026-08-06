//! Why does recycling an artifact dir take minutes? Times trash::delete(dir)
//! vs std::fs::remove_dir_all(dir) on a synthetic node_modules-like tree
//! (many tiny files) built in %TEMP%. Self-cleaning: purges its own items
//! from the Recycle Bin afterwards. Measured on the dev machine (V0.6.3):
//! recycle 947 files/s vs permanent 2,302 files/s - the shell processes
//! every file inside a recycled folder individually.
use std::fs;
use std::path::Path;
use std::time::Instant;

fn build_tree(root: &Path, dirs: usize, files_per_dir: usize) -> usize {
    let mut n = 0;
    for d in 0..dirs {
        let sub = root.join(format!("pkg{d}")).join("lib");
        fs::create_dir_all(&sub).unwrap();
        for f in 0..files_per_dir {
            fs::write(sub.join(format!("m{f}.js")), b"module.exports = 1;\n").unwrap();
            n += 1;
        }
    }
    n
}

fn main() {
    let base = std::env::temp_dir().join("cm_dir_probe");
    let _ = fs::remove_dir_all(&base);

    // Probe A: recycle the whole dir in one trash::delete call.
    let a = base.join("recycle_me");
    let n = build_tree(&a, 60, 100); // 6,000 tiny files
    let t = Instant::now();
    trash::delete(&a).expect("recycle failed");
    let recycle_s = t.elapsed().as_secs_f64();
    println!(
        "recycle  {n} files: {recycle_s:.1}s ({:.0} files/s)",
        n as f64 / recycle_s
    );

    // Probe B: permanent remove_dir_all on an identical tree.
    let b = base.join("delete_me");
    let n2 = build_tree(&b, 60, 100);
    let t = Instant::now();
    fs::remove_dir_all(&b).expect("remove_dir_all failed");
    let del_s = t.elapsed().as_secs_f64();
    println!(
        "perm-del {n2} files: {del_s:.1}s ({:.0} files/s)",
        n2 as f64 / del_s
    );
    println!("ratio: recycle is {:.0}x slower", recycle_s / del_s);

    // Clean the recycled copy back out of the bin (match by original path).
    #[cfg(windows)]
    {
        let items: Vec<_> = trash::os_limited::list()
            .unwrap_or_default()
            .into_iter()
            .filter(|i| i.original_path().starts_with(&base))
            .collect();
        if !items.is_empty() {
            let _ = trash::os_limited::purge_all(items);
            println!("bin cleaned");
        }
    }
    let _ = fs::remove_dir_all(&base);
}
