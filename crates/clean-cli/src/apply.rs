use crate::fmt::human_bytes;
use clean_core::safety::{self, ActionManifest};
use indicatif::{ProgressBar, ProgressStyle};
use std::io::Write;
use std::path::Path;

/// Typed confirmation gate. `--yes` skips it (documented for scripting);
/// dry-run remains the default at the command level regardless.
pub fn confirm(summary: &str, skip: bool) -> bool {
    if skip {
        return true;
    }
    print!("{summary}\nType 'yes' to move these files to the Recycle Bin (anything else aborts): ");
    std::io::stdout().flush().ok();
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        return false;
    }
    line.trim().eq_ignore_ascii_case("yes")
}

/// Recycle `targets`, write the undo manifest, report the outcome.
pub fn apply(targets: Vec<(String, u64)>, yes: bool) -> Result<(), String> {
    if targets.is_empty() {
        println!("Nothing to delete.");
        return Ok(());
    }
    let total_bytes: u64 = targets.iter().map(|(_, s)| s).sum();
    let summary = format!(
        "About to move {} files ({}) to the Recycle Bin.",
        targets.len(),
        human_bytes(total_bytes)
    );
    if !confirm(&summary, yes) {
        println!("Aborted. Nothing was deleted.");
        return Ok(());
    }

    let bar = ProgressBar::new(targets.len() as u64);
    bar.set_style(
        ProgressStyle::with_template("{bar:30} {pos}/{len} recycling...").expect("valid template"),
    );
    let mut manifest = ActionManifest::new();
    let outcome = safety::recycle_files(&targets, &mut manifest, |done| {
        bar.set_position(done as u64);
    });
    bar.finish_and_clear();

    let manifest_path = if manifest.actions.is_empty() {
        None
    } else {
        Some(
            manifest
                .save(Path::new("."))
                .map_err(|e| format!("files were recycled but the undo manifest could not be written: {e}"))?,
        )
    };

    println!(
        "Moved {} files ({}) to the Recycle Bin.",
        outcome.deleted,
        human_bytes(outcome.bytes)
    );
    if !outcome.failed.is_empty() {
        println!(
            "Skipped {} files that could not be deleted (in use or already gone):",
            outcome.failed.len()
        );
        for (path, reason) in outcome.failed.iter().take(10) {
            println!("  {path}: {reason}");
        }
        if outcome.failed.len() > 10 {
            println!("  ... and {} more", outcome.failed.len() - 10);
        }
    }
    if let Some(p) = manifest_path {
        println!("Undo manifest: {}", p.display());
        println!("Run `clean undo` to restore everything from this session.");
    }
    Ok(())
}
