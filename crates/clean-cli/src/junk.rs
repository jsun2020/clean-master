use crate::fmt::human_bytes;
use clean_core::rules::{self, RuleReport};
use comfy_table::{presets::UTF8_FULL_CONDENSED, Cell, CellAlignment, Table};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn collect_reports() -> Vec<RuleReport> {
    rules::evaluate_all(&rules::builtin_rules(), now_unix())
}

/// Report what would be (or is about to be) reclaimed, grouped by category.
/// Returns the deletable targets and the rule bases they are authorized under.
///
/// Opt-in rules (`default_apply == false`, e.g. browser history / cookies) are
/// always shown so the user knows they exist, but their files are only
/// returned as targets when `include_optional` is set (`clean junk --all`).
pub fn report(dry: bool, include_optional: bool) -> (Vec<(String, u64)>, Vec<std::path::PathBuf>) {
    if dry {
        println!("Scanning junk locations (dry run - nothing will be deleted)...");
    } else {
        println!("Scanning junk locations...");
    }
    let reports = collect_reports();

    let mut t = Table::new();
    t.load_preset(UTF8_FULL_CONDENSED);
    t.set_header(vec![
        "Category",
        "Rule",
        "Apply",
        "Location",
        "Files",
        "Reclaimable",
    ]);

    let mut total_files = 0usize;
    let mut total_bytes = 0u64;
    let mut skipped_optional = 0usize;
    for r in &reports {
        if r.findings.is_empty() {
            continue;
        }
        let selected = r.rule.default_apply || include_optional;
        let apply_cell = if r.rule.default_apply {
            "default"
        } else if include_optional {
            "opt-in*"
        } else {
            "opt-in"
        };
        if selected {
            total_files += r.findings.len();
            total_bytes += r.bytes;
        } else {
            skipped_optional += r.findings.len();
        }
        t.add_row(vec![
            Cell::new(r.rule.category.label()),
            Cell::new(&r.rule.id),
            Cell::new(apply_cell),
            Cell::new(&r.base),
            Cell::new(r.findings.len()).set_alignment(CellAlignment::Right),
            Cell::new(human_bytes(r.bytes)).set_alignment(CellAlignment::Right),
        ]);
    }

    if total_files == 0 && skipped_optional == 0 {
        println!("No junk found in the known-safe locations. Nice and tidy.");
        return (Vec::new(), Vec::new());
    }
    println!("{t}");
    println!();
    println!(
        "Total reclaimable: {} across {} files.",
        human_bytes(total_bytes),
        total_files
    );
    if skipped_optional > 0 && !include_optional {
        println!(
            "Plus {skipped_optional} files in opt-in privacy-trace rules (not selected). \
             Add --all to include them."
        );
    }
    if dry {
        println!("This was a DRY RUN. Nothing was deleted. Re-run with --apply to clean.");
        println!("Use `clean rules list` to see why each location is considered safe.");
    }

    // Only the selected rules contribute targets and authorized bases.
    let selected_reports = reports
        .iter()
        .filter(|r| r.rule.default_apply || include_optional);
    let bases: Vec<std::path::PathBuf> = selected_reports
        .clone()
        .map(|r| std::path::PathBuf::from(&r.base))
        .collect();
    let targets: Vec<(String, u64)> = selected_reports
        .flat_map(|r| r.findings.iter())
        .map(|f| (f.record.path.clone(), f.record.size))
        .collect();
    (targets, bases)
}

/// `clean rules list`
pub fn list_rules() {
    let mut t = Table::new();
    t.load_preset(UTF8_FULL_CONDENSED);
    t.set_header(vec![
        "Rule",
        "Category",
        "Match",
        "Apply",
        "Min age",
        "Location",
        "Why it is safe",
    ]);
    for rule in rules::builtin_rules() {
        let base = rules::expand_env(&rule.base).unwrap_or_else(|| rule.base.clone());
        let apply = if rule.default_apply {
            "default"
        } else {
            "opt-in"
        };
        t.add_row(vec![
            Cell::new(&rule.id),
            Cell::new(rule.category.label()),
            Cell::new(format!("{:?}", rule.predicate).to_lowercase()),
            Cell::new(apply),
            Cell::new(format!("{}d", rule.min_age_days)),
            Cell::new(base),
            Cell::new(&rule.rationale),
        ]);
    }
    println!("{t}");
    println!("Match: glob = by pattern; zerobyte/brokenshortcut/emptydir = predicate.");
    println!("Apply: default rules run on `clean junk`; opt-in rules need `clean junk --all`.");
}
