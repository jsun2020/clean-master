use crate::error::CoreError;
use crate::scanner::{ScanBackend, ScanOptions, WalkBackend};
use crate::types::FileRecord;
use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Embedded rule packs. A rule ships only if its target is regenerable
/// (caches, temp, thumbnails) or debugging leftovers (dumps, reports).
const WINDOWS_PACK: &str = include_str!("../rules/windows.json");
const MACOS_PACK: &str = include_str!("../rules/macos.json");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JunkCategory {
    Temp,
    Cache,
    Logs,
    Dumps,
    UpdateLeftover,
    /// Privacy traces: recent-file lists, jump lists, and (opt-in) browser
    /// history / cookies. Wopti-inspired; see `default_apply` for the safe
    /// default split.
    Trace,
    /// Shortcuts (`.lnk`) whose target no longer exists.
    BrokenShortcut,
    /// Directories left with no files or subdirectories.
    EmptyFolder,
    /// Miscellaneous leftovers (e.g. zero-byte files).
    Leftover,
}

impl JunkCategory {
    pub fn label(&self) -> &'static str {
        match self {
            JunkCategory::Temp => "Temporary files",
            JunkCategory::Cache => "Caches",
            JunkCategory::Logs => "Log files",
            JunkCategory::Dumps => "Crash dumps & error reports",
            JunkCategory::UpdateLeftover => "Update leftovers",
            JunkCategory::Trace => "Privacy traces",
            JunkCategory::BrokenShortcut => "Broken shortcuts",
            JunkCategory::EmptyFolder => "Empty folders",
            JunkCategory::Leftover => "Leftovers",
        }
    }
}

/// How a rule decides whether a scanned entry is junk. `Glob` (the default)
/// keeps the original behavior: match files by the include globs. The others
/// add a predicate on top of the include match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchPredicate {
    /// Include-glob match on files (original behavior).
    #[default]
    Glob,
    /// File whose size is exactly 0 bytes (and matches the include globs).
    ZeroByte,
    /// `.lnk` shortcut whose resolved local target no longer exists.
    BrokenShortcut,
    /// Directory that contains no files and no subdirectories.
    EmptyDir,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskTier {
    /// Regenerable or purely historical data. Only this tier is deletable in MVP.
    Safe,
    /// Reserved for V2 (e.g. old Downloads); never auto-applied.
    Moderate,
}

#[derive(Debug, Clone, Deserialize)]
pub struct JunkRule {
    pub id: String,
    pub category: JunkCategory,
    pub risk: RiskTier,
    pub rationale: String,
    /// Base directory containing %ENVVAR% placeholders. A rule can never
    /// match a path outside its expanded base.
    pub base: String,
    /// Globs relative to base (case-insensitive, `/` separators).
    pub include: Vec<String>,
    /// Files modified within the last N days are never flagged.
    #[serde(default)]
    pub min_age_days: u32,
    /// How entries are matched. Defaults to `Glob` (files by include globs).
    #[serde(default)]
    pub predicate: MatchPredicate,
    /// Whether this rule is applied by default. `false` marks a rule the user
    /// must opt into (e.g. browser history / cookies, which log you out):
    /// the CLI skips it unless `--all` is passed, and the GUI leaves it
    /// unchecked. Defaults to `true`.
    #[serde(default = "default_true")]
    pub default_apply: bool,
}

#[derive(Debug, Deserialize)]
pub struct RulePack {
    pub pack: String,
    pub rules: Vec<JunkRule>,
}

#[derive(Debug, Clone)]
pub struct JunkFinding {
    pub record: FileRecord,
    pub rule_id: String,
    pub category: JunkCategory,
    pub risk: RiskTier,
}

fn parse_pack(json: &str) -> Vec<JunkRule> {
    let pack: RulePack = serde_json::from_str(json).expect("embedded rule pack must parse");
    pack.rules
}

/// Rules for the OS this binary was built for. Other platforms get an
/// empty set (junk scan finds nothing rather than guessing at paths).
pub fn builtin_rules() -> Vec<JunkRule> {
    if cfg!(windows) {
        parse_pack(WINDOWS_PACK)
    } else if cfg!(target_os = "macos") {
        parse_pack(MACOS_PACK)
    } else {
        Vec::new()
    }
}

/// Expand %VAR% placeholders from the environment.
/// Returns None when a referenced variable is not set (rule is skipped).
pub fn expand_env(input: &str) -> Option<String> {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        let end = after.find('%')?;
        let var = &after[..end];
        out.push_str(&std::env::var(var).ok()?);
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Some(out)
}

fn build_include_set(rule: &JunkRule) -> Result<GlobSet, CoreError> {
    let mut builder = GlobSetBuilder::new();
    for pattern in &rule.include {
        let glob = GlobBuilder::new(pattern)
            .case_insensitive(true)
            .literal_separator(true)
            .build()
            .map_err(|e| CoreError::InvalidPattern {
                pattern: pattern.clone(),
                message: format!("rule {}: {e}", rule.id),
            })?;
        builder.add(glob);
    }
    builder.build().map_err(|e| CoreError::InvalidPattern {
        pattern: rule.include.join(", "),
        message: format!("rule {}: {e}", rule.id),
    })
}

/// Pure evaluation of one rule against already-scanned records under `base`.
/// Only files (never directories) are flagged; matching is on the path
/// relative to base; recently-modified files are excluded per rule.
pub fn evaluate_records(
    rule: &JunkRule,
    base: &Path,
    records: &[FileRecord],
    now_unix: i64,
) -> Result<Vec<JunkFinding>, CoreError> {
    let include = build_include_set(rule)?;
    let min_age_secs = rule.min_age_days as i64 * 86_400;
    // Only the EmptyDir predicate needs to know which directories have
    // children; compute it once and only when required.
    let dirs_with_children = if rule.predicate == MatchPredicate::EmptyDir {
        let mut set = std::collections::HashSet::new();
        for r in records {
            if let Some(parent) = Path::new(&r.path).parent() {
                set.insert(parent.to_path_buf());
            }
        }
        Some(set)
    } else {
        None
    };

    let mut findings = Vec::new();
    for r in records {
        // Directories are candidates only for EmptyDir; every other predicate
        // works on files (the original safety invariant).
        let wants_dir = rule.predicate == MatchPredicate::EmptyDir;
        if r.is_dir != wants_dir {
            continue;
        }
        let path = Path::new(&r.path);
        let rel = match path.strip_prefix(base) {
            Ok(rel) => rel,
            Err(_) => continue, // outside base: never flag (safety invariant)
        };
        if !include.is_match(rel) {
            continue;
        }
        // Freshness guard applies to every predicate.
        if now_unix - r.modified < min_age_secs {
            continue;
        }
        let matches = match rule.predicate {
            MatchPredicate::Glob => true,
            MatchPredicate::ZeroByte => r.size == 0,
            MatchPredicate::BrokenShortcut => is_broken_shortcut(path),
            MatchPredicate::EmptyDir => {
                // Never flag the base directory itself, and only a directory
                // that has no scanned children (a true empty leaf).
                path != base
                    && dirs_with_children
                        .as_ref()
                        .map(|s| !s.contains(path))
                        .unwrap_or(false)
            }
        };
        if !matches {
            continue;
        }
        findings.push(JunkFinding {
            record: r.clone(),
            rule_id: rule.id.clone(),
            category: rule.category,
            risk: rule.risk,
        });
    }
    Ok(findings)
}

/// True only when `path` is a `.lnk` whose local target was resolved and does
/// not exist. Unreadable files and shortcuts whose target cannot be resolved
/// are treated as not-broken (never flagged) - broken means "confidently
/// points at a missing local file".
fn is_broken_shortcut(path: &Path) -> bool {
    let Ok(bytes) = std::fs::read(path) else {
        return false;
    };
    match crate::shortcut::local_target_path(&bytes) {
        Some(target) => !Path::new(&target).exists(),
        None => false,
    }
}

pub struct RuleReport {
    pub rule: JunkRule,
    pub base: String,
    pub findings: Vec<JunkFinding>,
    pub bytes: u64,
}

/// Scan each rule's base directory and evaluate. Missing bases (app not
/// installed) and unreadable subtrees are skipped silently by design.
pub fn evaluate_all(rules: &[JunkRule], now_unix: i64) -> Vec<RuleReport> {
    evaluate_all_with_progress(rules, now_unix, &|_, _| {})
}

/// Same as `evaluate_all`, reporting `(rule_id, entries_seen)` while each
/// rule's base is being scanned (for UI progress display).
pub fn evaluate_all_with_progress(
    rules: &[JunkRule],
    now_unix: i64,
    progress: &(dyn Fn(&str, u64) + Sync),
) -> Vec<RuleReport> {
    let mut reports = Vec::new();
    for rule in rules {
        let Some(base) = expand_env(&rule.base) else {
            continue;
        };
        let base_path = Path::new(&base);
        if !base_path.is_dir() {
            continue;
        }
        let Ok(outcome) = WalkBackend.scan(base_path, &ScanOptions::default(), &|seen| {
            progress(&rule.id, seen)
        }) else {
            continue;
        };
        let Ok(findings) = evaluate_records(rule, base_path, &outcome.records, now_unix) else {
            continue;
        };
        let bytes = findings.iter().map(|f| f.record.size).sum();
        reports.push(RuleReport {
            rule: rule.clone(),
            base,
            findings,
            bytes,
        });
    }
    reports
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::{ScanBackend, ScanOptions, WalkBackend};
    use std::fs;

    const NOW: i64 = 1_800_000_000;

    fn rule(include: &[&str], min_age_days: u32) -> JunkRule {
        rule_pred(include, min_age_days, MatchPredicate::Glob)
    }

    fn rule_pred(include: &[&str], min_age_days: u32, predicate: MatchPredicate) -> JunkRule {
        JunkRule {
            id: "test.rule".into(),
            category: JunkCategory::Temp,
            risk: RiskTier::Safe,
            rationale: "test".into(),
            base: "unused".into(),
            include: include.iter().map(|s| s.to_string()).collect(),
            min_age_days,
            predicate,
            default_apply: true,
        }
    }

    fn scan_records(root: &Path) -> Vec<FileRecord> {
        WalkBackend
            .scan(root, &ScanOptions::default(), &|_| {})
            .unwrap()
            .records
    }

    #[test]
    fn builtin_pack_parses_and_is_safe_tier_only() {
        // The active pack for this build target.
        let rules = builtin_rules();
        assert!(rules.len() >= 5);
        assert!(rules.iter().all(|r| r.risk == RiskTier::Safe));
        assert!(rules.iter().all(|r| !r.include.is_empty()));
    }

    #[test]
    fn all_embedded_packs_parse_and_bases_never_nest() {
        // Validate every shipped pack on every platform, not just the
        // active one, so a bad pack cannot slip through CI on the other OS.
        for (name, json, min_rules) in [("windows", WINDOWS_PACK, 8), ("macos", MACOS_PACK, 5)] {
            let rules = parse_pack(json);
            assert!(rules.len() >= min_rules, "{name}: too few rules");
            assert!(rules.iter().all(|r| r.risk == RiskTier::Safe), "{name}");
            assert!(rules.iter().all(|r| !r.include.is_empty()), "{name}");
            // One rule's base nested inside another's would double-count
            // the same files in per-rule totals.
            for a in &rules {
                for b in &rules {
                    if a.id == b.id {
                        continue;
                    }
                    let prefix_slash = format!("{}/", b.base);
                    let prefix_bslash = format!("{}\\", b.base);
                    assert!(
                        !a.base.starts_with(&prefix_slash) && !a.base.starts_with(&prefix_bslash),
                        "{name}: base of {} nests inside base of {}",
                        a.id,
                        b.id
                    );
                }
            }
        }
    }

    #[test]
    fn matches_only_inside_base_and_pattern() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("profile");
        fs::create_dir_all(base.join("Cache").join("data")).unwrap();
        fs::create_dir_all(base.join("Documents")).unwrap();
        fs::write(
            base.join("Cache").join("data").join("f_0001"),
            vec![0u8; 100],
        )
        .unwrap();
        fs::write(base.join("Documents").join("thesis.docx"), vec![0u8; 100]).unwrap();

        let records = scan_records(&base);
        // File modified "now" but min_age 0 allows it.
        let findings =
            evaluate_records(&rule(&["Cache/**"], 0), &base, &records, NOW + 10 * 86_400).unwrap();
        assert_eq!(findings.len(), 1);
        assert!(findings[0].record.path.ends_with("f_0001"));
    }

    #[test]
    fn min_age_excludes_fresh_files() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();
        fs::write(base.join("fresh.tmp"), b"x").unwrap();
        let records = scan_records(base);
        let now = records[0].modified; // same second as file mtime
        let findings = evaluate_records(&rule(&["**"], 1), base, &records, now).unwrap();
        assert!(findings.is_empty());
        // 2 days later the same file is eligible
        let findings =
            evaluate_records(&rule(&["**"], 1), base, &records, now + 2 * 86_400).unwrap();
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn directories_are_never_flagged() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("sub")).unwrap();
        fs::write(dir.path().join("sub").join("a.tmp"), b"x").unwrap();
        let records = scan_records(dir.path());
        let findings = evaluate_records(&rule(&["**"], 0), dir.path(), &records, NOW * 2).unwrap();
        assert!(findings.iter().all(|f| !f.record.is_dir));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn records_outside_base_never_match() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.tmp"), b"x").unwrap();
        let records = scan_records(dir.path());
        // Evaluate against a DIFFERENT base: nothing may match.
        let other = dir.path().join("other-base");
        let findings = evaluate_records(&rule(&["**"], 0), &other, &records, NOW * 2).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn zero_byte_predicate_flags_only_empty_files() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();
        fs::write(base.join("empty.dat"), b"").unwrap();
        fs::write(base.join("full.dat"), b"content").unwrap();
        let records = scan_records(base);
        let findings = evaluate_records(
            &rule_pred(&["**"], 0, MatchPredicate::ZeroByte),
            base,
            &records,
            NOW,
        )
        .unwrap();
        assert_eq!(findings.len(), 1);
        assert!(findings[0].record.path.ends_with("empty.dat"));
    }

    #[test]
    fn empty_dir_predicate_flags_only_childless_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();
        fs::create_dir_all(base.join("empty")).unwrap();
        fs::create_dir_all(base.join("full")).unwrap();
        fs::write(base.join("full").join("a.txt"), b"x").unwrap();
        // A directory whose only child is another (empty) directory is NOT a
        // leaf, so it is not flagged this pass - only the true leaf is.
        fs::create_dir_all(base.join("outer").join("inner")).unwrap();
        let records = scan_records(base);
        let findings = evaluate_records(
            &rule_pred(&["**"], 0, MatchPredicate::EmptyDir),
            base,
            &records,
            NOW,
        )
        .unwrap();
        let flagged: Vec<_> = findings.iter().map(|f| f.record.name.clone()).collect();
        assert!(flagged.contains(&"empty".to_string()));
        assert!(flagged.contains(&"inner".to_string()));
        assert!(!flagged.contains(&"full".to_string()));
        assert!(!flagged.contains(&"outer".to_string()));
        // The base directory itself is never flagged.
        assert!(findings.iter().all(|f| Path::new(&f.record.path) != base));
    }

    #[test]
    fn broken_shortcut_predicate_needs_missing_target() {
        // Only exercises the non-.lnk fast path here (real .lnk parsing is
        // unit-tested in the shortcut module); a plain file is never broken.
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();
        fs::write(base.join("notreally.lnk"), b"not a real shortcut").unwrap();
        let records = scan_records(base);
        let findings = evaluate_records(
            &rule_pred(&["**/*.lnk"], 0, MatchPredicate::BrokenShortcut),
            base,
            &records,
            NOW,
        )
        .unwrap();
        // Unparseable .lnk -> treated as not-broken (safe), so nothing flagged.
        assert!(findings.is_empty());
    }

    #[test]
    fn expand_env_replaces_variables() {
        std::env::set_var("CLEAN_TEST_VAR", "value123");
        assert_eq!(
            expand_env("pre\\%CLEAN_TEST_VAR%\\post").as_deref(),
            Some("pre\\value123\\post")
        );
        assert_eq!(expand_env("no vars here").as_deref(), Some("no vars here"));
        assert!(expand_env("%CLEAN_TEST_UNSET_VAR_XYZ%").is_none());
    }
}
