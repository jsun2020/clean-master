//! Clean Master - desktop GUI over the clean-core engine.
//!
//! Safety contract (prd.md section 7) is enforced HERE, not in the webview:
//! the UI selects rule ids / group indexes, and every deletion target is
//! re-derived from server-side state and passed through `deletion_allowed`.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use clean_core::appscan::{scan_installed_apps, AppRemoval, InstalledApp};
use clean_core::devscan::scan_projects;
use clean_core::dupes::{find_duplicates, DupeGroup, DupeOptions};
use clean_core::report;
use clean_core::rules::{builtin_rules, evaluate_all_with_progress};
use clean_core::safety::{
    delete_dirs_permanently, delete_files_permanently, deletion_allowed, recycle_files,
    ActionManifest, Disposition,
};
use clean_core::scan_cache::{self, Snapshot, SnapshotMeta};
use clean_core::scanner::{merge_scan, ScanBackend, ScanOptions, ScanOutcome, WalkBackend};
use clean_core::startup::{self, StartupEntry};
use clean_core::toolbox::{self, Input, Mode, Tool};
use clean_core::usn::{self, DeltaVerdict};
use serde::Serialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, Emitter, State};

// ---------------------------------------------------------------- state --

#[derive(Default)]
struct AppState {
    /// Result of the last junk scan: per rule, its base and its dry-run targets.
    junk: Mutex<Vec<JunkRuleState>>,
    /// Result of the last duplicate scan.
    dupes: Mutex<Vec<DupeGroup>>,
    /// Deletable developer artifacts from the last dev scan, flat and indexed;
    /// the UI selects by index and the path is re-derived here (never injected).
    dev: Mutex<Vec<(String, u64)>>,
    /// Installed apps from the last app scan; the UI selects by index and the
    /// uninstall command / bundle path is re-derived here (never injected).
    apps: Mutex<Vec<InstalledApp>>,
    /// Autostart entries from the last startup scan; the UI toggles by index
    /// and the target entry is re-derived here (never injected).
    startup: Mutex<Vec<StartupEntry>>,
    /// Cancel flag of the toolbox tool currently running (one at a time).
    tool_running: Mutex<Option<Arc<AtomicBool>>>,
}

struct JunkRuleState {
    id: String,
    base: PathBuf,
    targets: Vec<(String, u64)>,
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Undo manifests live in a stable per-user location, independent of cwd:
/// %LOCALAPPDATA% on Windows, ~/Library/Application Support on macOS.
fn manifest_dir() -> PathBuf {
    let base = if cfg!(windows) {
        std::env::var("LOCALAPPDATA").map(PathBuf::from).ok()
    } else if cfg!(target_os = "macos") {
        std::env::var("HOME")
            .map(|h| PathBuf::from(h).join("Library").join("Application Support"))
            .ok()
    } else {
        std::env::var("HOME")
            .map(|h| PathBuf::from(h).join(".local").join("share"))
            .ok()
    };
    let dir = base.unwrap_or_else(std::env::temp_dir).join("CleanMaster");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

fn emit_progress(app: &AppHandle, stage: &str, label: &str, seen: u64) {
    let _ = app.emit(
        "progress",
        serde_json::json!({ "stage": stage, "label": label, "seen": seen }),
    );
}

// ----------------------------------------------------------------- DTOs --

#[derive(Serialize)]
struct JunkRuleDto {
    id: String,
    category: String,
    category_label: String,
    base: String,
    rationale: String,
    min_age_days: u32,
    files: usize,
    bytes: u64,
    /// Applied by default (true) vs opt-in only (false, e.g. privacy traces).
    /// The UI leaves opt-in rules unchecked after a scan.
    default_apply: bool,
}

#[derive(Serialize)]
struct JunkReportDto {
    rules: Vec<JunkRuleDto>,
    total_files: usize,
    total_bytes: u64,
}

#[derive(Serialize)]
struct ApplyDto {
    requested: usize,
    deleted: usize,
    bytes: u64,
    failed: usize,
    failed_sample: Vec<(String, String)>,
    /// Running applications holding open handles to the failed files
    /// (Restart Manager, batched). Empty when nothing failed or unknown.
    holders: Vec<String>,
    /// Rule ids that had at least one file fail to recycle (junk only).
    /// The UI greys these on the next scan and drops them from the
    /// "reclaimable now" headline. Empty for duplicates.
    blocked_rules: Vec<String>,
    manifest: Option<String>,
}

/// Explain failures: which running apps hold the files that would not move.
fn failure_holders(failed: &[(String, String)]) -> Vec<String> {
    if failed.is_empty() {
        return Vec::new();
    }
    let paths: Vec<String> = failed.iter().map(|(p, _)| p.clone()).collect();
    clean_core::safety::in_use_by(&paths)
}

#[derive(Serialize)]
struct DupeMemberDto {
    path: String,
    keep: bool,
}

#[derive(Serialize)]
struct DupeGroupDto {
    index: usize,
    size: u64,
    wasted: u64,
    hash12: String,
    members: Vec<DupeMemberDto>,
}

#[derive(Serialize)]
struct DupesDto {
    root: String,
    group_count: usize,
    redundant_files: usize,
    total_wasted: u64,
    truncated: bool,
    groups: Vec<DupeGroupDto>,
}

#[derive(Serialize)]
struct FileDto {
    path: String,
    bytes: u64,
}

#[derive(Serialize)]
struct DirDto {
    path: String,
    bytes: u64,
    files: u64,
}

#[derive(Serialize)]
struct ExtDto {
    ext: String,
    count: u64,
    bytes: u64,
    /// Largest files of this type, biggest first (drill-down detail).
    top: Vec<FileDto>,
}

#[derive(Serialize)]
struct AgeDto {
    label: String,
    count: u64,
    bytes: u64,
}

#[derive(Serialize)]
struct AnalyzeDto {
    root: String,
    total_bytes: u64,
    files: u64,
    dirs: u64,
    skipped: usize,
    top_files: Vec<FileDto>,
    top_dirs: Vec<DirDto>,
    exts: Vec<ExtDto>,
    ages: Vec<AgeDto>,
    /// True when served from a saved snapshot (instant, possibly stale).
    cached: bool,
    /// Snapshot age in seconds (0 for fresh results).
    age_secs: i64,
    /// How the result was produced: "cache" | "delta" | "full".
    method: String,
    /// Directories re-enumerated live in a delta refresh (0 otherwise).
    delta_dirs: u64,
}

#[derive(Serialize)]
struct UndoStatusDto {
    manifest: String,
    files: usize,
    bytes: u64,
    at_unix: i64,
}

#[derive(Serialize)]
struct UndoResultDto {
    restored: usize,
    missing: usize,
}

// ------------------------------------------------------------- commands --

#[tauri::command]
async fn junk_scan(app: AppHandle, state: State<'_, AppState>) -> Result<JunkReportDto, String> {
    let app2 = app.clone();
    let reports = tauri::async_runtime::spawn_blocking(move || {
        let rules = builtin_rules();
        evaluate_all_with_progress(&rules, now_unix(), &|rule_id, seen| {
            if seen % 2048 == 0 {
                emit_progress(&app2, "junk-scan", rule_id, seen);
            }
        })
    })
    .await
    .map_err(|e| format!("junk scan task failed: {e}"))?;

    let mut dto_rules = Vec::new();
    let mut rule_state = Vec::new();
    let mut total_files = 0usize;
    let mut total_bytes = 0u64;
    for r in &reports {
        total_files += r.findings.len();
        total_bytes += r.bytes;
        dto_rules.push(JunkRuleDto {
            id: r.rule.id.clone(),
            category: format!("{:?}", r.rule.category).to_lowercase(),
            category_label: r.rule.category.label().to_string(),
            base: r.base.clone(),
            rationale: r.rule.rationale.clone(),
            min_age_days: r.rule.min_age_days,
            files: r.findings.len(),
            bytes: r.bytes,
            default_apply: r.rule.default_apply,
        });
        rule_state.push(JunkRuleState {
            id: r.rule.id.clone(),
            base: PathBuf::from(&r.base),
            targets: r
                .findings
                .iter()
                .map(|f| (f.record.path.clone(), f.record.size))
                .collect(),
        });
    }
    *state.junk.lock().map_err(|_| "state lock poisoned")? = rule_state;
    Ok(JunkReportDto {
        rules: dto_rules,
        total_files,
        total_bytes,
    })
}

#[tauri::command]
async fn junk_apply(
    app: AppHandle,
    state: State<'_, AppState>,
    rule_ids: Vec<String>,
    permanent: Option<bool>,
) -> Result<ApplyDto, String> {
    let permanent = permanent.unwrap_or(false);
    let (targets, bases, path_to_rule) = {
        let junk = state.junk.lock().map_err(|_| "state lock poisoned")?;
        if junk.is_empty() {
            return Err("No scan results. Run a scan first.".into());
        }
        let mut targets: Vec<(String, u64)> = Vec::new();
        let mut bases: Vec<PathBuf> = Vec::new();
        // Remember which rule each target came from, so a failed file can be
        // mapped back to its rule for the "in use" marking on the next scan.
        let mut path_to_rule: HashMap<String, String> = HashMap::new();
        for r in junk.iter().filter(|r| rule_ids.contains(&r.id)) {
            bases.push(r.base.clone());
            for (p, sz) in &r.targets {
                targets.push((p.clone(), *sz));
                path_to_rule.insert(p.clone(), r.id.clone());
            }
        }
        (targets, bases, path_to_rule)
    };
    if targets.is_empty() {
        return Err("Nothing selected.".into());
    }

    let app2 = app.clone();
    let result = tauri::async_runtime::spawn_blocking(move || {
        // Safety gate: a target must sit inside a selected rule's own base
        // (or be outside every protected root).
        let filtered: Vec<(String, u64)> = targets
            .into_iter()
            .filter(|(p, _)| deletion_allowed(Path::new(p), &bases))
            .collect();
        let total = filtered.len();
        let mut manifest = ActionManifest::new();
        let report = |done: usize| {
            let _ = app2.emit(
                "apply-progress",
                serde_json::json!({ "done": done, "total": total }),
            );
        };
        // Opt-in fast path: the user explicitly ticked "delete permanently"
        // in the confirm dialog. Default stays Recycle Bin + undo.
        let outcome = if permanent {
            delete_files_permanently(&filtered, &mut manifest, report)
        } else {
            recycle_files(&filtered, &mut manifest, report)
        };
        let manifest_path = if manifest.actions.is_empty() {
            None
        } else {
            manifest
                .save(&manifest_dir())
                .ok()
                .map(|p| p.display().to_string())
        };
        (total, outcome, manifest_path)
    })
    .await
    .map_err(|e| format!("apply task failed: {e}"))?;

    let (requested, outcome, manifest) = result;
    // Results are now stale: force a rescan before the next apply.
    state
        .junk
        .lock()
        .map_err(|_| "state lock poisoned")?
        .clear();
    let holders = failure_holders(&outcome.failed);
    let mut blocked_rules: Vec<String> = Vec::new();
    for (p, _) in &outcome.failed {
        if let Some(rid) = path_to_rule.get(p) {
            if !blocked_rules.contains(rid) {
                blocked_rules.push(rid.clone());
            }
        }
    }
    Ok(ApplyDto {
        requested,
        deleted: outcome.deleted,
        bytes: outcome.bytes,
        failed: outcome.failed.len(),
        failed_sample: outcome.failed.into_iter().take(5).collect(),
        holders,
        blocked_rules,
        manifest,
    })
}

const MAX_GROUPS_IN_UI: usize = 500;

#[tauri::command]
async fn dupes_scan(
    app: AppHandle,
    state: State<'_, AppState>,
    path: String,
    min_size: u64,
) -> Result<DupesDto, String> {
    let root = PathBuf::from(&path);
    if !root.is_dir() {
        return Err(format!("Not a folder: {path}"));
    }
    let app2 = app.clone();
    let groups = tauri::async_runtime::spawn_blocking(move || {
        let outcome = WalkBackend
            .scan(&root, &ScanOptions::default(), &|seen| {
                if seen % 4096 == 0 {
                    emit_progress(&app2, "dupe-scan", "scanning", seen);
                }
            })
            .map_err(|e| e.to_string())?;
        emit_progress(&app2, "dupe-hash", "hashing", 0);
        let opts = DupeOptions {
            min_size,
            keep_priority: Vec::new(),
        };
        Ok::<Vec<DupeGroup>, String>(find_duplicates(&outcome.records, &opts))
    })
    .await
    .map_err(|e| format!("duplicate scan task failed: {e}"))??;

    let total_wasted: u64 = groups.iter().map(|g| g.wasted_bytes()).sum();
    let redundant_files: usize = groups.iter().map(|g| g.members.len() - 1).sum();
    let dto_groups: Vec<DupeGroupDto> = groups
        .iter()
        .take(MAX_GROUPS_IN_UI)
        .enumerate()
        .map(|(i, g)| DupeGroupDto {
            index: i,
            size: g.size,
            wasted: g.wasted_bytes(),
            hash12: g.hash.chars().take(12).collect(),
            members: g
                .members
                .iter()
                .enumerate()
                .map(|(mi, m)| DupeMemberDto {
                    path: m.path.clone(),
                    keep: mi == g.suggested_keep,
                })
                .collect(),
        })
        .collect();
    let dto = DupesDto {
        root: path,
        group_count: groups.len(),
        redundant_files,
        total_wasted,
        truncated: groups.len() > MAX_GROUPS_IN_UI,
        groups: dto_groups,
    };
    *state.dupes.lock().map_err(|_| "state lock poisoned")? = groups;
    Ok(dto)
}

#[tauri::command]
async fn dupes_apply(
    app: AppHandle,
    state: State<'_, AppState>,
    group_indexes: Vec<usize>,
) -> Result<ApplyDto, String> {
    let targets: Vec<(String, u64)> = {
        let groups = state.dupes.lock().map_err(|_| "state lock poisoned")?;
        if groups.is_empty() {
            return Err("No scan results. Run a scan first.".into());
        }
        let mut targets = Vec::new();
        for &i in &group_indexes {
            let Some(g) = groups.get(i) else { continue };
            // Business rule: the keeper must still exist, or the whole
            // group is skipped - one copy always survives.
            let keeper = &g.members[g.suggested_keep];
            if !Path::new(&keeper.path).is_file() {
                continue;
            }
            for m in g.deletable() {
                if deletion_allowed(Path::new(&m.path), &[]) {
                    targets.push((m.path.clone(), m.size));
                }
            }
        }
        targets
    };
    if targets.is_empty() {
        return Err("Nothing to delete in the selected groups.".into());
    }

    let app2 = app.clone();
    let (requested, outcome, manifest) = tauri::async_runtime::spawn_blocking(move || {
        let total = targets.len();
        let mut manifest = ActionManifest::new();
        let outcome = recycle_files(&targets, &mut manifest, |done| {
            let _ = app2.emit(
                "apply-progress",
                serde_json::json!({ "done": done, "total": total }),
            );
        });
        let manifest_path = if manifest.actions.is_empty() {
            None
        } else {
            manifest
                .save(&manifest_dir())
                .ok()
                .map(|p| p.display().to_string())
        };
        (total, outcome, manifest_path)
    })
    .await
    .map_err(|e| format!("apply task failed: {e}"))?;

    state
        .dupes
        .lock()
        .map_err(|_| "state lock poisoned")?
        .clear();
    let holders = failure_holders(&outcome.failed);
    Ok(ApplyDto {
        requested,
        deleted: outcome.deleted,
        bytes: outcome.bytes,
        failed: outcome.failed.len(),
        failed_sample: outcome.failed.into_iter().take(5).collect(),
        holders,
        blocked_rules: Vec::new(),
        manifest,
    })
}

/// Saved Analyze snapshots (instant reopen + USN differential refresh).
fn scan_cache_dir() -> PathBuf {
    manifest_dir().join("scan-cache")
}

fn build_analyze_dto(
    outcome: &ScanOutcome,
    root_str: &str,
    cached: bool,
    age_secs: i64,
    method: &str,
    delta_dirs: u64,
) -> AnalyzeDto {
    let records = &outcome.records;
    let files = records.iter().filter(|r| !r.is_dir).count() as u64;
    let dirs = records.iter().filter(|r| r.is_dir).count() as u64;
    let total_bytes: u64 = records.iter().filter(|r| !r.is_dir).map(|r| r.size).sum();
    AnalyzeDto {
        total_bytes,
        files,
        dirs,
        skipped: outcome.skipped.len(),
        top_files: report::top_files(records, 15)
            .into_iter()
            .map(|r| FileDto {
                path: r.path.clone(),
                bytes: r.size,
            })
            .collect(),
        top_dirs: report::top_dirs(records, root_str, 15)
            .into_iter()
            .map(|d| DirDto {
                path: d.path,
                bytes: d.bytes,
                files: d.files,
            })
            .collect(),
        exts: report::by_extension(records, 12)
            .into_iter()
            .map(|e| ExtDto {
                top: report::top_files_of_ext(records, &e.ext, 25)
                    .into_iter()
                    .map(|r| FileDto {
                        path: r.path.clone(),
                        bytes: r.size,
                    })
                    .collect(),
                ext: e.ext,
                count: e.count,
                bytes: e.bytes,
            })
            .collect(),
        ages: report::by_age(records, now_unix())
            .into_iter()
            .map(|a| AgeDto {
                label: a.label.to_string(),
                count: a.count,
                bytes: a.bytes,
            })
            .collect(),
        root: root_str.to_string(),
        cached,
        age_secs,
        method: method.to_string(),
        delta_dirs,
    }
}

/// Instant view of the last saved scan of `path`, if one exists. Read-only:
/// never touches the disk tree, so it is safe to call before every refresh.
#[tauri::command]
async fn analyze_cached(path: String) -> Result<Option<AnalyzeDto>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let file = scan_cache::cache_file(&scan_cache_dir(), &path, &[]);
        let Some(snap) = scan_cache::load(&file) else {
            return Ok(None);
        };
        let age = (now_unix() - snap.meta.created_unix).max(0);
        Ok(Some(build_analyze_dto(
            &snap.outcome,
            &path,
            true,
            age,
            "cache",
            0,
        )))
    })
    .await
    .map_err(|e| format!("analyze task failed: {e}"))?
}

#[tauri::command]
async fn analyze_path(app: AppHandle, path: String) -> Result<AnalyzeDto, String> {
    let root = PathBuf::from(&path);
    if !root.is_dir() {
        return Err(format!("Not a folder: {path}"));
    }
    let app2 = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let root_str = root.display().to_string();
        let opts = ScanOptions::default();
        let cache_file = scan_cache::cache_file(&scan_cache_dir(), &root_str, &opts.excludes);
        let progress = |seen: u64| {
            if seen.is_multiple_of(4096) {
                emit_progress(&app2, "analyze-scan", "scanning", seen);
            }
        };

        // Checkpoint BEFORE scanning: anything that changes mid-scan stays
        // above the checkpoint and gets re-processed by the next delta.
        let new_cp = usn::checkpoint_for(&root);

        // Differential path: snapshot + journal both vouch for the interval.
        let mut result: Option<(ScanOutcome, &str, u64)> = None;
        if let Some(snap) = scan_cache::load(&cache_file) {
            if let Some(old_cp) = snap.meta.usn {
                // Resolving one changed dir costs ~1 file open; past half the
                // snapshot's dir count a full walk is competitive anyway.
                let dir_count = snap.outcome.records.iter().filter(|r| r.is_dir).count();
                let max_dirty = (dir_count / 2).clamp(256, 50_000);
                if let DeltaVerdict::Dirty(dirty) =
                    usn::changed_dirs_since(&root, &old_cp, max_dirty)
                {
                    if let Ok((outcome, live)) =
                        merge_scan(&root, &opts, &snap.outcome, &dirty, &progress)
                    {
                        result = Some((outcome, "delta", live));
                    }
                }
            }
        }
        let (outcome, method, delta_dirs) = match result {
            Some(r) => r,
            None => {
                let outcome = WalkBackend
                    .scan(&root, &opts, &progress)
                    .map_err(|e| e.to_string())?;
                (outcome, "full", 0)
            }
        };

        // Persist for the next launch; a failed save only costs speed later.
        let snap = Snapshot {
            meta: SnapshotMeta {
                root: root_str.clone(),
                excludes: opts.excludes.clone(),
                created_unix: now_unix(),
                usn: new_cp,
            },
            outcome,
        };
        let _ = scan_cache::save(&cache_file, &snap);
        scan_cache::prune(&scan_cache_dir(), 5);

        Ok(build_analyze_dto(
            &snap.outcome,
            &root_str,
            false,
            0,
            method,
            delta_dirs,
        ))
    })
    .await
    .map_err(|e| format!("analyze task failed: {e}"))?
}

// ------------------------------------------------------ developer scan --

#[derive(Serialize)]
struct DevArtifactDto {
    index: usize,
    kind_id: String,
    kind_label: String,
    dir_name: String,
    path: String,
    bytes: u64,
    files: u64,
    restore_hint: String,
    last_used_unix: i64,
    recommended: bool,
}

#[derive(Serialize)]
struct DevProjectDto {
    name: String,
    root: String,
    total_bytes: u64,
    artifacts: Vec<DevArtifactDto>,
}

#[derive(Serialize)]
struct DevScanDto {
    root: String,
    project_count: usize,
    artifact_count: usize,
    total_bytes: u64,
    truncated: bool,
    projects: Vec<DevProjectDto>,
}

const MAX_DEV_PROJECTS_IN_UI: usize = 300;

#[tauri::command]
async fn dev_scan(
    app: AppHandle,
    state: State<'_, AppState>,
    path: String,
) -> Result<DevScanDto, String> {
    let root = PathBuf::from(&path);
    if !root.is_dir() {
        return Err(format!("Not a folder: {path}"));
    }
    let app2 = app.clone();
    let projects = tauri::async_runtime::spawn_blocking(move || {
        scan_projects(&root, &|seen| {
            if seen % 1024 == 0 {
                emit_progress(&app2, "dev-scan", "scanning projects", seen);
            }
        })
    })
    .await
    .map_err(|e| format!("dev scan task failed: {e}"))?;

    // Flat, indexed target list for apply. The index the UI receives maps 1:1
    // to a (path, size) here; the path is never taken from the webview.
    let mut flat: Vec<(String, u64)> = Vec::new();
    let total_bytes: u64 = projects.iter().map(|p| p.total_bytes).sum();
    let artifact_count: usize = projects.iter().map(|p| p.artifacts.len()).sum();

    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let mut dto_projects = Vec::new();
    for p in projects.iter().take(MAX_DEV_PROJECTS_IN_UI) {
        let mut arts = Vec::new();
        for a in &p.artifacts {
            let index = flat.len();
            flat.push((a.path.clone(), a.bytes));
            arts.push(DevArtifactDto {
                index,
                kind_id: a.kind_id.clone(),
                kind_label: a.kind_label.clone(),
                dir_name: a.dir_name.clone(),
                path: a.path.clone(),
                bytes: a.bytes,
                files: a.files,
                restore_hint: a.restore_hint.clone(),
                last_used_unix: a.last_used_unix,
                recommended: clean_core::devscan::is_recommended(now_unix, a.last_used_unix),
            });
        }
        dto_projects.push(DevProjectDto {
            name: p.name.clone(),
            root: p.root.clone(),
            total_bytes: p.total_bytes,
            artifacts: arts,
        });
    }
    // Index any artifacts beyond the display cap too, so their indexes stay
    // valid if ever referenced; they simply are not shown.
    for p in projects.iter().skip(MAX_DEV_PROJECTS_IN_UI) {
        for a in &p.artifacts {
            flat.push((a.path.clone(), a.bytes));
        }
    }

    *state.dev.lock().map_err(|_| "state lock poisoned")? = flat;
    Ok(DevScanDto {
        root: path,
        project_count: projects.len(),
        artifact_count,
        total_bytes,
        truncated: projects.len() > MAX_DEV_PROJECTS_IN_UI,
        projects: dto_projects,
    })
}

#[tauri::command]
async fn dev_apply(
    app: AppHandle,
    state: State<'_, AppState>,
    artifact_indexes: Vec<usize>,
    permanent: Option<bool>,
) -> Result<ApplyDto, String> {
    let permanent = permanent.unwrap_or(false);
    let targets: Vec<(String, u64)> = {
        let dev = state.dev.lock().map_err(|_| "state lock poisoned")?;
        if dev.is_empty() {
            return Err("No scan results. Run a scan first.".into());
        }
        artifact_indexes
            .iter()
            .filter_map(|&i| dev.get(i).cloned())
            .collect()
    };
    if targets.is_empty() {
        return Err("Nothing selected.".into());
    }

    let app2 = app.clone();
    let (requested, outcome, manifest) = tauri::async_runtime::spawn_blocking(move || {
        // Artifact directories live in user space; the protected-root guard
        // still applies (nothing under Windows/Program Files is ever touched).
        let filtered: Vec<(String, u64)> = targets
            .into_iter()
            .filter(|(p, _)| deletion_allowed(Path::new(p), &[]))
            .collect();
        let total = filtered.len();
        let mut manifest = ActionManifest::new();
        let emit = |done: usize| {
            let _ = app2.emit(
                "apply-progress",
                serde_json::json!({ "done": done, "total": total }),
            );
        };
        let outcome = if permanent {
            // Opt-in fast path: recycling a directory makes the shell touch
            // every file inside it (~950 files/s under EDR), so a large
            // node_modules selection takes minutes. remove_dir_all skips the
            // Recycle Bin entirely; the manifest still records each folder.
            delete_dirs_permanently(&filtered, &mut manifest, emit)
        } else {
            // One shell transaction per directory (they are few and huge)
            // so progress ticks per folder instead of freezing until done.
            let mut merged = clean_core::safety::ApplyOutcome {
                deleted: 0,
                bytes: 0,
                failed: Vec::new(),
            };
            for (done, item) in filtered.iter().enumerate() {
                let one = recycle_files(std::slice::from_ref(item), &mut manifest, |_| {});
                merged.deleted += one.deleted;
                merged.bytes += one.bytes;
                merged.failed.extend(one.failed);
                emit(done + 1);
            }
            merged
        };
        let manifest_path = if manifest.actions.is_empty() {
            None
        } else {
            manifest
                .save(&manifest_dir())
                .ok()
                .map(|p| p.display().to_string())
        };
        (total, outcome, manifest_path)
    })
    .await
    .map_err(|e| format!("apply task failed: {e}"))?;

    state.dev.lock().map_err(|_| "state lock poisoned")?.clear();
    let holders = failure_holders(&outcome.failed);
    Ok(ApplyDto {
        requested,
        deleted: outcome.deleted,
        bytes: outcome.bytes,
        failed: outcome.failed.len(),
        failed_sample: outcome.failed.into_iter().take(5).collect(),
        holders,
        blocked_rules: Vec::new(),
        manifest,
    })
}

// ----------------------------------------------------------- app manager --

#[derive(Serialize)]
struct AppDto {
    index: usize,
    name: String,
    version: String,
    publisher: String,
    install_date: String,
    bytes: u64,
    location: String,
    last_used_unix: i64,
    flags: Vec<String>,
    /// "uninstaller" (Windows: vendor uninstaller is launched) or
    /// "trash" (macOS: bundle is recycled, undo-able).
    removal: String,
}

#[derive(Serialize)]
struct AppsDto {
    app_count: usize,
    /// Sum over apps with a KNOWN size; unknown sizes count 0.
    total_bytes: u64,
    flagged_count: usize,
    apps: Vec<AppDto>,
}

#[derive(Serialize)]
struct AppRemoveDto {
    /// Windows: the vendor uninstaller was launched (finish it there, rescan).
    launched: bool,
    /// macOS: the bundle was moved to the Trash.
    recycled: usize,
    bytes: u64,
    failed: usize,
    manifest: Option<String>,
}

#[tauri::command]
async fn apps_scan(app: AppHandle, state: State<'_, AppState>) -> Result<AppsDto, String> {
    let app2 = app.clone();
    let apps = tauri::async_runtime::spawn_blocking(move || {
        scan_installed_apps(now_unix(), &|seen| {
            emit_progress(&app2, "apps-scan", "reading installed software", seen);
        })
    })
    .await
    .map_err(|e| format!("app scan task failed: {e}"))?;

    let dto = AppsDto {
        app_count: apps.len(),
        total_bytes: apps.iter().map(|a| a.size_bytes).sum(),
        flagged_count: apps.iter().filter(|a| !a.flags.is_empty()).count(),
        apps: apps
            .iter()
            .enumerate()
            .map(|(i, a)| AppDto {
                index: i,
                name: a.name.clone(),
                version: a.version.clone(),
                publisher: a.publisher.clone(),
                install_date: a.install_date.clone(),
                bytes: a.size_bytes,
                location: a.location.clone(),
                last_used_unix: a.last_used_unix,
                flags: a.flags.clone(),
                removal: match a.removal {
                    AppRemoval::WindowsUninstall { .. } => "uninstaller".to_string(),
                    AppRemoval::MacBundle { .. } => "trash".to_string(),
                },
            })
            .collect(),
    };
    *state.apps.lock().map_err(|_| "state lock poisoned")? = apps;
    Ok(dto)
}

#[tauri::command]
async fn app_uninstall(state: State<'_, AppState>, index: usize) -> Result<AppRemoveDto, String> {
    // Re-derive the removal action from server-side state; the webview only
    // ever supplies an index.
    let (removal, size) = {
        let apps = state.apps.lock().map_err(|_| "state lock poisoned")?;
        let Some(a) = apps.get(index) else {
            return Err("No such app. Rescan first.".into());
        };
        (a.removal.clone(), a.size_bytes)
    };
    match removal {
        AppRemoval::WindowsUninstall { uninstall_string } => {
            // Launch the vendor's own uninstaller, exactly like Settings >
            // Apps. Clean Master never deletes program files itself.
            std::process::Command::new("cmd")
                .args(["/C", &uninstall_string])
                .spawn()
                .map_err(|e| format!("could not launch the uninstaller: {e}"))?;
            Ok(AppRemoveDto {
                launched: true,
                recycled: 0,
                bytes: 0,
                failed: 0,
                manifest: None,
            })
        }
        AppRemoval::MacBundle { path } => {
            tauri::async_runtime::spawn_blocking(move || {
                let bundle = PathBuf::from(&path);
                // /Applications is a protected root; authorize exactly the
                // directory that holds this bundle (same mechanism junk rules
                // use to authorize their own base).
                let base = bundle.parent().map(Path::to_path_buf).unwrap_or_default();
                if !deletion_allowed(&bundle, &[base]) {
                    return Err("Refusing to remove: outside the applications folder.".to_string());
                }
                let mut manifest = ActionManifest::new();
                let outcome = recycle_files(&[(path, size)], &mut manifest, |_| {});
                let manifest_path = if manifest.actions.is_empty() {
                    None
                } else {
                    manifest
                        .save(&manifest_dir())
                        .ok()
                        .map(|p| p.display().to_string())
                };
                Ok(AppRemoveDto {
                    launched: false,
                    recycled: outcome.deleted,
                    bytes: outcome.bytes,
                    failed: outcome.failed.len(),
                    manifest: manifest_path,
                })
            })
            .await
            .map_err(|e| format!("remove task failed: {e}"))?
        }
    }
}

// -------------------------------------------------------------- toolbox --

#[derive(Serialize)]
struct ToolDto {
    id: String,
    category: String,
    name: String,
    blurb: String,
    needs_admin: bool,
    reboot: bool,
    long_running: bool,
    has_check: bool,
    has_action: bool,
    has_open: bool,
    takes_input: bool,
    check_label: String,
    action_label: String,
    /// Literal command lines, for the card and the confirm dialog.
    check_cmd: String,
    action_cmd: String,
    /// Size preview (hiberfil.sys, Windows.old, DO cache); None = no probe
    /// or nothing there.
    probe_bytes: Option<u64>,
    /// Stable reason id when the tool cannot run right now.
    unavailable: Option<String>,
}

#[derive(Serialize)]
struct ToolboxDto {
    /// false on macOS: the catalog is Windows-only.
    supported: bool,
    elevated: bool,
    tools: Vec<ToolDto>,
}

#[derive(Serialize)]
struct ToolRunDto {
    exit_code: Option<i32>,
    success: bool,
    cancelled: bool,
}

#[derive(Serialize, Clone)]
struct ToolLinePayload {
    id: String,
    line: String,
}

fn join_cmds(cmds: &[toolbox::Cmd]) -> String {
    cmds.iter()
        .map(|c| c.display())
        .collect::<Vec<_>>()
        .join("\n")
}

#[tauri::command]
async fn toolbox_list() -> Result<ToolboxDto, String> {
    tauri::async_runtime::spawn_blocking(|| {
        let tools = toolbox::builtin_tools();
        ToolboxDto {
            supported: cfg!(target_os = "windows"),
            elevated: toolbox::is_elevated(),
            tools: tools
                .iter()
                .map(|t: &Tool| ToolDto {
                    id: t.id.to_string(),
                    category: t.category.id().to_string(),
                    name: t.name.to_string(),
                    blurb: t.blurb.to_string(),
                    needs_admin: t.needs_admin,
                    reboot: t.reboot,
                    long_running: t.long_running,
                    has_check: !t.check.is_empty(),
                    has_action: !t.action.is_empty(),
                    has_open: t.open.is_some(),
                    takes_input: t.input == Input::WingetTerm,
                    check_label: t.check_label.to_string(),
                    action_label: t.action_label.to_string(),
                    check_cmd: join_cmds(&t.check),
                    action_cmd: join_cmds(&t.action),
                    probe_bytes: toolbox::probe_bytes(&t.probe),
                    unavailable: toolbox::unavailable_reason(t).map(str::to_string),
                })
                .collect(),
        }
    })
    .await
    .map_err(|e| format!("toolbox list failed: {e}"))
}

/// Run one tool. The webview sends an id + mode (+ a winget term); the
/// command line is re-derived from the catalog here. Output lines stream as
/// "tool-line" events; the result comes back when the tool finishes.
#[tauri::command]
async fn toolbox_run(
    app: AppHandle,
    state: State<'_, AppState>,
    id: String,
    mode: String,
    input: Option<String>,
) -> Result<ToolRunDto, String> {
    let tool = toolbox::find_tool(&id).ok_or_else(|| format!("Unknown tool: {id}"))?;
    let mode = Mode::parse(&mode).ok_or_else(|| format!("Unknown mode: {mode}"))?;
    if tool.needs_admin && !toolbox::is_elevated() {
        return Err(
            "This tool needs administrator rights. Restart Clean Master as administrator first."
                .into(),
        );
    }
    if let Some(reason) = toolbox::unavailable_reason(&tool) {
        return Err(format!("Tool is not available right now ({reason})."));
    }
    let steps: Vec<toolbox::Cmd> = match (mode, tool.input) {
        (Mode::Open, _) => {
            let cmd = tool.open.clone().ok_or("This tool has nothing to open.")?;
            return tauri::async_runtime::spawn_blocking(move || {
                toolbox::open_cmd(&cmd).map(|_| ToolRunDto {
                    exit_code: Some(0),
                    success: true,
                    cancelled: false,
                })
            })
            .await
            .map_err(|e| format!("open failed: {e}"))?;
        }
        (m, Input::WingetTerm) => {
            let term = toolbox::validate_winget_term(input.as_deref().unwrap_or(""))?;
            toolbox::winget_cmds(m, &term)
        }
        (Mode::Check, Input::None) => tool.check.clone(),
        (Mode::Action, Input::None) => tool.action.clone(),
    };
    if steps.is_empty() {
        return Err("This tool has no such command.".into());
    }

    // One tool at a time: claim the slot before spawning.
    let cancel = Arc::new(AtomicBool::new(false));
    {
        let mut slot = state
            .tool_running
            .lock()
            .map_err(|_| "state lock poisoned")?;
        if slot.is_some() {
            return Err("Another tool is still running. Wait for it or cancel it first.".into());
        }
        *slot = Some(cancel.clone());
    }

    let app2 = app.clone();
    let id2 = id.clone();
    let result = tauri::async_runtime::spawn_blocking(move || {
        toolbox::run_steps(&steps, &cancel, |line| {
            let _ = app2.emit(
                "tool-line",
                ToolLinePayload {
                    id: id2.clone(),
                    line: line.to_string(),
                },
            );
        })
    })
    .await
    .map_err(|e| format!("tool task failed: {e}"));

    // Always free the slot, even when the tool errored.
    if let Ok(mut slot) = state.tool_running.lock() {
        *slot = None;
    }
    let outcome = result??;
    Ok(ToolRunDto {
        exit_code: outcome.exit_code,
        success: outcome.success,
        cancelled: outcome.cancelled,
    })
}

#[tauri::command]
async fn toolbox_cancel(state: State<'_, AppState>) -> Result<bool, String> {
    let slot = state
        .tool_running
        .lock()
        .map_err(|_| "state lock poisoned")?;
    match slot.as_ref() {
        Some(flag) => {
            flag.store(true, Ordering::SeqCst);
            Ok(true)
        }
        None => Ok(false),
    }
}

/// Start an elevated instance through UAC and quit this one on success.
#[tauri::command]
async fn toolbox_elevate(app: AppHandle, state: State<'_, AppState>) -> Result<(), String> {
    if state
        .tool_running
        .lock()
        .map_err(|_| "state lock poisoned")?
        .is_some()
    {
        return Err("A tool is still running. Wait for it or cancel it first.".into());
    }
    tauri::async_runtime::spawn_blocking(toolbox::relaunch_elevated)
        .await
        .map_err(|e| format!("elevate task failed: {e}"))??;
    app.exit(0);
    Ok(())
}

#[tauri::command]
async fn undo_status() -> Result<Option<UndoStatusDto>, String> {
    tauri::async_runtime::spawn_blocking(|| {
        // Permanent-delete manifests are audit records with nothing to give
        // back; the undo panel only ever shows recycle sessions. A session
        // whose items are no longer in the Recycle Bin (bin emptied, or
        // everything restored by hand) is retired on sight - offering it
        // would promise an undo that restores nothing.
        loop {
            let Some((path, m)) = ActionManifest::latest_restorable_in(&manifest_dir()) else {
                return Ok(None);
            };
            let entries: Vec<_> = m
                .actions
                .iter()
                .filter(|a| a.disposition == Disposition::RecycleBin)
                .collect();
            let at_unix = entries.first().map(|a| a.at_unix).unwrap_or(0);
            let (files, bytes) = match clean_core::safety::restorable_stats(&m) {
                Some((0, _)) => {
                    let dead = path.with_file_name(format!("stale-{}.json", m.session_id));
                    if std::fs::rename(&path, dead).is_err() {
                        // Cannot retire (e.g. locked): hide the card this
                        // round rather than loop on the same manifest.
                        return Ok(None);
                    }
                    continue; // an older session may still be restorable
                }
                Some(live) => live,
                // Bin unlistable: fail open with manifest counts.
                None => (entries.len(), entries.iter().map(|a| a.size).sum()),
            };
            return Ok(Some(UndoStatusDto {
                manifest: path.display().to_string(),
                files,
                bytes,
                at_unix,
            }));
        }
    })
    .await
    .map_err(|e| format!("undo status task failed: {e}"))?
}

#[tauri::command]
async fn undo_last() -> Result<UndoResultDto, String> {
    tauri::async_runtime::spawn_blocking(|| {
        let Some((path, m)) = ActionManifest::latest_restorable_in(&manifest_dir()) else {
            return Err("Nothing to undo.".to_string());
        };
        let out = clean_core::safety::undo(&m).map_err(|e| e.to_string())?;
        // Retire the manifest so "undo last" moves on to the previous apply.
        let done = path.with_file_name(format!("undone-{}.json", m.session_id));
        let _ = std::fs::rename(&path, done);
        Ok(UndoResultDto {
            restored: out.restored,
            missing: out.missing,
        })
    })
    .await
    .map_err(|e| format!("undo task failed: {e}"))?
}

/// Open the system file manager with `path` selected, so the user can view
/// or manually delete it. Analyze stays read-only in-app: this never touches
/// the file, and args are passed as a vector (no shell string to inject into).
#[tauri::command]
async fn reveal_path(path: String) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || {
        if !std::path::Path::new(&path).exists() {
            return Err(format!("No longer exists: {path}"));
        }
        if cfg!(target_os = "windows") {
            // Explorer's exit code is meaningless (1 even on success): spawn only.
            std::process::Command::new("explorer")
                .arg(format!("/select,{path}"))
                .spawn()
                .map_err(|e| format!("Could not open Explorer: {e}"))?;
            Ok(())
        } else if cfg!(target_os = "macos") {
            std::process::Command::new("open")
                .arg("-R")
                .arg(&path)
                .spawn()
                .map_err(|e| format!("Could not open Finder: {e}"))?;
            Ok(())
        } else {
            Err("Reveal is not supported on this platform.".to_string())
        }
    })
    .await
    .map_err(|e| format!("reveal task failed: {e}"))?
}

// ---------------------------------------------------------- startup ------

#[derive(Serialize)]
struct StartupEntryDto {
    index: usize,
    name: String,
    command: String,
    location: String,
    enabled: bool,
    requires_admin: bool,
}

#[derive(Serialize)]
struct StartupDto {
    total: usize,
    enabled: usize,
    /// Whether THIS process is running elevated. Changing an HKLM / all-users
    /// entry needs administrator rights; when false the UI offers a UAC
    /// relaunch instead of attempting the write and surfacing a raw os error 5.
    elevated: bool,
    entries: Vec<StartupEntryDto>,
}

fn startup_dto(entries: &[StartupEntry]) -> StartupDto {
    StartupDto {
        total: entries.len(),
        enabled: entries.iter().filter(|e| e.enabled).count(),
        elevated: toolbox::is_elevated(),
        entries: entries
            .iter()
            .enumerate()
            .map(|(i, e)| StartupEntryDto {
                index: i,
                name: e.name.clone(),
                command: e.command.clone(),
                location: e.location_label.clone(),
                enabled: e.enabled,
                requires_admin: e.requires_admin,
            })
            .collect(),
    }
}

#[tauri::command]
async fn startup_scan(state: State<'_, AppState>) -> Result<StartupDto, String> {
    let entries = tauri::async_runtime::spawn_blocking(startup::list)
        .await
        .map_err(|e| format!("startup scan task failed: {e}"))?;
    let dto = startup_dto(&entries);
    *state.startup.lock().map_err(|_| "state lock poisoned")? = entries;
    Ok(dto)
}

/// Toggle one entry by index. The webview never sends the target - it is
/// re-derived from server-side state, then re-listed so the UI reflects the
/// real post-change state (and disabled entries keep their new home).
#[tauri::command]
async fn startup_toggle(
    state: State<'_, AppState>,
    index: usize,
    enable: bool,
) -> Result<StartupDto, String> {
    let entry = {
        let entries = state.startup.lock().map_err(|_| "state lock poisoned")?;
        entries
            .get(index)
            .cloned()
            .ok_or("No such entry. Rescan first.")?
    };
    if entry.requires_admin && !toolbox::is_elevated() {
        // The frontend disables ADMIN rows while unelevated; this guards the
        // command directly so a stale view can never trigger a raw os error 5.
        return Err(format!(
            "'{}' lives in {} and needs administrator rights. Restart Clean Master as administrator first.",
            entry.name, entry.location_label
        ));
    }
    let refreshed = tauri::async_runtime::spawn_blocking(move || {
        startup::set_enabled(&entry, enable).map(|_| startup::list())
    })
    .await
    .map_err(|e| format!("startup toggle task failed: {e}"))?
    .map_err(|e| e.to_string())?;
    let dto = startup_dto(&refreshed);
    *state.startup.lock().map_err(|_| "state lock poisoned")? = refreshed;
    Ok(dto)
}

#[tauri::command]
async fn pick_folder() -> Result<Option<String>, String> {
    // E2E seam: native dialogs cannot be automated, so tests preselect the
    // folder via env var. Inert in production (variable absent).
    if let Ok(p) = std::env::var("CM_TEST_PICK_FOLDER") {
        if !p.trim().is_empty() {
            return Ok(Some(p));
        }
    }
    tauri::async_runtime::spawn_blocking(|| {
        rfd::FileDialog::new()
            .set_title("Choose a folder")
            .pick_folder()
            .map(|p| p.display().to_string())
    })
    .await
    .map_err(|e| format!("folder dialog failed: {e}"))
}

fn main() {
    // Elevated relaunch handshake: the previous (non-elevated) instance must
    // be gone before this one creates its window, or WebView2 refuses to
    // share the user-data folder across integrity levels.
    let args: Vec<String> = std::env::args().collect();
    if let Some(pid) = toolbox::wait_for_pid_arg(&args) {
        toolbox::wait_for_pid_exit(pid, 15_000);
    }
    tauri::Builder::default()
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            junk_scan,
            junk_apply,
            dupes_scan,
            dupes_apply,
            dev_scan,
            dev_apply,
            apps_scan,
            app_uninstall,
            analyze_path,
            analyze_cached,
            reveal_path,
            undo_status,
            undo_last,
            pick_folder,
            toolbox_list,
            toolbox_run,
            toolbox_cancel,
            toolbox_elevate,
            startup_scan,
            startup_toggle
        ])
        .run(tauri::generate_context!())
        .expect("error while running Clean Master");
}
