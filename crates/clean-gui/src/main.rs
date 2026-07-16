//! Clean Master - desktop GUI over the clean-core engine.
//!
//! Safety contract (prd.md section 7) is enforced HERE, not in the webview:
//! the UI selects rule ids / group indexes, and every deletion target is
//! re-derived from server-side state and passed through `deletion_allowed`.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use clean_core::devscan::scan_projects;
use clean_core::dupes::{find_duplicates, DupeGroup, DupeOptions};
use clean_core::report;
use clean_core::rules::{builtin_rules, evaluate_all_with_progress};
use clean_core::safety::{deletion_allowed, recycle_files, ActionManifest};
use clean_core::scanner::{ScanBackend, ScanOptions, WalkBackend};
use serde::Serialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
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
) -> Result<ApplyDto, String> {
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
        let outcome = recycle_files(&filtered, &mut manifest, |done| {
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

#[tauri::command]
async fn analyze_path(app: AppHandle, path: String) -> Result<AnalyzeDto, String> {
    let root = PathBuf::from(&path);
    if !root.is_dir() {
        return Err(format!("Not a folder: {path}"));
    }
    let app2 = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let outcome = WalkBackend
            .scan(&root, &ScanOptions::default(), &|seen| {
                if seen % 4096 == 0 {
                    emit_progress(&app2, "analyze-scan", "scanning", seen);
                }
            })
            .map_err(|e| e.to_string())?;
        let records = &outcome.records;
        let files = records.iter().filter(|r| !r.is_dir).count() as u64;
        let dirs = records.iter().filter(|r| r.is_dir).count() as u64;
        let total_bytes: u64 = records.iter().filter(|r| !r.is_dir).map(|r| r.size).sum();
        let root_str = root.display().to_string();
        Ok(AnalyzeDto {
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
            top_dirs: report::top_dirs(records, &root_str, 15)
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
            root: root_str,
        })
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
) -> Result<ApplyDto, String> {
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
        // trash::delete recycles each directory as a single operation.
        let outcome = recycle_files(&filtered, &mut manifest, |done| {
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

#[tauri::command]
async fn undo_status() -> Result<Option<UndoStatusDto>, String> {
    tauri::async_runtime::spawn_blocking(|| {
        let Some(path) = ActionManifest::latest_in(&manifest_dir()) else {
            return Ok(None);
        };
        let m = ActionManifest::load(&path).map_err(|e| e.to_string())?;
        Ok(Some(UndoStatusDto {
            manifest: path.display().to_string(),
            files: m.actions.len(),
            bytes: m.actions.iter().map(|a| a.size).sum(),
            at_unix: m.actions.first().map(|a| a.at_unix).unwrap_or(0),
        }))
    })
    .await
    .map_err(|e| format!("undo status task failed: {e}"))?
}

#[tauri::command]
async fn undo_last() -> Result<UndoResultDto, String> {
    tauri::async_runtime::spawn_blocking(|| {
        let Some(path) = ActionManifest::latest_in(&manifest_dir()) else {
            return Err("Nothing to undo.".to_string());
        };
        let m = ActionManifest::load(&path).map_err(|e| e.to_string())?;
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

#[tauri::command]
async fn pick_folder() -> Result<Option<String>, String> {
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
    tauri::Builder::default()
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            junk_scan,
            junk_apply,
            dupes_scan,
            dupes_apply,
            dev_scan,
            dev_apply,
            analyze_path,
            undo_status,
            undo_last,
            pick_folder
        ])
        .run(tauri::generate_context!())
        .expect("error while running Clean Master");
}
