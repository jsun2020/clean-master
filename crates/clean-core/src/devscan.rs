//! Developer artifact discovery: find large, fully regenerable dependency and
//! build directories (node_modules, Rust/Maven `target`, Gradle output, Python
//! virtualenvs, .NET bin/obj) grouped by project, so a user can reclaim them
//! per project while keeping source code.
//!
//! Safety by construction: an artifact directory is only ever reported when a
//! **project marker** proves it is regenerable - `node_modules` beside a
//! `package.json`, `target` beside `Cargo.toml`/`pom.xml`, a virtualenv that
//! contains `pyvenv.cfg`, etc. Source files, `.git`, and unmarked directories
//! are never matched. Nothing here deletes; callers decide (opt-in per project).

use crate::scanner::{ScanBackend, ScanOptions, WalkBackend};
use rayon::prelude::*;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// How an artifact directory is recognized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Detect {
    /// The directory name matches, AND one of `markers` exists in its PARENT
    /// (the project root). Example: `node_modules` + parent has `package.json`.
    SiblingMarker,
    /// The directory itself CONTAINS the marker file. Example: a Python
    /// virtualenv always contains `pyvenv.cfg`, regardless of its name.
    SelfMarker,
}

#[derive(Debug, Clone)]
struct ArtifactKind {
    id: &'static str,
    label: &'static str,
    /// Directory name to match (case-insensitive). Ignored for `SelfMarker`.
    dir_name: &'static str,
    detect: Detect,
    /// Marker file names that gate the match (see `Detect`).
    markers: &'static [&'static str],
    /// How the user regenerates it after deletion.
    restore_hint: &'static str,
}

/// The catalog. Conservative on purpose: only unambiguous, high-value,
/// clearly-regenerable directories tied to a strong project manifest.
fn catalog() -> &'static [ArtifactKind] {
    &[
        ArtifactKind {
            id: "node_modules",
            label: "Node.js dependencies",
            dir_name: "node_modules",
            detect: Detect::SiblingMarker,
            markers: &["package.json"],
            restore_hint: "npm/pnpm/yarn install",
        },
        ArtifactKind {
            id: "rust_target",
            label: "Rust build output",
            dir_name: "target",
            detect: Detect::SiblingMarker,
            markers: &["Cargo.toml"],
            restore_hint: "cargo build",
        },
        ArtifactKind {
            id: "maven_target",
            label: "Maven build output",
            dir_name: "target",
            detect: Detect::SiblingMarker,
            markers: &["pom.xml"],
            restore_hint: "mvn package",
        },
        ArtifactKind {
            id: "gradle_build",
            label: "Gradle build output",
            dir_name: "build",
            detect: Detect::SiblingMarker,
            markers: &[
                "build.gradle",
                "build.gradle.kts",
                "settings.gradle",
                "settings.gradle.kts",
            ],
            restore_hint: "gradle build",
        },
        ArtifactKind {
            id: "gradle_cache",
            label: "Gradle local cache",
            dir_name: ".gradle",
            detect: Detect::SiblingMarker,
            markers: &[
                "build.gradle",
                "build.gradle.kts",
                "settings.gradle",
                "settings.gradle.kts",
            ],
            restore_hint: "gradle build",
        },
        ArtifactKind {
            id: "python_venv",
            label: "Python virtualenv",
            dir_name: "",
            detect: Detect::SelfMarker,
            markers: &["pyvenv.cfg"],
            restore_hint: "recreate the virtualenv",
        },
        ArtifactKind {
            id: "dotnet_obj",
            label: ".NET intermediate (obj)",
            dir_name: "obj",
            detect: Detect::SiblingMarker,
            markers: &[".csproj", ".vbproj", ".fsproj"],
            restore_hint: "dotnet build",
        },
        ArtifactKind {
            id: "dotnet_bin",
            label: ".NET build output (bin)",
            dir_name: "bin",
            detect: Detect::SiblingMarker,
            markers: &[".csproj", ".vbproj", ".fsproj"],
            restore_hint: "dotnet build",
        },
    ]
}

/// One reclaimable artifact directory belonging to a project.
#[derive(Debug, Clone)]
pub struct DevArtifact {
    pub kind_id: String,
    pub kind_label: String,
    pub dir_name: String,
    pub path: String,
    pub bytes: u64,
    pub files: u64,
    pub restore_hint: String,
    /// Newest modified time (unix seconds) of any file inside the artifact -
    /// a free by-product of the sizing walk. Approximates the last build /
    /// install; 0 when unknown.
    pub last_used_unix: i64,
}

/// An artifact untouched for this long is recommended for cleanup: the
/// project is not being actively built, so reclaiming costs nothing until
/// the next (re)build regenerates it.
pub const DEV_STALE_DAYS: i64 = 30;

/// Pure recommendation heuristic. Unknown activity (0) is never recommended:
/// a recommendation must rest on evidence, same rule the App Manager flags
/// follow. Deleting is safe either way (artifacts are regenerable by
/// construction); this only ranks convenience.
pub fn is_recommended(now_unix: i64, last_used_unix: i64) -> bool {
    last_used_unix > 0 && now_unix - last_used_unix > DEV_STALE_DAYS * 86400
}

/// A project (a directory holding a recognized manifest) and its artifacts.
#[derive(Debug, Clone)]
pub struct DevProject {
    pub root: String,
    pub name: String,
    pub artifacts: Vec<DevArtifact>,
    pub total_bytes: u64,
}

/// Directories we never descend into: already-found artifacts (pruned in the
/// walk) plus source-history / VCS dirs that must never be touched or spidered.
fn is_vcs_or_meta(name: &str) -> bool {
    matches!(name, ".git" | ".hg" | ".svn")
}

fn marker_present_in(dir: &Path, markers: &[&str]) -> bool {
    // Markers beginning with '.' (e.g. ".csproj") are extension matches; the
    // rest are exact file names. One directory read, no per-file stat.
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();
        for m in markers {
            if let Some(ext) = m.strip_prefix('.') {
                if name
                    .rsplit('.')
                    .next()
                    .map(|e| e.eq_ignore_ascii_case(ext))
                    .unwrap_or(false)
                    && name.len() > ext.len() + 1
                {
                    return true;
                }
            } else if name.eq_ignore_ascii_case(m) {
                return true;
            }
        }
    }
    false
}

/// Match a directory against the catalog. Returns the matching kind, if any.
fn match_kind(dir: &Path) -> Option<&'static ArtifactKind> {
    let name = dir.file_name()?.to_string_lossy().to_string();
    for kind in catalog() {
        match kind.detect {
            Detect::SelfMarker => {
                if marker_present_in(dir, kind.markers) {
                    return Some(kind);
                }
            }
            Detect::SiblingMarker => {
                if name.eq_ignore_ascii_case(kind.dir_name) {
                    if let Some(parent) = dir.parent() {
                        if marker_present_in(parent, kind.markers) {
                            return Some(kind);
                        }
                    }
                }
            }
        }
    }
    None
}

/// A raw hit found during discovery, before sizing.
struct Hit {
    kind: &'static ArtifactKind,
    path: PathBuf,
    project_root: PathBuf,
}

/// Recursive discovery with pruning: when a directory is recognized as an
/// artifact it is recorded and NOT descended into (so a project's node_modules
/// is one hit, not thousands). VCS dirs are skipped entirely.
fn discover(dir: &Path, hits: &mut Vec<Hit>, progress: &(dyn Fn(u64) + Sync), seen: &mut u64) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_dir() || file_type.is_symlink() {
            continue;
        }
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        *seen += 1;
        if seen.is_multiple_of(512) {
            progress(*seen);
        }
        if is_vcs_or_meta(&name) {
            continue;
        }
        if let Some(kind) = match_kind(&path) {
            let project_root = match kind.detect {
                // A venv's "project" is its parent directory.
                Detect::SelfMarker => path.parent().unwrap_or(&path).to_path_buf(),
                Detect::SiblingMarker => path.parent().unwrap_or(&path).to_path_buf(),
            };
            hits.push(Hit {
                kind,
                path: path.clone(),
                project_root,
            });
            continue; // prune: never descend into an artifact directory
        }
        discover(&path, hits, progress, seen);
    }
}

/// Total size, file count and newest file mtime of a directory subtree,
/// using the shared EDR-safe parallel walker (enumeration-cached metadata,
/// no per-file stat) - the mtime is free, the records already carry it.
fn size_of(dir: &Path) -> (u64, u64, i64) {
    match WalkBackend.scan(dir, &ScanOptions::default(), &|_| {}) {
        Ok(outcome) => {
            let mut files = 0u64;
            let mut bytes = 0u64;
            let mut newest = 0i64;
            for r in outcome.records.iter().filter(|r| !r.is_dir) {
                files += 1;
                bytes += r.size;
                newest = newest.max(r.modified);
            }
            (bytes, files, newest)
        }
        Err(_) => (0, 0, 0),
    }
}

/// Discover reclaimable developer artifacts under `root`, grouped by project.
/// `progress` is called with a growing count of directories examined during
/// the (cheap) discovery phase; the (expensive) sizing phase runs in parallel
/// across artifacts afterwards. Never deletes anything.
pub fn scan_projects(root: &Path, progress: &(dyn Fn(u64) + Sync)) -> Vec<DevProject> {
    let mut hits = Vec::new();
    let mut seen = 0u64;
    discover(root, &mut hits, progress, &mut seen);

    // Size every artifact in parallel (the slow part - a node_modules can hold
    // 100k files). Independent subtrees, so this is embarrassingly parallel.
    let sized: Vec<(Hit, u64, u64, i64)> = hits
        .into_par_iter()
        .map(|hit| {
            let (bytes, files, newest) = size_of(&hit.path);
            (hit, bytes, files, newest)
        })
        .collect();

    // Group by project root (stable, sorted path order within a project).
    let mut by_project: BTreeMap<PathBuf, Vec<DevArtifact>> = BTreeMap::new();
    for (hit, bytes, files, newest) in sized {
        by_project
            .entry(hit.project_root.clone())
            .or_default()
            .push(DevArtifact {
                kind_id: hit.kind.id.to_string(),
                kind_label: hit.kind.label.to_string(),
                dir_name: hit
                    .path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                path: hit.path.display().to_string(),
                bytes,
                files,
                restore_hint: hit.kind.restore_hint.to_string(),
                last_used_unix: newest,
            });
    }

    let mut projects: Vec<DevProject> = by_project
        .into_iter()
        .map(|(root, mut artifacts)| {
            artifacts.sort_by(|a, b| b.bytes.cmp(&a.bytes).then_with(|| a.path.cmp(&b.path)));
            let total_bytes = artifacts.iter().map(|a| a.bytes).sum();
            DevProject {
                name: root
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| root.display().to_string()),
                root: root.display().to_string(),
                artifacts,
                total_bytes,
            }
        })
        .collect();

    // Biggest projects first; ties broken by path for determinism.
    projects.sort_by(|a, b| {
        b.total_bytes
            .cmp(&a.total_bytes)
            .then_with(|| a.root.cmp(&b.root))
    });
    projects
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn touch(path: &Path, bytes: usize) {
        if let Some(p) = path.parent() {
            fs::create_dir_all(p).unwrap();
        }
        fs::write(path, vec![0u8; bytes]).unwrap();
    }

    #[test]
    fn finds_node_modules_only_with_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        // A real project: package.json + node_modules with content.
        touch(&root.join("app").join("package.json"), 50);
        touch(
            &root
                .join("app")
                .join("node_modules")
                .join("left-pad")
                .join("index.js"),
            1000,
        );
        touch(&root.join("app").join("src").join("main.js"), 200);
        // A decoy: a node_modules with NO package.json beside it (must be ignored).
        touch(&root.join("decoy").join("node_modules").join("x.js"), 9999);

        let projects = scan_projects(root, &|_| {});
        assert_eq!(projects.len(), 1, "only the manifest-backed project counts");
        let p = &projects[0];
        assert!(p.root.ends_with("app"));
        assert_eq!(p.artifacts.len(), 1);
        assert_eq!(p.artifacts[0].kind_id, "node_modules");
        assert_eq!(p.artifacts[0].bytes, 1000);
        assert_eq!(p.artifacts[0].files, 1);
    }

    #[test]
    fn discovery_prunes_inside_artifacts() {
        // A node_modules that itself contains a nested node_modules must be a
        // SINGLE hit (we recycle the whole top directory).
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        touch(&root.join("package.json"), 10);
        touch(
            &root.join("node_modules").join("a").join("package.json"),
            10,
        );
        touch(
            &root
                .join("node_modules")
                .join("a")
                .join("node_modules")
                .join("b.js"),
            500,
        );
        let projects = scan_projects(root, &|_| {});
        assert_eq!(projects.len(), 1);
        assert_eq!(projects[0].artifacts.len(), 1);
        // Size includes the nested tree.
        assert!(projects[0].artifacts[0].bytes >= 500);
    }

    #[test]
    fn rust_and_maven_target_distinguished_by_marker() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        touch(&root.join("rustproj").join("Cargo.toml"), 10);
        touch(
            &root
                .join("rustproj")
                .join("target")
                .join("debug")
                .join("bin.exe"),
            2000,
        );
        touch(&root.join("mavenproj").join("pom.xml"), 10);
        touch(
            &root
                .join("mavenproj")
                .join("target")
                .join("classes")
                .join("A.class"),
            3000,
        );

        let projects = scan_projects(root, &|_| {});
        let kinds: Vec<&str> = projects
            .iter()
            .flat_map(|p| p.artifacts.iter().map(|a| a.kind_id.as_str()))
            .collect();
        assert!(kinds.contains(&"rust_target"));
        assert!(kinds.contains(&"maven_target"));
    }

    #[test]
    fn python_venv_detected_by_pyvenv_cfg() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        touch(&root.join("proj").join(".venv").join("pyvenv.cfg"), 20);
        touch(
            &root.join("proj").join(".venv").join("Lib").join("site.py"),
            4000,
        );
        touch(&root.join("proj").join("main.py"), 100);

        let projects = scan_projects(root, &|_| {});
        assert_eq!(projects.len(), 1);
        assert_eq!(projects[0].artifacts[0].kind_id, "python_venv");
        assert!(projects[0].artifacts[0].bytes >= 4000);
    }

    #[test]
    fn git_dir_is_never_matched_or_spidered() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        touch(&root.join("proj").join("package.json"), 10);
        // A node_modules buried inside .git must never surface.
        touch(
            &root
                .join("proj")
                .join(".git")
                .join("node_modules")
                .join("x.js"),
            5000,
        );
        let projects = scan_projects(root, &|_| {});
        assert!(projects.is_empty(), ".git subtree must be skipped entirely");
    }

    #[test]
    fn recommended_only_when_stale_with_evidence() {
        let now = 1_800_000_000i64;
        let day = 86_400i64;
        // Fresh build: not recommended.
        assert!(!is_recommended(now, now - 2 * day));
        // Just under the threshold: not recommended.
        assert!(!is_recommended(now, now - (DEV_STALE_DAYS - 1) * day));
        // Past the threshold: recommended.
        assert!(is_recommended(now, now - (DEV_STALE_DAYS + 1) * day));
        // Unknown activity never creates a recommendation.
        assert!(!is_recommended(now, 0));
    }

    #[test]
    fn artifact_carries_newest_mtime() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        touch(&root.join("app").join("package.json"), 10);
        touch(&root.join("app").join("node_modules").join("x.js"), 100);
        let projects = scan_projects(root, &|_| {});
        assert_eq!(projects.len(), 1);
        // Freshly written fixture: mtime must be present and recent, so the
        // artifact must NOT be recommended.
        let a = &projects[0].artifacts[0];
        assert!(a.last_used_unix > 0);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        assert!(now - a.last_used_unix < 3600);
        assert!(!is_recommended(now, a.last_used_unix));
    }

    #[test]
    fn multiple_artifacts_group_under_one_project() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let proj = root.join("fullstack");
        touch(&proj.join("package.json"), 10);
        touch(&proj.join("node_modules").join("dep.js"), 1000);
        touch(&proj.join("Cargo.toml"), 10);
        touch(&proj.join("target").join("out.bin"), 2000);

        let projects = scan_projects(root, &|_| {});
        assert_eq!(projects.len(), 1);
        assert_eq!(projects[0].artifacts.len(), 2);
        assert_eq!(projects[0].total_bytes, 3000);
        // Sorted biggest-first within the project.
        assert_eq!(projects[0].artifacts[0].kind_id, "rust_target");
    }
}
