# CleanCLI (`clean`) + Clean Master (GUI)

Fast, safe, portable disk cleaning for Windows and macOS. No install, no
telemetry. Two front ends over the same engine:

- `clean` / `clean.exe` - the CLI (~3 MB)
- `clean-master` / `clean-master.exe` - **Clean Master**, the desktop GUI
  (Tauri 2, single portable binary; assets embedded, no WebView bundled -
  uses the system WebView2 runtime on Windows 10/11, WKWebView on macOS)

See `prd.md` for the full product definition.

## Clean Master (GUI)

```
cargo build --release -p clean-gui   # target/release/clean-master.exe
```

Three screens, same safety contract as the CLI:

- **Junk Clean** - scans the built-in rule pack on launch (dry run), shows
  every rule with its location, size and rationale; clean what you select.
- **Duplicates** - pick a folder, full BLAKE3 verification, the KEEP copy is
  marked and can never be deleted; opt groups in or out.
- **Space Analyze** - largest files/folders, by type, by age. Read-only.
- **Developer** - pick a folder; finds regenerable dependency/build folders
  (node_modules, Rust/Maven `target`, Gradle output, Python venvs, .NET
  bin/obj) grouped by project. Off by default (opt-in per project); an
  artifact is only listed when a project manifest proves it is regenerable,
  so source code and `.git` are never touched.
- **Undo** - every clean writes a manifest to `%LOCALAPPDATA%\CleanMaster`;
  the sidebar restores the last clean from the Recycle Bin in one click.

The webview only ever selects rule ids / group indexes - deletion targets are
re-derived and re-validated (protected roots, keeper-survives) in Rust.

## Quick start

```
clean scan D:\                # index a folder or drive -> clean-session.json
clean analyze                 # where did the space go? (files/dirs/ext/age)
clean junk                    # find junk in known-safe locations (DRY RUN)
clean junk --apply            # move it to the Recycle Bin (asks confirmation)
clean dupes D:\Photos         # find duplicate files (DRY RUN, full BLAKE3 verify)
clean dupes D:\Photos --apply # recycle redundant copies (one always survives)
clean undo                    # restore everything from the last apply
clean rules list              # every junk rule + why it is safe
```

## Safety model (non-negotiable, see prd.md section 7)

- Dry run is the default everywhere; deletion requires `--apply` plus a typed
  confirmation (`--yes` skips the prompt for scripting).
- Deletion means Recycle Bin, never permanent. Every apply writes a
  `clean-undo-<id>.json` manifest; `clean undo` restores from it.
- Junk rules only ever match inside their documented base directory and skip
  recently-modified files. Duplicates: full-content BLAKE3 verification, and
  one copy of every group always survives.
- Protected roots are never touched except where a junk rule explicitly
  authorizes its own base (e.g. `C:\Windows\Temp`). Windows: `C:\Windows`,
  Program Files, ProgramData. macOS: `/System`, `/Library`, `/Applications`,
  `/usr`, `/bin`, `/sbin`, `/etc`, `/private/etc`, `/private/var/db`.

## Build

```
cargo build --release        # target/release/clean.exe + clean-master.exe
cargo test                   # unit tests
```

Workspace layout: `crates/clean-core` is the engine library (no terminal
I/O), `crates/clean-cli` is the thin CLI binary, `crates/clean-gui` is the
Clean Master desktop app (static HTML/CSS/JS frontend, no Node toolchain).

## Platform support

| | Windows | macOS |
|---|---|---|
| Junk rule pack | `rules/windows.json` (9 rules) | `rules/macos.json` (5 rules: TMPDIR, `~/Library/Caches`, Logs, Saved Application State, Xcode DerivedData) |
| Deletion | Recycle Bin (`trash` crate) | Trash (`trash` crate) |
| Undo | One-click restore from the Recycle Bin | Not available programmatically (the `trash` crate cannot enumerate the macOS Trash) - use Finder's **Put Back** |
| "File in use" explanation | Restart Manager names the holding apps | Not applicable (POSIX deletes don't block on open handles) |
| Undo manifests | `%LOCALAPPDATA%\CleanMaster` | `~/Library/Application Support/CleanMaster` |

CI (`.github/workflows/ci.yml`) builds and tests both OSes on every push.
The macOS build is developed on Windows and verified via `cargo check/clippy
--target aarch64-apple-darwin` plus the macOS CI runner; run the GUI smoke
test on real hardware before distributing Mac binaries.

## Measured performance (Win10, corporate EDR active)

- 1.51M entries (`%LOCALAPPDATA%`) scanned in ~17 s; ~120k entries/s.
- 687k-entry tree in 5.7 s. Small trees are effectively instant.

## Known limitations (MVP)

- Session files are JSON; at 1M+ records they get large (~470 MB) and
  `analyze` spends most of its time parsing. V2: compact binary session.
- `win.windows_temp` / `win.update_download_cache` need admin rights to see
  everything; without them those locations are silently skipped.
- Locked files (browser running, thumbnail cache in use) are skipped and
  reported during apply - close the app and re-run to get them.
- Duplicate detection treats hardlinked copies as duplicates (deleting one is
  harmless but frees no space).
- First scan of a cold, never-enumerated tree on an EDR-managed machine can be
  much slower than the numbers above; warm rescans are fast. V2's NTFS MFT
  backend bypasses this entirely.
