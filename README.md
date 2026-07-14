# CleanCLI (`clean`)

Fast, safe, portable disk cleaning for Windows. Single ~3 MB exe, no install,
no telemetry. See `prd.md` for the full product definition.

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
- Protected roots (Windows, Program Files, ProgramData) are never touched
  except where a junk rule explicitly authorizes its own base (e.g.
  `C:\Windows\Temp`).

## Build

```
cargo build --release        # target/release/clean.exe (~2.7 MB)
cargo test                   # 30 unit tests
```

Workspace layout: `crates/clean-core` is the engine library (no terminal I/O;
the future GUI consumes it), `crates/clean-cli` is the thin CLI binary.

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
