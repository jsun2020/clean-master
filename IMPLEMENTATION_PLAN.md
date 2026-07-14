# Implementation Plan: CleanCLI MVP (V1)

Source of truth for requirements: `prd.md`. Delete this file when all stages are Complete.

Resolved open questions (2026-07-14, owner approved defaults):
- Name: keep working title `clean` / CleanCLI for MVP.
- Junk rule scope: Windows temp, user temp, browser caches (Chrome/Edge/Firefox), thumbnail cache, Windows Update download cache, crash dumps. (Recycle Bin emptying deferred - it IS our safety net.)
- Duplicate review: plain flag-driven CLI in MVP, no interactive TUI.
- License: deferred to release.

## Stage 1: Workspace scaffold + scan engine + `clean scan`
**Goal**: Cargo workspace (`crates/clean-core` lib, `crates/clean-cli` bin); FileRecord types; jwalk parallel scanner behind `ScanBackend` trait; session JSON snapshot; `clean scan <path> [--exclude] [--output]` with progress.
**Success Criteria**: Scans a real directory tree; writes session file; re-runnable; access-denied paths skipped and counted, never fatal; reparse points not followed.
**Tests**: Scanner on generated fixture tree (nested dirs, sizes, extensions); exclude globs; session serde roundtrip.
**Status**: Not Started

## Stage 2: Analysis report + `clean analyze`
**Goal**: Aggregations in core (top-N files/dirs, by extension, by age bucket); `clean analyze [--top N] [--by ext|age|dir]` rendering tables from session.
**Success Criteria**: Correct totals vs fixture; readable table output; handles empty/missing session with clear error.
**Tests**: Aggregation unit tests on fixture session.
**Status**: Not Started

## Stage 3: Junk rules + `clean junk` (dry-run) + `clean rules list`
**Goal**: Rule pack format (JSON, embedded via include_str!), evaluator -> JunkFinding {rule_id, category, risk, rationale}; dry-run report grouped by category with reclaimable totals.
**Success Criteria**: Safe-tier rules only; every finding shows rationale; no rule matches outside its documented target dirs.
**Tests**: Evaluator against synthetic fixture mimicking temp/cache layouts; protected-path exclusion.
**Status**: Not Started

## Stage 4: Duplicate finder + `clean dupes`
**Goal**: size bucket -> 4KB head+tail hash -> full BLAKE3 funnel; DupeGroup with suggested_keep (keep-priority dirs, then oldest); `clean dupes <path> [--min-size] [--keep-priority]`.
**Success Criteria**: Only content-identical files grouped (full-hash verified); one-copy-survives invariant enforced in group model; 1MB default min-size.
**Tests**: Fixture with identical/near-identical files; hardlink/same-file exclusion; keep heuristic ordering.
**Status**: Not Started

## Stage 5: Safety layer + apply/undo + E2E verification
**Goal**: Protected paths module; Recycle-Bin delete (trash crate); ActionManifest per apply session; `--apply` on junk/dupes with typed confirmation; `clean undo`.
**Success Criteria**: Dry-run remains default everywhere; apply moves to Recycle Bin and writes manifest; undo restores; permanent delete requires --permanent + confirmation; protected paths untouchable. E2E pass on scratch dir.
**Tests**: Manifest roundtrip; protected-path checks; recycle+undo smoke test in scratch dir.
**Status**: Not Started
