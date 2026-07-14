mod analyze;
mod dupes_cmd;
mod fmt;
mod junk;

use clap::{Parser, Subcommand};
use clean_core::scanner::{ScanBackend, ScanOptions, WalkBackend};
use clean_core::session::{Session, DEFAULT_SESSION_FILE};
use indicatif::{ProgressBar, ProgressStyle};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

#[derive(Parser)]
#[command(
    name = "clean",
    version,
    about = "CleanCLI - fast, safe, portable disk cleaning (MVP)",
    long_about = "Scan folders or drives, analyze space usage, find junk and duplicates.\n\
                  All destructive commands are dry-run by default and require --apply."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Scan a folder or drive and cache the result in a session file
    Scan {
        /// Root to scan, e.g. C:\ or D:\Projects
        path: PathBuf,
        /// Glob pattern(s) to exclude (repeatable), e.g. --exclude *.iso
        #[arg(long = "exclude")]
        excludes: Vec<String>,
        /// Session file to write (default: clean-session.json next to the exe's working dir)
        #[arg(long, short)]
        output: Option<PathBuf>,
    },
    /// Show where the space went, based on the last scan session
    Analyze {
        /// Session file produced by `clean scan`
        #[arg(long, short, default_value = clean_core::session::DEFAULT_SESSION_FILE)]
        session: PathBuf,
        /// Rows per table
        #[arg(long, default_value_t = 20)]
        top: usize,
        /// Show only one section
        #[arg(long, value_enum)]
        by: Option<analyze::Section>,
    },
    /// Find junk files in known-safe locations (dry run by default)
    Junk,
    /// Find duplicate files under a path (dry run by default)
    Dupes {
        /// Root to search for duplicates
        path: PathBuf,
        /// Ignore files smaller than this many bytes
        #[arg(long = "min-size", default_value_t = clean_core::dupes::DEFAULT_MIN_SIZE)]
        min_size: u64,
        /// Directory to prefer when choosing which copy to keep (repeatable, highest priority first)
        #[arg(long = "keep-priority")]
        keep_priority: Vec<String>,
        /// Max groups to display
        #[arg(long, default_value_t = 20)]
        top: usize,
    },
    /// Inspect the built-in junk rules
    Rules {
        #[command(subcommand)]
        cmd: RulesCmd,
    },
}

#[derive(Subcommand)]
enum RulesCmd {
    /// List all junk rules with location and safety rationale
    List,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.cmd {
        Cmd::Scan {
            path,
            excludes,
            output,
        } => cmd_scan(path, excludes, output),
        Cmd::Analyze { session, top, by } => cmd_analyze(session, top, by),
        Cmd::Junk => {
            junk::run_dry();
            Ok(())
        }
        Cmd::Dupes {
            path,
            min_size,
            keep_priority,
            top,
        } => dupes_cmd::run_dry(&dupes_cmd::DupesArgs {
            path,
            min_size,
            keep_priority,
            top,
        }),
        Cmd::Rules { cmd: RulesCmd::List } => {
            junk::list_rules();
            Ok(())
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("error: {msg}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_scan(path: PathBuf, excludes: Vec<String>, output: Option<PathBuf>) -> Result<(), String> {
    let output = output.unwrap_or_else(|| PathBuf::from(DEFAULT_SESSION_FILE));
    let bar = ProgressBar::new_spinner();
    bar.set_style(
        ProgressStyle::with_template("{spinner} scanning... {msg}")
            .expect("valid template"),
    );
    bar.enable_steady_tick(Duration::from_millis(120));

    let started = Instant::now();
    let opts = ScanOptions { excludes };
    let outcome = WalkBackend
        .scan(&path, &opts, &mut |seen| {
            bar.set_message(format!("{seen} entries"));
        })
        .map_err(|e| e.to_string())?;
    bar.finish_and_clear();

    let elapsed = started.elapsed();
    let session = Session::from_scan(&path, outcome);
    session.save(&output).map_err(|e| e.to_string())?;

    println!("Scan complete: {}", session.root);
    println!("  files:    {}", session.file_count());
    println!("  dirs:     {}", session.dir_count());
    println!("  size:     {}", fmt::human_bytes(session.total_file_bytes()));
    println!("  skipped:  {} (access denied / unreadable)", session.skipped.len());
    println!("  elapsed:  {:.1}s", elapsed.as_secs_f64());
    println!("  session:  {}", output.display());
    println!();
    println!("Next: `clean analyze` to see where the space went.");
    Ok(())
}

fn cmd_analyze(
    session_path: PathBuf,
    top: usize,
    by: Option<analyze::Section>,
) -> Result<(), String> {
    let session = Session::load(&session_path).map_err(|e| {
        format!("{e}\nHint: run `clean scan <path>` first to create a session file.")
    })?;
    analyze::run(&session, top, by);
    Ok(())
}
