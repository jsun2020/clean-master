mod fmt;

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
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.cmd {
        Cmd::Scan {
            path,
            excludes,
            output,
        } => cmd_scan(path, excludes, output),
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
