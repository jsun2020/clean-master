//! clean-core: engine library for CleanCLI.
//!
//! Contains no terminal I/O. The CLI (and the future GUI) consume this crate.

pub mod appscan;
pub mod devscan;
pub mod dupes;
pub mod error;
pub mod memory;
pub mod report;
pub mod rules;
pub mod safety;
pub mod scan_cache;
pub mod scanner;
pub mod session;
pub mod shortcut;
pub mod startup;
pub mod toolbox;
pub mod types;
pub mod usn;

pub use error::CoreError;
