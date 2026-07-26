//! clean-core: engine library for CleanCLI.
//!
//! Contains no terminal I/O. The CLI (and the future GUI) consume this crate.

pub mod appscan;
pub mod devscan;
pub mod dupes;
pub mod error;
pub mod report;
pub mod rules;
pub mod safety;
pub mod scanner;
pub mod session;
pub mod types;

pub use error::CoreError;
