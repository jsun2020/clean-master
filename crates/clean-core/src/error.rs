use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("I/O error at {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("invalid exclude pattern '{pattern}': {message}")]
    InvalidPattern { pattern: String, message: String },

    #[error("scan root does not exist or is not accessible: {0}")]
    InvalidRoot(String),

    #[error("session file error: {0}")]
    Session(String),
}
