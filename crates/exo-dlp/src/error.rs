use thiserror::Error;

#[derive(Debug, Error)]
pub enum DlpError {
    #[error("scanner error: {0}")]
    Scanner(String),

    #[error("upstream error: {0}")]
    Upstream(String),

    #[error("policy violation: {0}")]
    Policy(String),

    #[error("custody error: {0}")]
    Custody(String),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("not yet implemented: {0}")]
    Unimplemented(&'static str),
}
