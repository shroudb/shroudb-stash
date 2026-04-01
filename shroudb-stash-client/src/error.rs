/// Errors from the Stash client.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("connection failed: {0}")]
    Connection(#[from] std::io::Error),

    #[error("server error: {0}")]
    Server(String),

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("serialization failed: {0}")]
    Serialization(String),

    #[error("unexpected response format: {0}")]
    ResponseFormat(String),
}
