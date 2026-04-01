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

impl From<shroudb_client_common::ConnectionError> for ClientError {
    fn from(err: shroudb_client_common::ConnectionError) -> Self {
        match err {
            shroudb_client_common::ConnectionError::Io(e) => Self::Connection(e),
            shroudb_client_common::ConnectionError::Protocol(s) => Self::Protocol(s),
            shroudb_client_common::ConnectionError::Server(s) => Self::Server(s),
        }
    }
}
