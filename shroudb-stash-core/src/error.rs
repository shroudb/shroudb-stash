/// Errors that can occur during Stash engine operations.
#[derive(Debug, thiserror::Error)]
pub enum StashError {
    /// Blob not found by ID.
    #[error("blob not found: {id}")]
    NotFound { id: String },

    /// Blob already exists with this ID.
    #[error("blob already exists: {id}")]
    AlreadyExists { id: String },

    /// Blob has been revoked (soft or hard).
    #[error("blob revoked: {id}")]
    Revoked { id: String },

    /// Blob has been crypto-shredded; data is unrecoverable.
    #[error("blob shredded: {id}")]
    Shredded { id: String },

    /// Cipher engine is not available for envelope encryption.
    #[error("cipher engine unavailable")]
    CipherUnavailable,

    /// Object store operation failed.
    #[error("object store error: {0}")]
    ObjectStore(String),

    /// ABAC policy denied the operation.
    #[error("access denied: {action} on {resource} (policy: {policy})")]
    AbacDenied {
        action: String,
        resource: String,
        policy: String,
    },

    /// Store (metadata) operation failed.
    #[error("store error: {0}")]
    Store(String),

    /// Encryption or decryption failed.
    #[error("crypto error: {0}")]
    Crypto(String),

    /// Duplicate viewer fingerprint.
    #[error("viewer already fingerprinted: {viewer_id} on blob {blob_id}")]
    DuplicateViewer { blob_id: String, viewer_id: String },

    /// Cannot fingerprint a client-encrypted blob (client manages encryption).
    #[error("cannot fingerprint client-encrypted blob: {id}")]
    ClientEncrypted { id: String },

    /// Invalid argument.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// Internal error.
    #[error("internal error: {0}")]
    Internal(String),
}

impl StashError {
    /// Whether this error represents a "not found" condition.
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::NotFound { .. })
    }

    /// Whether this error represents an access denial.
    pub fn is_denied(&self) -> bool {
        matches!(self, Self::AbacDenied { .. })
    }
}

/// Display-friendly error code for protocol responses.
impl StashError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotFound { .. } => "NOTFOUND",
            Self::AlreadyExists { .. } => "EXISTS",
            Self::Revoked { .. } => "REVOKED",
            Self::Shredded { .. } => "SHREDDED",
            Self::CipherUnavailable => "CIPHER_UNAVAILABLE",
            Self::DuplicateViewer { .. } => "DUPLICATE_VIEWER",
            Self::ClientEncrypted { .. } => "CLIENT_ENCRYPTED",
            Self::ObjectStore(_) => "OBJECT_STORE",
            Self::AbacDenied { .. } => "DENIED",
            Self::Store(_) => "STORE",
            Self::Crypto(_) => "CRYPTO",
            Self::InvalidArgument(_) => "INVALID_ARGUMENT",
            Self::Internal(_) => "INTERNAL",
        }
    }
}
