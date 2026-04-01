/// A Stash command response, ready for RESP3 serialization.
#[derive(Debug)]
pub enum StashResponse {
    /// Success with JSON data.
    Ok(serde_json::Value),
    /// Success with binary blob data + metadata.
    /// Used by RETRIEVE to return the blob alongside its metadata.
    Blob {
        metadata: serde_json::Value,
        data: Vec<u8>,
    },
    /// Error response.
    Error(String),
}

impl StashResponse {
    pub fn ok(data: serde_json::Value) -> Self {
        Self::Ok(data)
    }

    pub fn ok_simple() -> Self {
        Self::Ok(serde_json::json!({"status": "ok"}))
    }

    pub fn blob(metadata: serde_json::Value, data: Vec<u8>) -> Self {
        Self::Blob { metadata, data }
    }

    pub fn error(msg: impl Into<String>) -> Self {
        Self::Error(msg.into())
    }

    pub fn is_ok(&self) -> bool {
        matches!(self, Self::Ok(_) | Self::Blob { .. })
    }
}
