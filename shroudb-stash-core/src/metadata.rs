use serde::{Deserialize, Serialize};

/// Status of a stored blob.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BlobStatus {
    /// Blob is active and retrievable.
    Active,
    /// Soft-revoked: metadata and blob preserved, but access denied by policy.
    Revoked,
    /// Hard-revoked (crypto-shredded): DEK destroyed, S3 object deleted.
    Shredded,
}

impl std::fmt::Display for BlobStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Revoked => write!(f, "revoked"),
            Self::Shredded => write!(f, "shredded"),
        }
    }
}

/// Metadata for a stored blob, persisted in the ShrouDB Store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobMetadata {
    /// Unique blob identifier.
    pub id: String,
    /// S3 object key for the encrypted blob.
    pub s3_key: String,
    /// Base64-encoded CiphertextEnvelope wrapping the data encryption key.
    /// Cleared on crypto-shred.
    pub wrapped_dek: String,
    /// Cipher keyring used for envelope encryption.
    pub keyring: String,
    /// Cipher key version that wrapped the DEK.
    pub key_version: u32,
    /// MIME content type (e.g. "image/png", "application/pdf").
    pub content_type: Option<String>,
    /// Size of the original plaintext blob in bytes.
    pub plaintext_size: u64,
    /// Size of the encrypted blob in S3 (includes nonce + tag overhead).
    pub encrypted_size: u64,
    /// Whether the client performed encryption (Stash is passthrough).
    pub client_encrypted: bool,
    /// Current blob status.
    pub status: BlobStatus,
    /// Unix timestamp (ms) when the blob was stored.
    pub created_at: u64,
    /// Unix timestamp (ms) of the last status change.
    pub updated_at: u64,
}

/// Record of a fingerprinted viewer copy (populated by FINGERPRINT in v0.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViewerRecord {
    /// Viewer identifier.
    pub viewer_id: String,
    /// S3 object key for the viewer's fingerprinted copy.
    pub s3_key: String,
    /// Wrapped DEK for this specific copy.
    pub wrapped_dek: String,
    /// Fingerprint parameters used by the processor.
    pub fingerprint_params: serde_json::Value,
    /// Unix timestamp (ms) when the fingerprinted copy was created.
    pub created_at: u64,
}

/// Container for all viewer records associated with a blob.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ViewerMap {
    pub viewers: Vec<ViewerRecord>,
}

impl ViewerMap {
    pub fn find(&self, viewer_id: &str) -> Option<&ViewerRecord> {
        self.viewers.iter().find(|v| v.viewer_id == viewer_id)
    }

    pub fn is_empty(&self) -> bool {
        self.viewers.is_empty()
    }

    pub fn len(&self) -> usize {
        self.viewers.len()
    }
}

/// Result of an INSPECT command — metadata without blob data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InspectResult {
    pub id: String,
    pub status: BlobStatus,
    pub content_type: Option<String>,
    pub plaintext_size: u64,
    pub encrypted_size: u64,
    pub keyring: String,
    pub key_version: u32,
    pub client_encrypted: bool,
    pub viewer_count: usize,
    pub created_at: u64,
    pub updated_at: u64,
}

impl From<(&BlobMetadata, usize)> for InspectResult {
    fn from((meta, viewer_count): (&BlobMetadata, usize)) -> Self {
        Self {
            id: meta.id.clone(),
            status: meta.status,
            content_type: meta.content_type.clone(),
            plaintext_size: meta.plaintext_size,
            encrypted_size: meta.encrypted_size,
            keyring: meta.keyring.clone(),
            key_version: meta.key_version,
            client_encrypted: meta.client_encrypted,
            viewer_count,
            created_at: meta.created_at,
            updated_at: meta.updated_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blob_status_serde_roundtrip() {
        for status in [
            BlobStatus::Active,
            BlobStatus::Revoked,
            BlobStatus::Shredded,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let parsed: BlobStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, status);
        }
    }

    #[test]
    fn blob_status_display() {
        assert_eq!(BlobStatus::Active.to_string(), "active");
        assert_eq!(BlobStatus::Revoked.to_string(), "revoked");
        assert_eq!(BlobStatus::Shredded.to_string(), "shredded");
    }

    #[test]
    fn blob_metadata_serde_roundtrip() {
        let meta = BlobMetadata {
            id: "test-blob".into(),
            s3_key: "stash/test-blob".into(),
            wrapped_dek: "base64dek".into(),
            keyring: "stash-blobs".into(),
            key_version: 1,
            content_type: Some("image/png".into()),
            plaintext_size: 1024,
            encrypted_size: 1052,
            client_encrypted: false,
            status: BlobStatus::Active,
            created_at: 1700000000000,
            updated_at: 1700000000000,
        };
        let json = serde_json::to_string(&meta).unwrap();
        let parsed: BlobMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, "test-blob");
        assert_eq!(parsed.status, BlobStatus::Active);
        assert_eq!(parsed.plaintext_size, 1024);
    }

    #[test]
    fn viewer_map_operations() {
        let mut map = ViewerMap::default();
        assert!(map.is_empty());
        assert_eq!(map.len(), 0);
        assert!(map.find("viewer-1").is_none());

        map.viewers.push(ViewerRecord {
            viewer_id: "viewer-1".into(),
            s3_key: "stash/test-blob/viewer-1".into(),
            wrapped_dek: "dek1".into(),
            fingerprint_params: serde_json::json!({"mode": "invisible"}),
            created_at: 1700000000000,
        });

        assert!(!map.is_empty());
        assert_eq!(map.len(), 1);
        assert!(map.find("viewer-1").is_some());
        assert!(map.find("viewer-2").is_none());
    }

    #[test]
    fn inspect_result_from_metadata() {
        let meta = BlobMetadata {
            id: "test".into(),
            s3_key: "s3/test".into(),
            wrapped_dek: "dek".into(),
            keyring: "kr".into(),
            key_version: 2,
            content_type: Some("text/plain".into()),
            plaintext_size: 100,
            encrypted_size: 128,
            client_encrypted: false,
            status: BlobStatus::Active,
            created_at: 1000,
            updated_at: 2000,
        };
        let result = InspectResult::from((&meta, 3));
        assert_eq!(result.id, "test");
        assert_eq!(result.viewer_count, 3);
        assert_eq!(result.key_version, 2);
    }
}
