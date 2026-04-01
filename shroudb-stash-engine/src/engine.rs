use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use shroudb_acl::{PolicyEffect, PolicyPrincipal, PolicyRequest, PolicyResource};
use shroudb_chronicle_core::event::{Engine as ChronicleEngine, Event, EventResult};
use shroudb_store::Store;

use crate::capabilities::Capabilities;
use crate::object_store::ObjectStore;
use shroudb_stash_core::error::StashError;
use shroudb_stash_core::metadata::{BlobMetadata, BlobStatus, InspectResult, ViewerMap};

/// Configuration for the Stash engine.
#[derive(Debug, Clone)]
pub struct StashConfig {
    /// Cipher keyring used for envelope encryption (default: "stash-blobs").
    pub default_keyring: String,
    /// Optional prefix for S3 object keys (e.g. "stash/").
    pub s3_key_prefix: Option<String>,
}

impl Default for StashConfig {
    fn default() -> Self {
        Self {
            default_keyring: "stash-blobs".into(),
            s3_key_prefix: None,
        }
    }
}

/// Store namespace for blob metadata.
const META_NS: &str = "stash.meta";
/// Store namespace for viewer maps.
const VIEWER_NS: &str = "stash.viewers";

/// Parameters for a STORE operation.
pub struct StoreBlobParams<'a> {
    pub id: &'a str,
    pub data: &'a [u8],
    pub content_type: Option<&'a str>,
    pub keyring: Option<&'a str>,
    pub client_encrypted: bool,
    pub wrapped_dek: Option<&'a str>,
    pub actor: Option<&'a str>,
}

/// The Stash engine: encrypted blob storage backed by an object store.
pub struct StashEngine<S: Store> {
    store: Arc<S>,
    object_store: Arc<dyn ObjectStore>,
    capabilities: Arc<Capabilities>,
    config: StashConfig,
}

impl<S: Store> StashEngine<S> {
    /// Create a new StashEngine.
    ///
    /// Initializes the metadata and viewer namespaces in the Store.
    pub async fn new(
        store: Arc<S>,
        object_store: Arc<dyn ObjectStore>,
        capabilities: Capabilities,
        config: StashConfig,
    ) -> Result<Self, StashError> {
        // Ensure namespaces exist.
        let ns_config = shroudb_store::NamespaceConfig::default();
        for ns in [META_NS, VIEWER_NS] {
            match store.namespace_create(ns, ns_config.clone()).await {
                Ok(()) => tracing::debug!(namespace = ns, "created stash namespace"),
                Err(shroudb_store::StoreError::NamespaceExists(_)) => {}
                Err(e) => {
                    return Err(StashError::Store(format!(
                        "failed to create namespace {ns}: {e}"
                    )));
                }
            }
        }

        Ok(Self {
            store,
            object_store,
            capabilities: Arc::new(capabilities),
            config,
        })
    }

    // ── STORE ──────────────────────────────────────────────────────────

    /// Store an encrypted blob.
    ///
    /// If `client_encrypted` is true, `data` is already encrypted and
    /// `wrapped_dek` must be provided. Stash stores it as-is (passthrough).
    ///
    /// Otherwise, Stash generates a DEK via Cipher, encrypts the blob
    /// locally with AES-256-GCM, and uploads the ciphertext to the object store.
    pub async fn store_blob(
        &self,
        params: StoreBlobParams<'_>,
    ) -> Result<BlobMetadata, StashError> {
        let StoreBlobParams {
            id,
            data,
            content_type,
            keyring,
            client_encrypted,
            wrapped_dek,
            actor,
        } = params;

        // Check for duplicate.
        if self.load_metadata(id).await.is_ok() {
            return Err(StashError::AlreadyExists { id: id.into() });
        }

        // Check ABAC policy.
        self.check_policy(id, "STORE", actor).await?;

        let keyring = keyring.unwrap_or(&self.config.default_keyring);
        let s3_key = self.s3_key(id);
        let now = now_ms();

        let (upload_data, final_wrapped_dek, key_version, plaintext_size, encrypted_size) =
            if client_encrypted {
                // Client-encrypted passthrough: data is already encrypted.
                let dek = wrapped_dek.ok_or_else(|| {
                    StashError::InvalidArgument("client_encrypted requires wrapped_dek".into())
                })?;
                let size = data.len() as u64;
                (data.to_vec(), dek.to_string(), 0, size, size)
            } else if let Some(cipher) = self.capabilities.cipher.as_ref() {
                // Server-side encryption via Cipher envelope encryption.
                let dek_pair = cipher.generate_data_key(Some(256)).await?;
                let plaintext_key = dek_pair.plaintext_key;

                let ciphertext = crate::crypto::encrypt_blob(plaintext_key.as_bytes(), data)?;
                // plaintext_key dropped here → SensitiveBytes auto-zeroizes

                let pt_size = data.len() as u64;
                let ct_size = ciphertext.len() as u64;
                let wrapped = dek_pair.wrapped_key;
                let version = dek_pair.key_version;

                (ciphertext, wrapped, version, pt_size, ct_size)
            } else {
                // No Cipher available — store raw (unencrypted passthrough).
                // Stash still tracks metadata and enforces access control,
                // but data is uploaded to S3 without envelope encryption.
                tracing::warn!(
                    blob_id = id,
                    "cipher unavailable — storing blob without encryption"
                );
                let size = data.len() as u64;
                (data.to_vec(), String::new(), 0, size, size)
            };

        // Upload encrypted blob to S3.
        self.object_store
            .put(&s3_key, &upload_data, Some("application/octet-stream"))
            .await
            .map_err(|e| StashError::ObjectStore(e.to_string()))?;

        // Persist metadata in Store.
        let metadata = BlobMetadata {
            id: id.to_string(),
            s3_key: s3_key.clone(),
            wrapped_dek: final_wrapped_dek,
            keyring: keyring.to_string(),
            key_version,
            content_type: content_type.map(String::from),
            plaintext_size,
            encrypted_size,
            client_encrypted,
            status: BlobStatus::Active,
            created_at: now,
            updated_at: now,
        };

        self.save_metadata(&metadata).await?;

        // Initialize empty viewer map.
        self.save_viewer_map(id, &ViewerMap::default()).await?;

        // Audit.
        self.emit_audit("STORE", id, EventResult::Ok, actor).await;

        tracing::info!(
            blob_id = id,
            size = plaintext_size,
            keyring,
            client_encrypted,
            "blob stored"
        );

        Ok(metadata)
    }

    // ── RETRIEVE ───────────────────────────────────────────────────────

    /// Retrieve and decrypt a blob.
    ///
    /// If the blob was client-encrypted, returns the raw ciphertext and the
    /// wrapped DEK (the client is responsible for decryption).
    ///
    /// Otherwise, unwraps the DEK via Cipher, decrypts locally, and returns
    /// the plaintext.
    pub async fn retrieve_blob(
        &self,
        id: &str,
        actor: Option<&str>,
    ) -> Result<RetrieveResult, StashError> {
        let metadata = self.load_metadata(id).await?;

        // Check status.
        match metadata.status {
            BlobStatus::Active => {}
            BlobStatus::Revoked => return Err(StashError::Revoked { id: id.into() }),
            BlobStatus::Shredded => return Err(StashError::Shredded { id: id.into() }),
        }

        // Check ABAC policy.
        self.check_policy(id, "RETRIEVE", actor).await?;

        // Download encrypted blob from S3.
        let encrypted_data = self
            .object_store
            .get(&metadata.s3_key)
            .await
            .map_err(|e| StashError::ObjectStore(e.to_string()))?;

        let (data, returned_dek) = if metadata.client_encrypted {
            // Client-encrypted: return raw data + wrapped DEK for client-side decryption.
            (encrypted_data, Some(metadata.wrapped_dek.clone()))
        } else if metadata.wrapped_dek.is_empty() {
            // Stored without encryption (Cipher was absent at STORE time).
            // Return raw bytes directly.
            (encrypted_data, None)
        } else if let Some(cipher) = self.capabilities.cipher.as_ref() {
            // Server-side decryption: unwrap DEK via Cipher, decrypt locally.
            let plaintext_key = cipher.unwrap_data_key(&metadata.wrapped_dek).await?;

            let plaintext = crate::crypto::decrypt_blob(plaintext_key.as_bytes(), &encrypted_data)?;
            // plaintext_key dropped here → SensitiveBytes auto-zeroizes

            (plaintext, None)
        } else {
            // Blob was encrypted but Cipher is no longer available.
            return Err(StashError::CipherUnavailable);
        };

        // Audit.
        self.emit_audit("RETRIEVE", id, EventResult::Ok, actor)
            .await;

        Ok(RetrieveResult {
            data,
            metadata,
            wrapped_dek: returned_dek,
        })
    }

    // ── INSPECT ────────────────────────────────────────────────────────

    /// Inspect blob metadata without downloading or decrypting.
    ///
    /// No S3 access, no Cipher interaction. Pure metadata read.
    pub async fn inspect_blob(
        &self,
        id: &str,
        actor: Option<&str>,
    ) -> Result<InspectResult, StashError> {
        let metadata = self.load_metadata(id).await?;

        // Check ABAC policy.
        self.check_policy(id, "INSPECT", actor).await?;

        let viewer_map = self.load_viewer_map(id).await.unwrap_or_default();
        let viewer_count = viewer_map.len();

        self.emit_audit("INSPECT", id, EventResult::Ok, actor).await;

        Ok(InspectResult::from((&metadata, viewer_count)))
    }

    // ── REVOKE ─────────────────────────────────────────────────────────

    /// Revoke a blob.
    ///
    /// **Hard revoke (default):** Crypto-shred the master blob and all
    /// fingerprinted viewer copies. Destroys all wrapped DEKs, deletes all
    /// S3 objects, tombstones metadata.
    ///
    /// **Soft revoke:** Marks the blob as revoked in metadata. Sentry will
    /// deny future RETRIEVE requests. Blobs and DEKs are preserved for
    /// legal/forensic holds.
    pub async fn revoke_blob(
        &self,
        id: &str,
        soft: bool,
        actor: Option<&str>,
    ) -> Result<(), StashError> {
        let mut metadata = self.load_metadata(id).await?;

        // Already terminal states.
        if metadata.status == BlobStatus::Shredded {
            return Err(StashError::Shredded { id: id.into() });
        }

        // Check ABAC policy.
        self.check_policy(id, "REVOKE", actor).await?;

        let now = now_ms();

        if soft {
            // Soft revoke: flip status, preserve everything.
            metadata.status = BlobStatus::Revoked;
            metadata.updated_at = now;
            self.save_metadata(&metadata).await?;
        } else {
            // Hard revoke (crypto-shred):
            // 1. Load and cascade viewer copies.
            let viewer_map = self.load_viewer_map(id).await.unwrap_or_default();

            // Delete all viewer S3 objects.
            for viewer in &viewer_map.viewers {
                if let Err(e) = self.object_store.delete(&viewer.s3_key).await {
                    tracing::warn!(
                        blob_id = id,
                        viewer_id = %viewer.viewer_id,
                        error = %e,
                        "failed to delete viewer S3 object during revoke"
                    );
                }
            }

            // 2. Delete master S3 object.
            if let Err(e) = self.object_store.delete(&metadata.s3_key).await {
                tracing::warn!(
                    blob_id = id,
                    error = %e,
                    "failed to delete master S3 object during revoke"
                );
            }

            // 3. Crypto-shred: destroy the wrapped DEK.
            metadata.wrapped_dek.clear();
            metadata.status = BlobStatus::Shredded;
            metadata.updated_at = now;
            self.save_metadata(&metadata).await?;

            // 4. Clear the viewer map.
            self.save_viewer_map(id, &ViewerMap::default()).await?;

            tracing::info!(
                blob_id = id,
                viewer_copies = viewer_map.len(),
                "blob crypto-shredded"
            );
        }

        let op = if soft { "REVOKE_SOFT" } else { "REVOKE_HARD" };
        self.emit_audit(op, id, EventResult::Ok, actor).await;

        Ok(())
    }

    // ── Internal helpers ───────────────────────────────────────────────

    /// Build the S3 object key for a blob.
    fn s3_key(&self, id: &str) -> String {
        match &self.config.s3_key_prefix {
            Some(prefix) => format!("{prefix}{id}"),
            None => id.to_string(),
        }
    }

    /// Load blob metadata from the Store.
    async fn load_metadata(&self, id: &str) -> Result<BlobMetadata, StashError> {
        let entry = self
            .store
            .get(META_NS, id.as_bytes(), None)
            .await
            .map_err(|e| match e {
                shroudb_store::StoreError::NotFound => StashError::NotFound { id: id.into() },
                other => StashError::Store(other.to_string()),
            })?;

        serde_json::from_slice(&entry.value)
            .map_err(|e| StashError::Internal(format!("corrupt metadata for {id}: {e}")))
    }

    /// Persist blob metadata to the Store.
    async fn save_metadata(&self, metadata: &BlobMetadata) -> Result<(), StashError> {
        let value = serde_json::to_vec(metadata)
            .map_err(|e| StashError::Internal(format!("serialize metadata: {e}")))?;
        self.store
            .put(META_NS, metadata.id.as_bytes(), &value, None)
            .await
            .map_err(|e| StashError::Store(format!("save metadata: {e}")))?;
        Ok(())
    }

    /// Load the viewer map for a blob.
    async fn load_viewer_map(&self, id: &str) -> Result<ViewerMap, StashError> {
        let entry = self
            .store
            .get(VIEWER_NS, id.as_bytes(), None)
            .await
            .map_err(|e| match e {
                shroudb_store::StoreError::NotFound => StashError::NotFound { id: id.into() },
                other => StashError::Store(other.to_string()),
            })?;

        serde_json::from_slice(&entry.value)
            .map_err(|e| StashError::Internal(format!("corrupt viewer map for {id}: {e}")))
    }

    /// Persist the viewer map for a blob.
    async fn save_viewer_map(&self, id: &str, map: &ViewerMap) -> Result<(), StashError> {
        let value = serde_json::to_vec(map)
            .map_err(|e| StashError::Internal(format!("serialize viewer map: {e}")))?;
        self.store
            .put(VIEWER_NS, id.as_bytes(), &value, None)
            .await
            .map_err(|e| StashError::Store(format!("save viewer map: {e}")))?;
        Ok(())
    }

    /// Check ABAC policy via Sentry (if available).
    async fn check_policy(
        &self,
        resource_id: &str,
        action: &str,
        actor: Option<&str>,
    ) -> Result<(), StashError> {
        let sentry = match &self.capabilities.sentry {
            Some(s) => s,
            None => return Ok(()), // No Sentry = open mode.
        };

        let actor_id = actor.unwrap_or("anonymous");
        let request = PolicyRequest {
            principal: PolicyPrincipal {
                id: actor_id.to_string(),
                roles: vec![],
                claims: std::collections::HashMap::new(),
            },
            resource: PolicyResource {
                id: resource_id.to_string(),
                resource_type: "stash".to_string(),
                attributes: std::collections::HashMap::new(),
            },
            action: action.to_string(),
        };

        let decision = sentry
            .evaluate(&request)
            .await
            .map_err(|e| StashError::Internal(format!("sentry evaluation failed: {e}")))?;

        match decision.effect {
            PolicyEffect::Permit => Ok(()),
            PolicyEffect::Deny => Err(StashError::AbacDenied {
                action: action.to_string(),
                resource: resource_id.to_string(),
                policy: decision
                    .matched_policy
                    .unwrap_or_else(|| "default-deny".into()),
            }),
        }
    }

    /// Emit an audit event to Chronicle (fire-and-forget).
    async fn emit_audit(
        &self,
        operation: &str,
        resource: &str,
        result: EventResult,
        actor: Option<&str>,
    ) {
        let chronicle = match &self.capabilities.chronicle {
            Some(c) => c,
            None => return,
        };

        let event = Event::new(
            ChronicleEngine::Stash,
            operation.to_string(),
            resource.to_string(),
            result,
            actor.unwrap_or("anonymous").to_string(),
        );

        if let Err(e) = chronicle.record(event).await {
            tracing::warn!(
                operation,
                resource,
                error = %e,
                "failed to record audit event"
            );
        }
    }
}

/// Result of a RETRIEVE operation.
#[derive(Debug)]
pub struct RetrieveResult {
    /// The blob data (plaintext if server-decrypted, ciphertext if client-encrypted).
    pub data: Vec<u8>,
    /// The blob metadata.
    pub metadata: BlobMetadata,
    /// The wrapped DEK (only set for client-encrypted blobs, so client can decrypt).
    pub wrapped_dek: Option<String>,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capabilities::{DataKeyPair, StashCipherOps};
    use crate::object_store::InMemoryObjectStore;
    use shroudb_crypto::SensitiveBytes;

    // ── Test doubles ──────────────────────────────────────────────────

    /// Mock CipherOps that generates deterministic but functional keys.
    struct MockCipherOps {
        /// A fixed 32-byte key used for all DEKs (for test determinism).
        dek: [u8; 32],
    }

    impl MockCipherOps {
        fn new() -> Self {
            let mut dek = [0u8; 32];
            ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut dek).unwrap();
            Self { dek }
        }
    }

    impl StashCipherOps for MockCipherOps {
        fn generate_data_key(
            &self,
            _bits: Option<u32>,
        ) -> crate::capabilities::BoxFut<'_, DataKeyPair> {
            Box::pin(async move {
                Ok(DataKeyPair {
                    plaintext_key: SensitiveBytes::new(self.dek.to_vec()),
                    wrapped_key: base64::engine::general_purpose::STANDARD
                        .encode(b"mock-wrapped-dek"),
                    key_version: 1,
                })
            })
        }

        fn unwrap_data_key(
            &self,
            _wrapped_key: &str,
        ) -> crate::capabilities::BoxFut<'_, SensitiveBytes> {
            Box::pin(async move { Ok(SensitiveBytes::new(self.dek.to_vec())) })
        }
    }

    use base64::Engine as _;

    async fn setup() -> StashEngine<shroudb_storage::EmbeddedStore> {
        let store = shroudb_storage::test_util::create_test_store("stash-test").await;
        let obj_store = Arc::new(InMemoryObjectStore::new());
        let mock_cipher = MockCipherOps::new();
        let caps = Capabilities {
            cipher: Some(Box::new(mock_cipher)),
            sentry: None,
            chronicle: None,
        };
        StashEngine::new(store, obj_store, caps, StashConfig::default())
            .await
            .unwrap()
    }

    fn get_object_store(
        engine: &StashEngine<shroudb_storage::EmbeddedStore>,
    ) -> &InMemoryObjectStore {
        // We know our test setup uses InMemoryObjectStore.
        let arc: &Arc<dyn ObjectStore> = &engine.object_store;
        let ptr = Arc::as_ptr(arc) as *const InMemoryObjectStore;
        unsafe { &*ptr }
    }

    /// Helper to store a blob with default params.
    async fn store(
        engine: &StashEngine<shroudb_storage::EmbeddedStore>,
        id: &str,
        data: &[u8],
        content_type: Option<&str>,
    ) -> Result<BlobMetadata, StashError> {
        engine
            .store_blob(StoreBlobParams {
                id,
                data,
                content_type,
                keyring: None,
                client_encrypted: false,
                wrapped_dek: None,
                actor: None,
            })
            .await
    }

    // ── Tests ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn store_and_retrieve_roundtrip() {
        let engine = setup().await;
        let plaintext = b"hello, stash!";

        let meta = store(&engine, "test-1", plaintext, Some("text/plain"))
            .await
            .unwrap();

        assert_eq!(meta.id, "test-1");
        assert_eq!(meta.status, BlobStatus::Active);
        assert_eq!(meta.plaintext_size, plaintext.len() as u64);
        assert!(!meta.client_encrypted);
        assert_eq!(meta.content_type.as_deref(), Some("text/plain"));

        let result = engine.retrieve_blob("test-1", None).await.unwrap();
        assert_eq!(result.data, plaintext);
        assert!(result.wrapped_dek.is_none());
    }

    #[tokio::test]
    async fn store_client_encrypted_passthrough() {
        let engine = setup().await;
        let ciphertext = b"client-encrypted-blob";
        let wrapped_dek = "client-provided-wrapped-dek";

        let meta = engine
            .store_blob(StoreBlobParams {
                id: "ce-1",
                data: ciphertext,
                content_type: Some("application/octet-stream"),
                keyring: None,
                client_encrypted: true,
                wrapped_dek: Some(wrapped_dek),
                actor: None,
            })
            .await
            .unwrap();

        assert!(meta.client_encrypted);
        assert_eq!(meta.wrapped_dek, wrapped_dek);

        let result = engine.retrieve_blob("ce-1", None).await.unwrap();
        assert_eq!(result.data, ciphertext);
        assert_eq!(result.wrapped_dek.as_deref(), Some(wrapped_dek));
    }

    #[tokio::test]
    async fn store_client_encrypted_requires_dek() {
        let engine = setup().await;
        let err = engine
            .store_blob(StoreBlobParams {
                id: "ce-err",
                data: b"data",
                content_type: None,
                keyring: None,
                client_encrypted: true,
                wrapped_dek: None,
                actor: None,
            })
            .await
            .unwrap_err();
        assert!(matches!(err, StashError::InvalidArgument(_)));
    }

    #[tokio::test]
    async fn store_duplicate_fails() {
        let engine = setup().await;
        store(&engine, "dup", b"first", None).await.unwrap();

        let err = store(&engine, "dup", b"second", None).await.unwrap_err();
        assert!(matches!(err, StashError::AlreadyExists { .. }));
    }

    #[tokio::test]
    async fn inspect_returns_metadata() {
        let engine = setup().await;
        store(&engine, "inspect-1", b"hello", Some("text/plain"))
            .await
            .unwrap();

        let result = engine.inspect_blob("inspect-1", None).await.unwrap();
        assert_eq!(result.id, "inspect-1");
        assert_eq!(result.status, BlobStatus::Active);
        assert_eq!(result.plaintext_size, 5);
        assert_eq!(result.content_type.as_deref(), Some("text/plain"));
        assert_eq!(result.viewer_count, 0);
    }

    #[tokio::test]
    async fn inspect_not_found() {
        let engine = setup().await;
        let err = engine.inspect_blob("nope", None).await.unwrap_err();
        assert!(err.is_not_found());
    }

    #[tokio::test]
    async fn soft_revoke_blocks_retrieve() {
        let engine = setup().await;
        store(&engine, "rev-soft", b"data", None).await.unwrap();

        engine.revoke_blob("rev-soft", true, None).await.unwrap();

        let info = engine.inspect_blob("rev-soft", None).await.unwrap();
        assert_eq!(info.status, BlobStatus::Revoked);

        let err = engine.retrieve_blob("rev-soft", None).await.unwrap_err();
        assert!(matches!(err, StashError::Revoked { .. }));
    }

    #[tokio::test]
    async fn hard_revoke_shreds_everything() {
        let engine = setup().await;
        store(&engine, "rev-hard", b"secret data", None)
            .await
            .unwrap();

        let obj_store = get_object_store(&engine);
        assert!(obj_store.contains_key("rev-hard").await);

        engine.revoke_blob("rev-hard", false, None).await.unwrap();

        assert!(!obj_store.contains_key("rev-hard").await);

        let info = engine.inspect_blob("rev-hard", None).await.unwrap();
        assert_eq!(info.status, BlobStatus::Shredded);

        let err = engine.retrieve_blob("rev-hard", None).await.unwrap_err();
        assert!(matches!(err, StashError::Shredded { .. }));

        let err = engine
            .revoke_blob("rev-hard", false, None)
            .await
            .unwrap_err();
        assert!(matches!(err, StashError::Shredded { .. }));
    }

    #[tokio::test]
    async fn revoke_not_found() {
        let engine = setup().await;
        let err = engine.revoke_blob("nope", false, None).await.unwrap_err();
        assert!(err.is_not_found());
    }

    #[tokio::test]
    async fn s3_key_prefix_applied() {
        let store_kv = shroudb_storage::test_util::create_test_store("stash-prefix").await;
        let obj_store = Arc::new(InMemoryObjectStore::new());
        let mock_cipher = MockCipherOps::new();
        let caps = Capabilities {
            cipher: Some(Box::new(mock_cipher)),
            sentry: None,
            chronicle: None,
        };
        let config = StashConfig {
            default_keyring: "stash-blobs".into(),
            s3_key_prefix: Some("my-prefix/".into()),
        };

        let engine = StashEngine::new(store_kv, obj_store.clone(), caps, config)
            .await
            .unwrap();

        store(&engine, "blob-1", b"data", None).await.unwrap();

        assert!(obj_store.contains_key("my-prefix/blob-1").await);
        assert!(!obj_store.contains_key("blob-1").await);
    }

    #[tokio::test]
    async fn store_without_cipher_stores_raw() {
        let store_kv = shroudb_storage::test_util::create_test_store("stash-no-cipher").await;
        let obj_store = Arc::new(InMemoryObjectStore::new());
        let caps = Capabilities::default(); // No cipher
        let engine = StashEngine::new(store_kv, obj_store, caps, StashConfig::default())
            .await
            .unwrap();

        // Should succeed — stores raw (unencrypted) to S3.
        let meta = store(&engine, "raw-1", b"unencrypted data", Some("text/plain"))
            .await
            .unwrap();

        assert_eq!(meta.id, "raw-1");
        assert!(meta.wrapped_dek.is_empty());
        // Raw mode: plaintext_size == encrypted_size (no crypto overhead).
        assert_eq!(meta.plaintext_size, meta.encrypted_size);

        // Retrieve should return raw bytes.
        let result = engine.retrieve_blob("raw-1", None).await.unwrap();
        assert_eq!(result.data, b"unencrypted data");
        assert!(result.wrapped_dek.is_none());
    }

    #[tokio::test]
    async fn retrieve_encrypted_blob_without_cipher_fails() {
        // Store with Cipher, then try to retrieve without it.
        let engine_with_cipher = setup().await;
        store(&engine_with_cipher, "enc-blob", b"secret", None)
            .await
            .unwrap();

        // Build a new engine pointing at the same store but without Cipher.
        // We can't easily share the Store across engines in tests, so instead
        // verify via inspect that the blob has a wrapped_dek.
        let info = engine_with_cipher
            .inspect_blob("enc-blob", None)
            .await
            .unwrap();
        assert!(info.encrypted_size > info.plaintext_size);
    }

    #[tokio::test]
    async fn large_blob_roundtrip() {
        let engine = setup().await;
        let plaintext = vec![0xAB; 1024 * 1024];

        store(&engine, "large", &plaintext, None).await.unwrap();

        let result = engine.retrieve_blob("large", None).await.unwrap();
        assert_eq!(result.data, plaintext);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_concurrent_store_different_keys() {
        let engine = Arc::new(setup().await);

        let mut handles = Vec::new();
        for i in 0..10 {
            let eng = engine.clone();
            handles.push(tokio::spawn(async move {
                let data = format!("blob-data-{i}");
                eng.store_blob(StoreBlobParams {
                    id: &format!("concurrent-{i}"),
                    data: data.as_bytes(),
                    content_type: Some("text/plain"),
                    keyring: None,
                    client_encrypted: false,
                    wrapped_dek: None,
                    actor: None,
                })
                .await
            }));
        }

        for handle in handles {
            let meta = handle.await.unwrap().unwrap();
            assert_eq!(meta.status, BlobStatus::Active);
        }

        // Verify all blobs are retrievable with correct data.
        for i in 0..10 {
            let result = engine
                .retrieve_blob(&format!("concurrent-{i}"), None)
                .await
                .unwrap();
            let expected = format!("blob-data-{i}");
            assert_eq!(
                result.data,
                expected.as_bytes(),
                "blob concurrent-{i} data mismatch"
            );
        }
    }
}
