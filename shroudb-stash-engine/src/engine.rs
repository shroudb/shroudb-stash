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
    /// Blobs larger than this threshold (in bytes) use chunked streaming
    /// encryption to bound memory usage. Default: 10 MB. Set to 0 to disable.
    pub streaming_threshold_bytes: usize,
    /// Whether to validate client-encrypted blob integrity on STORE.
    ///
    /// When `true` (the default), Stash validates:
    /// - The wrapped DEK is valid base64 encoding
    /// - The wrapped DEK decodes to at least 32 bytes (AES-256 key + wrapping overhead)
    /// - The ciphertext is at least 28 bytes (12-byte nonce + 16-byte auth tag)
    ///
    /// Set to `false` only when clients use a non-AES-256-GCM encryption scheme.
    pub validate_client_encrypted: bool,
}

/// Default streaming threshold: 10 MB.
const DEFAULT_STREAMING_THRESHOLD: usize = 10 * 1024 * 1024;

impl Default for StashConfig {
    fn default() -> Self {
        Self {
            default_keyring: "stash-blobs".into(),
            s3_key_prefix: None,
            streaming_threshold_bytes: DEFAULT_STREAMING_THRESHOLD,
            validate_client_encrypted: true,
        }
    }
}

/// Store namespace for blob metadata.
const META_NS: &str = "stash.meta";
/// Store namespace for viewer maps.
const VIEWER_NS: &str = "stash.viewers";

/// Parameters for a STORE operation.
pub struct StoreBlobParams<'a> {
    pub tenant: &'a str,
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
            tenant,
            id,
            data,
            content_type,
            keyring,
            client_encrypted,
            wrapped_dek,
            actor,
        } = params;

        // Check for duplicate.
        if self.load_metadata(tenant, id).await.is_ok() {
            return Err(StashError::AlreadyExists { id: id.into() });
        }

        // Check ABAC policy.
        self.check_policy(tenant, id, "STORE", actor).await?;

        let keyring = keyring.unwrap_or(&self.config.default_keyring);
        let s3_key = self.s3_key(tenant, id);
        let now = now_ms();

        let (upload_data, final_wrapped_dek, key_version, plaintext_size, encrypted_size) =
            if client_encrypted {
                // Client-encrypted passthrough: data is already encrypted.
                let dek = wrapped_dek.ok_or_else(|| {
                    StashError::InvalidArgument("client_encrypted requires wrapped_dek".into())
                })?;

                if self.config.validate_client_encrypted {
                    Self::validate_client_encrypted_blob(dek, data)?;
                }

                let size = data.len() as u64;
                (data.to_vec(), dek.to_string(), 0, size, size)
            } else if let Some(cipher) = self.capabilities.cipher.as_ref() {
                // Server-side encryption via Cipher envelope encryption.
                let dek_pair = cipher.generate_data_key(Some(256)).await?;
                let plaintext_key = dek_pair.plaintext_key;

                let use_streaming = self.config.streaming_threshold_bytes > 0
                    && data.len() > self.config.streaming_threshold_bytes;
                let ciphertext = if use_streaming {
                    crate::crypto::encrypt_blob_chunked(
                        plaintext_key.as_bytes(),
                        data,
                        id.as_bytes(),
                    )?
                } else {
                    crate::crypto::encrypt_blob(plaintext_key.as_bytes(), data, id.as_bytes())?
                };
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
            tenant_id: tenant.to_string(),
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
        self.save_viewer_map(tenant, id, &ViewerMap::default())
            .await?;

        // Audit.
        self.emit_audit("STORE", tenant, id, EventResult::Ok, actor)
            .await;

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
        tenant: &str,
        id: &str,
        actor: Option<&str>,
    ) -> Result<RetrieveResult, StashError> {
        let metadata = self.load_metadata(tenant, id).await?;

        // Fail-closed: if tenant doesn't match, return NotFound to avoid leaking blob existence.
        if metadata.tenant_id != tenant {
            return Err(StashError::NotFound { id: id.into() });
        }

        // Check status.
        match metadata.status {
            BlobStatus::Active => {}
            BlobStatus::Revoked => return Err(StashError::Revoked { id: id.into() }),
            BlobStatus::Shredded => return Err(StashError::Shredded { id: id.into() }),
        }

        // Check ABAC policy.
        self.check_policy(tenant, id, "RETRIEVE", actor).await?;

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

            let plaintext = if crate::crypto::is_chunked(&encrypted_data) {
                crate::crypto::decrypt_blob_chunked(
                    plaintext_key.as_bytes(),
                    &encrypted_data,
                    id.as_bytes(),
                )?
            } else {
                // Use compat decryption to handle blobs encrypted before
                // AAD binding was added (empty AAD fallback).
                let (data, used_legacy) = crate::crypto::decrypt_blob_compat(
                    plaintext_key.as_bytes(),
                    &encrypted_data,
                    id.as_bytes(),
                )?;
                if used_legacy {
                    tracing::warn!(
                        blob_id = id,
                        "blob was encrypted without AAD binding — re-store to upgrade"
                    );
                }
                data
            };
            // plaintext_key dropped here → SensitiveBytes auto-zeroizes

            (plaintext, None)
        } else {
            // Blob was encrypted but Cipher is no longer available.
            return Err(StashError::CipherUnavailable);
        };

        // Audit.
        self.emit_audit("RETRIEVE", tenant, id, EventResult::Ok, actor)
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
        tenant: &str,
        id: &str,
        actor: Option<&str>,
    ) -> Result<InspectResult, StashError> {
        let metadata = self.load_metadata(tenant, id).await?;

        // Fail-closed: if tenant doesn't match, return NotFound to avoid leaking blob existence.
        if metadata.tenant_id != tenant {
            return Err(StashError::NotFound { id: id.into() });
        }

        // Check ABAC policy.
        self.check_policy(tenant, id, "INSPECT", actor).await?;

        let viewer_map = self.load_viewer_map(tenant, id).await.unwrap_or_default();
        let viewer_count = viewer_map.len();

        self.emit_audit("INSPECT", tenant, id, EventResult::Ok, actor)
            .await;

        Ok(InspectResult::from((&metadata, viewer_count)))
    }

    // ── REWRAP ─────────────────────────────────────────────────────────

    /// Re-wrap a blob's DEK under the current Cipher key version.
    ///
    /// The blob ciphertext in S3 is NOT re-encrypted — only the wrapped DEK
    /// in metadata is updated. This is useful after a Cipher key rotation to
    /// migrate blobs to the new key version.
    pub async fn rewrap_blob(
        &self,
        tenant: &str,
        id: &str,
        actor: Option<&str>,
    ) -> Result<BlobMetadata, StashError> {
        let mut metadata = self.load_metadata(tenant, id).await?;

        // Fail-closed: if tenant doesn't match, return NotFound to avoid leaking blob existence.
        if metadata.tenant_id != tenant {
            return Err(StashError::NotFound { id: id.into() });
        }

        match metadata.status {
            BlobStatus::Active => {}
            BlobStatus::Revoked => return Err(StashError::Revoked { id: id.into() }),
            BlobStatus::Shredded => return Err(StashError::Shredded { id: id.into() }),
        }

        if metadata.client_encrypted {
            return Err(StashError::InvalidArgument(
                "cannot rewrap client-encrypted blob — client manages key material".into(),
            ));
        }

        if metadata.wrapped_dek.is_empty() {
            return Err(StashError::InvalidArgument(
                "blob has no wrapped DEK (stored without encryption)".into(),
            ));
        }

        self.check_policy(tenant, id, "REWRAP", actor).await?;

        let cipher = self
            .capabilities
            .cipher
            .as_ref()
            .ok_or(StashError::CipherUnavailable)?;

        let new_pair = cipher.rewrap_data_key(&metadata.wrapped_dek).await?;
        metadata.wrapped_dek = new_pair.wrapped_key;
        metadata.key_version = new_pair.key_version;
        metadata.updated_at = now_ms();

        self.save_metadata(&metadata).await?;

        self.emit_audit("REWRAP", tenant, id, EventResult::Ok, actor)
            .await;

        Ok(metadata)
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
        tenant: &str,
        id: &str,
        soft: bool,
        actor: Option<&str>,
    ) -> Result<(), StashError> {
        let mut metadata = self.load_metadata(tenant, id).await?;

        // Fail-closed: if tenant doesn't match, return NotFound to avoid leaking blob existence.
        if metadata.tenant_id != tenant {
            return Err(StashError::NotFound { id: id.into() });
        }

        // Already terminal states.
        if metadata.status == BlobStatus::Shredded {
            return Err(StashError::Shredded { id: id.into() });
        }

        // Check ABAC policy.
        self.check_policy(tenant, id, "REVOKE", actor).await?;

        let now = now_ms();

        if soft {
            // Soft revoke: flip status, preserve everything.
            metadata.status = BlobStatus::Revoked;
            metadata.updated_at = now;
            self.save_metadata(&metadata).await?;
        } else {
            // Hard revoke (crypto-shred):
            // 1. Load and cascade viewer copies.
            let viewer_map = self.load_viewer_map(tenant, id).await.unwrap_or_default();

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
            self.save_viewer_map(tenant, id, &ViewerMap::default())
                .await?;

            tracing::info!(
                blob_id = id,
                viewer_copies = viewer_map.len(),
                "blob crypto-shredded"
            );
        }

        let op = if soft { "REVOKE_SOFT" } else { "REVOKE_HARD" };
        self.emit_audit(op, tenant, id, EventResult::Ok, actor)
            .await;

        Ok(())
    }

    // ── Internal helpers ───────────────────────────────────────────────

    /// Build the tenant-scoped Store key for metadata/viewer maps.
    fn meta_key(tenant: &str, id: &str) -> Vec<u8> {
        format!("{tenant}:{id}").into_bytes()
    }

    /// Build the S3 object key for a blob, scoped by tenant.
    fn s3_key(&self, tenant: &str, id: &str) -> String {
        match &self.config.s3_key_prefix {
            Some(prefix) => format!("{prefix}{tenant}/{id}"),
            None => format!("{tenant}/{id}"),
        }
    }

    /// Load blob metadata from the Store.
    async fn load_metadata(&self, tenant: &str, id: &str) -> Result<BlobMetadata, StashError> {
        let key = Self::meta_key(tenant, id);
        let entry = self
            .store
            .get(META_NS, &key, None)
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
        let key = Self::meta_key(&metadata.tenant_id, &metadata.id);
        let value = serde_json::to_vec(metadata)
            .map_err(|e| StashError::Internal(format!("serialize metadata: {e}")))?;
        self.store
            .put(META_NS, &key, &value, None)
            .await
            .map_err(|e| StashError::Store(format!("save metadata: {e}")))?;
        Ok(())
    }

    /// Load the viewer map for a blob.
    async fn load_viewer_map(&self, tenant: &str, id: &str) -> Result<ViewerMap, StashError> {
        let key = Self::meta_key(tenant, id);
        let entry = self
            .store
            .get(VIEWER_NS, &key, None)
            .await
            .map_err(|e| match e {
                shroudb_store::StoreError::NotFound => StashError::NotFound { id: id.into() },
                other => StashError::Store(other.to_string()),
            })?;

        serde_json::from_slice(&entry.value)
            .map_err(|e| StashError::Internal(format!("corrupt viewer map for {id}: {e}")))
    }

    /// Persist the viewer map for a blob.
    async fn save_viewer_map(
        &self,
        tenant: &str,
        id: &str,
        map: &ViewerMap,
    ) -> Result<(), StashError> {
        let key = Self::meta_key(tenant, id);
        let value = serde_json::to_vec(map)
            .map_err(|e| StashError::Internal(format!("serialize viewer map: {e}")))?;
        self.store
            .put(VIEWER_NS, &key, &value, None)
            .await
            .map_err(|e| StashError::Store(format!("save viewer map: {e}")))?;
        Ok(())
    }

    // ── LIST ──────────────────────────────────────────────────────────

    /// List blobs for a tenant.
    ///
    /// Scans the metadata namespace for keys with the `{tenant}:` prefix.
    /// Returns inspect results for matching blobs (up to `limit`).
    pub async fn list_blobs(
        &self,
        tenant: &str,
        limit: usize,
        actor: Option<&str>,
    ) -> Result<Vec<InspectResult>, StashError> {
        let prefix = format!("{tenant}:");
        let page = self
            .store
            .list(META_NS, Some(prefix.as_bytes()), None, limit)
            .await
            .map_err(|e| StashError::Store(format!("list blobs: {e}")))?;

        let mut results = Vec::with_capacity(page.keys.len());
        for key in &page.keys {
            let entry = self
                .store
                .get(META_NS, key, None)
                .await
                .map_err(|e| StashError::Store(format!("list: get metadata: {e}")))?;
            let metadata: BlobMetadata = serde_json::from_slice(&entry.value)
                .map_err(|e| StashError::Internal(format!("corrupt metadata: {e}")))?;
            let viewer_map = self
                .load_viewer_map(tenant, &metadata.id)
                .await
                .unwrap_or_default();
            results.push(InspectResult::from((&metadata, viewer_map.len())));
        }

        self.emit_audit("LIST", tenant, "*", EventResult::Ok, actor)
            .await;

        Ok(results)
    }

    /// Check ABAC policy via Sentry (if available).
    async fn check_policy(
        &self,
        tenant: &str,
        resource_id: &str,
        action: &str,
        actor: Option<&str>,
    ) -> Result<(), StashError> {
        let sentry = match &self.capabilities.sentry {
            Some(s) => s,
            None => return Ok(()), // No Sentry = open mode.
        };

        let actor_id = actor.unwrap_or("anonymous");
        let mut resource_attrs = std::collections::HashMap::new();
        resource_attrs.insert("tenant".to_string(), tenant.to_string());
        let request = PolicyRequest {
            principal: PolicyPrincipal {
                id: actor_id.to_string(),
                roles: vec![],
                claims: std::collections::HashMap::new(),
            },
            resource: PolicyResource {
                id: resource_id.to_string(),
                resource_type: "stash".to_string(),
                attributes: resource_attrs,
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

    /// Validate a client-encrypted blob's wrapped DEK and ciphertext format.
    ///
    /// Checks:
    /// - `wrapped_dek` is valid base64
    /// - Decoded wrapped DEK is at least 32 bytes (AES-256 key + wrapping overhead)
    /// - Ciphertext is at least `MIN_CIPHERTEXT_LEN` bytes (nonce + auth tag)
    fn validate_client_encrypted_blob(
        wrapped_dek: &str,
        ciphertext: &[u8],
    ) -> Result<(), StashError> {
        use base64::Engine as _;

        // Validate wrapped DEK is valid base64.
        let decoded_dek = base64::engine::general_purpose::STANDARD
            .decode(wrapped_dek)
            .map_err(|e| {
                StashError::InvalidArgument(format!("wrapped_dek is not valid base64: {e}"))
            })?;

        // A wrapped AES-256 key must be at least 32 bytes (the raw key itself)
        // plus wrapping overhead. In practice, Cipher CiphertextEnvelopes are
        // significantly larger, but 32 bytes is the absolute minimum.
        const MIN_WRAPPED_DEK_LEN: usize = 32;
        if decoded_dek.len() < MIN_WRAPPED_DEK_LEN {
            return Err(StashError::InvalidArgument(format!(
                "wrapped_dek too short: {} bytes (minimum {MIN_WRAPPED_DEK_LEN})",
                decoded_dek.len()
            )));
        }

        // Ciphertext must contain at least a nonce and an auth tag.
        if ciphertext.len() < crate::crypto::MIN_CIPHERTEXT_LEN {
            return Err(StashError::InvalidArgument(format!(
                "client-encrypted ciphertext too short: {} bytes (minimum {})",
                ciphertext.len(),
                crate::crypto::MIN_CIPHERTEXT_LEN
            )));
        }

        Ok(())
    }

    /// Emit an audit event to Chronicle (fire-and-forget).
    async fn emit_audit(
        &self,
        operation: &str,
        tenant: &str,
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
            "blob".to_string(),
            format!("{tenant}:{resource}"),
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
            ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut dek)
                .expect("CSPRNG failed — system entropy source is broken");
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

        fn rewrap_data_key(
            &self,
            _old_wrapped_key: &str,
        ) -> crate::capabilities::BoxFut<'_, DataKeyPair> {
            Box::pin(async move {
                Ok(DataKeyPair {
                    plaintext_key: SensitiveBytes::new(self.dek.to_vec()),
                    wrapped_key: base64::engine::general_purpose::STANDARD
                        .encode(b"mock-rewrapped-dek"),
                    key_version: 2,
                })
            })
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

    /// Default tenant used in tests.
    const TEST_TENANT: &str = "test-tenant";

    /// Helper to store a blob with default params.
    async fn store(
        engine: &StashEngine<shroudb_storage::EmbeddedStore>,
        id: &str,
        data: &[u8],
        content_type: Option<&str>,
    ) -> Result<BlobMetadata, StashError> {
        engine
            .store_blob(StoreBlobParams {
                tenant: TEST_TENANT,
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

    /// Generate a valid wrapped DEK for client-encrypted tests.
    /// Returns a base64-encoded string of 48 bytes (enough to pass validation).
    fn valid_wrapped_dek() -> String {
        base64::engine::general_purpose::STANDARD.encode([0xAA; 48])
    }

    /// Generate valid fake ciphertext for client-encrypted tests.
    /// Returns a byte vec of the specified length (must be >= MIN_CIPHERTEXT_LEN).
    fn valid_ciphertext(len: usize) -> Vec<u8> {
        vec![0xBB; len]
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

        let result = engine
            .retrieve_blob(TEST_TENANT, "test-1", None)
            .await
            .unwrap();
        assert_eq!(result.data, plaintext);
        assert!(result.wrapped_dek.is_none());
    }

    #[tokio::test]
    async fn store_client_encrypted_passthrough() {
        let engine = setup().await;
        let ciphertext = valid_ciphertext(64);
        let wrapped_dek = valid_wrapped_dek();

        let meta = engine
            .store_blob(StoreBlobParams {
                tenant: TEST_TENANT,
                id: "ce-1",
                data: &ciphertext,
                content_type: Some("application/octet-stream"),
                keyring: None,
                client_encrypted: true,
                wrapped_dek: Some(&wrapped_dek),
                actor: None,
            })
            .await
            .unwrap();

        assert!(meta.client_encrypted);
        assert_eq!(meta.wrapped_dek, wrapped_dek);

        let result = engine
            .retrieve_blob(TEST_TENANT, "ce-1", None)
            .await
            .unwrap();
        assert_eq!(result.data, ciphertext);
        assert_eq!(result.wrapped_dek.as_deref(), Some(wrapped_dek.as_str()));
    }

    #[tokio::test]
    async fn store_client_encrypted_requires_dek() {
        let engine = setup().await;
        let err = engine
            .store_blob(StoreBlobParams {
                tenant: TEST_TENANT,
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

        let result = engine
            .inspect_blob(TEST_TENANT, "inspect-1", None)
            .await
            .unwrap();
        assert_eq!(result.id, "inspect-1");
        assert_eq!(result.status, BlobStatus::Active);
        assert_eq!(result.plaintext_size, 5);
        assert_eq!(result.content_type.as_deref(), Some("text/plain"));
        assert_eq!(result.viewer_count, 0);
    }

    #[tokio::test]
    async fn inspect_not_found() {
        let engine = setup().await;
        let err = engine
            .inspect_blob(TEST_TENANT, "nope", None)
            .await
            .unwrap_err();
        assert!(err.is_not_found());
    }

    #[tokio::test]
    async fn soft_revoke_blocks_retrieve() {
        let engine = setup().await;
        store(&engine, "rev-soft", b"data", None).await.unwrap();

        engine
            .revoke_blob(TEST_TENANT, "rev-soft", true, None)
            .await
            .unwrap();

        let info = engine
            .inspect_blob(TEST_TENANT, "rev-soft", None)
            .await
            .unwrap();
        assert_eq!(info.status, BlobStatus::Revoked);

        let err = engine
            .retrieve_blob(TEST_TENANT, "rev-soft", None)
            .await
            .unwrap_err();
        assert!(matches!(err, StashError::Revoked { .. }));
    }

    #[tokio::test]
    async fn hard_revoke_shreds_everything() {
        let engine = setup().await;
        store(&engine, "rev-hard", b"secret data", None)
            .await
            .unwrap();

        let obj_store = get_object_store(&engine);
        assert!(
            obj_store
                .contains_key(&format!("{TEST_TENANT}/rev-hard"))
                .await
        );

        engine
            .revoke_blob(TEST_TENANT, "rev-hard", false, None)
            .await
            .unwrap();

        assert!(
            !obj_store
                .contains_key(&format!("{TEST_TENANT}/rev-hard"))
                .await
        );

        let info = engine
            .inspect_blob(TEST_TENANT, "rev-hard", None)
            .await
            .unwrap();
        assert_eq!(info.status, BlobStatus::Shredded);

        let err = engine
            .retrieve_blob(TEST_TENANT, "rev-hard", None)
            .await
            .unwrap_err();
        assert!(matches!(err, StashError::Shredded { .. }));

        let err = engine
            .revoke_blob(TEST_TENANT, "rev-hard", false, None)
            .await
            .unwrap_err();
        assert!(matches!(err, StashError::Shredded { .. }));
    }

    #[tokio::test]
    async fn revoke_not_found() {
        let engine = setup().await;
        let err = engine
            .revoke_blob(TEST_TENANT, "nope", false, None)
            .await
            .unwrap_err();
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
            ..Default::default()
        };

        let engine = StashEngine::new(store_kv, obj_store.clone(), caps, config)
            .await
            .unwrap();

        store(&engine, "blob-1", b"data", None).await.unwrap();

        assert!(
            obj_store
                .contains_key(&format!("my-prefix/{TEST_TENANT}/blob-1"))
                .await
        );
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
        let result = engine
            .retrieve_blob(TEST_TENANT, "raw-1", None)
            .await
            .unwrap();
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
            .inspect_blob(TEST_TENANT, "enc-blob", None)
            .await
            .unwrap();
        assert!(info.encrypted_size > info.plaintext_size);
    }

    #[tokio::test]
    async fn large_blob_roundtrip() {
        let engine = setup().await;
        let plaintext = vec![0xAB; 1024 * 1024];

        store(&engine, "large", &plaintext, None).await.unwrap();

        let result = engine
            .retrieve_blob(TEST_TENANT, "large", None)
            .await
            .unwrap();
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
                    tenant: TEST_TENANT,
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
                .retrieve_blob(TEST_TENANT, &format!("concurrent-{i}"), None)
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

    #[tokio::test]
    async fn large_blob_uses_chunked_path_and_roundtrips() {
        // Configure a very low streaming threshold so we exercise the chunked path
        let store_kv = shroudb_storage::test_util::create_test_store("stash-chunked").await;
        let obj_store = Arc::new(InMemoryObjectStore::new());
        let mock_cipher = MockCipherOps::new();
        let caps = Capabilities {
            cipher: Some(Box::new(mock_cipher)),
            sentry: None,
            chronicle: None,
        };
        let config = StashConfig {
            streaming_threshold_bytes: 100, // very low: 100 bytes
            ..Default::default()
        };
        let engine = StashEngine::new(store_kv, obj_store.clone(), caps, config)
            .await
            .unwrap();

        // Store a blob larger than the threshold → forces chunked encryption
        let plaintext = vec![0xABu8; 500]; // 500 bytes > 100 byte threshold
        store(&engine, "chunked-blob", &plaintext, None)
            .await
            .unwrap();

        // The encrypted data in S3 should start with the chunked version byte
        let encrypted = obj_store
            .get(&format!("{TEST_TENANT}/chunked-blob"))
            .await
            .unwrap();
        assert!(
            crate::crypto::is_chunked(&encrypted),
            "blob should use chunked encryption format"
        );

        // Retrieve should auto-detect chunked format and decrypt correctly
        let result = engine
            .retrieve_blob(TEST_TENANT, "chunked-blob", None)
            .await
            .unwrap();
        assert_eq!(result.data, plaintext, "chunked decrypt roundtrip failed");
    }

    #[tokio::test]
    async fn small_blob_uses_standard_path() {
        let store_kv = shroudb_storage::test_util::create_test_store("stash-standard").await;
        let obj_store = Arc::new(InMemoryObjectStore::new());
        let mock_cipher = MockCipherOps::new();
        let caps = Capabilities {
            cipher: Some(Box::new(mock_cipher)),
            sentry: None,
            chronicle: None,
        };
        let config = StashConfig {
            streaming_threshold_bytes: 1000, // threshold above our blob size
            ..Default::default()
        };
        let engine = StashEngine::new(store_kv, obj_store.clone(), caps, config)
            .await
            .unwrap();

        let plaintext = b"small blob data";
        store(&engine, "small-blob", plaintext, None).await.unwrap();

        // Should NOT be chunked
        let encrypted = obj_store
            .get(&format!("{TEST_TENANT}/small-blob"))
            .await
            .unwrap();
        assert!(
            !crate::crypto::is_chunked(&encrypted),
            "small blob should use standard encryption"
        );

        let result = engine
            .retrieve_blob(TEST_TENANT, "small-blob", None)
            .await
            .unwrap();
        assert_eq!(result.data, plaintext);
    }

    // ── REWRAP tests ─────────────────────────────────────────────────

    #[tokio::test]
    async fn rewrap_updates_wrapped_dek_and_key_version() {
        let engine = setup().await;
        let plaintext = b"rewrap-test-data";

        store(&engine, "rw-1", plaintext, None).await.unwrap();

        // Inspect before rewrap
        let before = engine
            .inspect_blob(TEST_TENANT, "rw-1", None)
            .await
            .unwrap();
        assert_eq!(before.key_version, 1);

        // Rewrap
        let meta = engine.rewrap_blob(TEST_TENANT, "rw-1", None).await.unwrap();
        assert_eq!(meta.key_version, 2, "key_version should be updated");

        // Inspect after rewrap confirms version changed
        let after = engine
            .inspect_blob(TEST_TENANT, "rw-1", None)
            .await
            .unwrap();
        assert_eq!(after.key_version, 2);

        // Data is still retrievable with same plaintext
        let result = engine
            .retrieve_blob(TEST_TENANT, "rw-1", None)
            .await
            .unwrap();
        assert_eq!(result.data, plaintext, "plaintext should be unchanged");
    }

    #[tokio::test]
    async fn rewrap_client_encrypted_rejected() {
        let engine = setup().await;

        // Store a client-encrypted blob with valid wrapped DEK and ciphertext
        let ciphertext = valid_ciphertext(64);
        let wrapped_dek = valid_wrapped_dek();
        engine
            .store_blob(StoreBlobParams {
                tenant: TEST_TENANT,
                id: "ce-rw",
                data: &ciphertext,
                content_type: None,
                keyring: None,
                client_encrypted: true,
                wrapped_dek: Some(&wrapped_dek),
                actor: None,
            })
            .await
            .unwrap();

        // Rewrap should fail — client manages key material
        let err = engine.rewrap_blob(TEST_TENANT, "ce-rw", None).await;
        assert!(err.is_err(), "rewrap on client-encrypted should fail");
    }

    #[tokio::test]
    async fn rewrap_nonexistent_fails() {
        let engine = setup().await;
        let err = engine.rewrap_blob(TEST_TENANT, "nope", None).await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn rewrap_revoked_fails() {
        let engine = setup().await;
        store(&engine, "revoked-rw", b"data", None).await.unwrap();
        engine
            .revoke_blob(TEST_TENANT, "revoked-rw", true, None)
            .await
            .unwrap(); // soft revoke
        let err = engine.rewrap_blob(TEST_TENANT, "revoked-rw", None).await;
        assert!(err.is_err(), "rewrap on revoked blob should fail");
    }

    // ── Client-encrypted validation tests ────────────────────────────

    #[tokio::test]
    async fn client_encrypted_rejects_invalid_base64_dek() {
        let engine = setup().await;
        let ciphertext = valid_ciphertext(64);

        let err = engine
            .store_blob(StoreBlobParams {
                tenant: TEST_TENANT,
                id: "ce-bad-b64",
                data: &ciphertext,
                content_type: None,
                keyring: None,
                client_encrypted: true,
                wrapped_dek: Some("not!!!valid===base64"),
                actor: None,
            })
            .await
            .unwrap_err();

        assert!(matches!(err, StashError::InvalidArgument(_)));
        assert!(
            err.to_string().contains("not valid base64"),
            "error should mention base64: {err}"
        );
    }

    #[tokio::test]
    async fn client_encrypted_rejects_short_dek() {
        let engine = setup().await;
        let ciphertext = valid_ciphertext(64);
        // 16 bytes encoded as base64 — below the 32-byte minimum
        let short_dek = base64::engine::general_purpose::STANDARD.encode([0xCC; 16]);

        let err = engine
            .store_blob(StoreBlobParams {
                tenant: TEST_TENANT,
                id: "ce-short-dek",
                data: &ciphertext,
                content_type: None,
                keyring: None,
                client_encrypted: true,
                wrapped_dek: Some(&short_dek),
                actor: None,
            })
            .await
            .unwrap_err();

        assert!(matches!(err, StashError::InvalidArgument(_)));
        assert!(
            err.to_string().contains("too short"),
            "error should mention too short: {err}"
        );
    }

    #[tokio::test]
    async fn client_encrypted_rejects_short_ciphertext() {
        let engine = setup().await;
        let wrapped_dek = valid_wrapped_dek();
        // 10 bytes is less than MIN_CIPHERTEXT_LEN (28)
        let short_ct = vec![0xDD; 10];

        let err = engine
            .store_blob(StoreBlobParams {
                tenant: TEST_TENANT,
                id: "ce-short-ct",
                data: &short_ct,
                content_type: None,
                keyring: None,
                client_encrypted: true,
                wrapped_dek: Some(&wrapped_dek),
                actor: None,
            })
            .await
            .unwrap_err();

        assert!(matches!(err, StashError::InvalidArgument(_)));
        assert!(
            err.to_string().contains("ciphertext too short"),
            "error should mention ciphertext: {err}"
        );
    }

    #[tokio::test]
    async fn client_encrypted_validation_disabled_accepts_anything() {
        let store_kv = shroudb_storage::test_util::create_test_store("stash-no-validate-ce").await;
        let obj_store = Arc::new(InMemoryObjectStore::new());
        let mock_cipher = MockCipherOps::new();
        let caps = Capabilities {
            cipher: Some(Box::new(mock_cipher)),
            sentry: None,
            chronicle: None,
        };
        let config = StashConfig {
            validate_client_encrypted: false,
            ..Default::default()
        };
        let engine = StashEngine::new(store_kv, obj_store, caps, config)
            .await
            .unwrap();

        // Should succeed even with non-base64 DEK and tiny ciphertext
        let meta = engine
            .store_blob(StoreBlobParams {
                tenant: TEST_TENANT,
                id: "ce-novalidate",
                data: b"tiny",
                content_type: None,
                keyring: None,
                client_encrypted: true,
                wrapped_dek: Some("not-base64-at-all"),
                actor: None,
            })
            .await
            .unwrap();

        assert!(meta.client_encrypted);
    }

    #[tokio::test]
    async fn client_encrypted_exact_minimum_ciphertext_accepted() {
        let engine = setup().await;
        let wrapped_dek = valid_wrapped_dek();
        // Exactly MIN_CIPHERTEXT_LEN bytes — should be accepted
        let ct = valid_ciphertext(crate::crypto::MIN_CIPHERTEXT_LEN);

        let meta = engine
            .store_blob(StoreBlobParams {
                tenant: TEST_TENANT,
                id: "ce-min-ct",
                data: &ct,
                content_type: None,
                keyring: None,
                client_encrypted: true,
                wrapped_dek: Some(&wrapped_dek),
                actor: None,
            })
            .await
            .unwrap();

        assert!(meta.client_encrypted);
        assert_eq!(
            meta.plaintext_size,
            crate::crypto::MIN_CIPHERTEXT_LEN as u64
        );
    }

    #[tokio::test]
    async fn client_encrypted_exact_minimum_dek_accepted() {
        let engine = setup().await;
        let ciphertext = valid_ciphertext(64);
        // Exactly 32 bytes encoded — should be accepted
        let min_dek = base64::engine::general_purpose::STANDARD.encode([0xEE; 32]);

        let meta = engine
            .store_blob(StoreBlobParams {
                tenant: TEST_TENANT,
                id: "ce-min-dek",
                data: &ciphertext,
                content_type: None,
                keyring: None,
                client_encrypted: true,
                wrapped_dek: Some(&min_dek),
                actor: None,
            })
            .await
            .unwrap();

        assert!(meta.client_encrypted);
    }
}
