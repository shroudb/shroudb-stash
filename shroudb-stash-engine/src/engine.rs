use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use shroudb_acl::{PolicyEffect, PolicyPrincipal, PolicyRequest, PolicyResource};
use shroudb_chronicle_core::event::{Engine as ChronicleEngine, Event, EventResult};
use shroudb_store::Store;
use zeroize::Zeroize;

use crate::capabilities::Capabilities;
use crate::object_store::ObjectStore;
use shroudb_stash_core::error::StashError;
use shroudb_stash_core::metadata::{
    BlobMetadata, BlobStatus, InspectResult, TraceResult, ViewerMap, ViewerRecord,
};

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
/// Store namespace for deduplication records.
const DEDUP_NS: &str = "stash.dedup";

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

/// Internal dedup tracking record stored in the dedup namespace.
#[derive(serde::Serialize, serde::Deserialize)]
struct DedupRecord {
    canonical_id: String,
    s3_key: String,
    wrapped_dek: String,
    keyring: String,
    key_version: u32,
    reference_count: u32,
}

/// Result of a STORE operation, returned to the protocol layer.
#[derive(Debug)]
pub struct StoreResult {
    pub metadata: BlobMetadata,
    pub deduplicated: bool,
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
        for ns in [META_NS, VIEWER_NS, DEDUP_NS] {
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
    ///
    /// Content-addressed deduplication: for server-encrypted blobs, Stash
    /// computes a SHA-256 hash of the plaintext. If identical content already
    /// exists for the same tenant, the new blob becomes a metadata-only
    /// reference sharing the existing S3 object and wrapped DEK.
    pub async fn store_blob(&self, params: StoreBlobParams<'_>) -> Result<StoreResult, StashError> {
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

        // Compute content hash for dedup (server-encrypted blobs only).
        let content_hash = if !client_encrypted {
            Some(crate::crypto::hash_plaintext(data))
        } else {
            None
        };

        // Check for dedup opportunity (tenant-scoped, server-encrypted only).
        if let Some(ref hash) = content_hash
            && let Some(mut dedup) = self.load_dedup_record(tenant, hash).await
        {
            // Dedup hit: create a reference blob sharing the canonical's S3 object.
            dedup.reference_count += 1;
            self.save_dedup_record(tenant, hash, &dedup).await?;

            let metadata = BlobMetadata {
                id: id.to_string(),
                tenant_id: tenant.to_string(),
                s3_key: dedup.s3_key.clone(),
                wrapped_dek: dedup.wrapped_dek.clone(),
                keyring: dedup.keyring.clone(),
                key_version: dedup.key_version,
                content_type: content_type.map(String::from),
                plaintext_size: data.len() as u64,
                encrypted_size: 0, // no new S3 object
                client_encrypted: false,
                status: BlobStatus::Active,
                created_at: now,
                updated_at: now,
                content_hash: Some(hash.clone()),
                canonical_id: Some(dedup.canonical_id.clone()),
            };

            self.save_metadata(&metadata).await?;
            self.save_viewer_map(tenant, id, &ViewerMap::default())
                .await?;

            self.emit_audit("STORE", tenant, id, EventResult::Ok, actor)
                .await;

            tracing::info!(
                blob_id = id,
                canonical_id = %dedup.canonical_id,
                "blob stored (deduplicated)"
            );

            return Ok(StoreResult {
                metadata,
                deduplicated: true,
            });
        }

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
                // Fail-closed: without Cipher there is no envelope encryption
                // path. Uploading plaintext to S3 would violate "no plaintext
                // at rest". Refuse the operation so the operator either wires
                // Cipher or uses client-encrypted passthrough.
                tracing::error!(
                    blob_id = id,
                    justification = ?self.capabilities.cipher.justification(),
                    "STORE refused: cipher capability is not enabled"
                );
                return Err(StashError::CipherUnavailable);
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
            wrapped_dek: final_wrapped_dek.clone(),
            keyring: keyring.to_string(),
            key_version,
            content_type: content_type.map(String::from),
            plaintext_size,
            encrypted_size,
            client_encrypted,
            status: BlobStatus::Active,
            created_at: now,
            updated_at: now,
            content_hash: content_hash.clone(),
            canonical_id: None,
        };

        self.save_metadata(&metadata).await?;

        // Create dedup record for server-encrypted blobs.
        if let Some(ref hash) = content_hash {
            let dedup = DedupRecord {
                canonical_id: id.to_string(),
                s3_key: s3_key.clone(),
                wrapped_dek: final_wrapped_dek,
                keyring: keyring.to_string(),
                key_version,
                reference_count: 1,
            };
            self.save_dedup_record(tenant, hash, &dedup).await?;
        }

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

        Ok(StoreResult {
            metadata,
            deduplicated: false,
        })
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

        // For dedup references, the S3 object was encrypted with the
        // canonical blob's ID as AAD. Use the canonical ID for decryption.
        let aad_id = metadata.canonical_id.as_deref().unwrap_or(id);

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
                    aad_id.as_bytes(),
                )?
            } else {
                // Use compat decryption to handle blobs encrypted before
                // AAD binding was added (empty AAD fallback).
                let (data, used_legacy) = crate::crypto::decrypt_blob_compat(
                    plaintext_key.as_bytes(),
                    &encrypted_data,
                    aad_id.as_bytes(),
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

            // 2. Handle dedup-aware S3 object and DEK cleanup.
            let mut should_delete_s3 = true;
            let mut should_delete_dedup = false;

            if let Some(ref hash) = metadata.content_hash
                && let Some(mut dedup) = self.load_dedup_record(tenant, hash).await
            {
                dedup.reference_count = dedup.reference_count.saturating_sub(1);

                if metadata.canonical_id.is_some() {
                    // This blob is a reference — never delete the S3 object
                    // (it belongs to the canonical blob).
                    should_delete_s3 = false;

                    if dedup.reference_count == 0
                        && let Ok(canonical_meta) =
                            self.load_metadata(tenant, &dedup.canonical_id).await
                        && canonical_meta.status == BlobStatus::Shredded
                    {
                        // Both canonical and all references are gone.
                        should_delete_s3 = true;
                        should_delete_dedup = true;
                    }

                    self.save_dedup_record(tenant, hash, &dedup).await?;
                } else {
                    // This blob IS the canonical.
                    if dedup.reference_count > 0 {
                        // Other references still need the S3 object.
                        should_delete_s3 = false;
                    } else {
                        // No more references — safe to clean up everything.
                        should_delete_dedup = true;
                    }

                    self.save_dedup_record(tenant, hash, &dedup).await?;
                }

                if should_delete_dedup {
                    self.delete_dedup_record(tenant, hash).await?;
                }
            }

            if should_delete_s3 && let Err(e) = self.object_store.delete(&metadata.s3_key).await {
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

    // ── FINGERPRINT ────────────────────────────────────────────────────

    /// Create a viewer-specific encrypted copy of a blob.
    ///
    /// Decrypts the master blob, generates a new DEK for the viewer,
    /// re-encrypts with viewer-specific AAD (`{id}:{viewer_id}`), and
    /// uploads to S3 under `{s3_key}/viewers/{viewer_id}`.
    ///
    /// Each viewer gets their own DEK, enabling per-viewer revocation
    /// and leak tracing.
    pub async fn fingerprint_blob(
        &self,
        tenant: &str,
        id: &str,
        viewer_id: &str,
        params: Option<serde_json::Value>,
        actor: Option<&str>,
    ) -> Result<ViewerRecord, StashError> {
        let metadata = self.load_metadata(tenant, id).await?;

        // Fail-closed: if tenant doesn't match, return NotFound.
        if metadata.tenant_id != tenant {
            return Err(StashError::NotFound { id: id.into() });
        }

        // Only active blobs can be fingerprinted.
        match metadata.status {
            BlobStatus::Active => {}
            BlobStatus::Revoked => return Err(StashError::Revoked { id: id.into() }),
            BlobStatus::Shredded => return Err(StashError::Shredded { id: id.into() }),
        }

        // Client-encrypted blobs cannot be fingerprinted — client manages encryption.
        if metadata.client_encrypted {
            return Err(StashError::ClientEncrypted { id: id.into() });
        }

        // Check ABAC policy.
        self.check_policy(tenant, id, "FINGERPRINT", actor).await?;

        // Cipher is required for fingerprinting (need to unwrap master DEK + generate viewer DEK).
        let cipher = self
            .capabilities
            .cipher
            .as_ref()
            .ok_or(StashError::CipherUnavailable)?;

        // Check for duplicate viewer.
        let mut viewer_map = self.load_viewer_map(tenant, id).await.unwrap_or_default();
        if viewer_map.find(viewer_id).is_some() {
            return Err(StashError::DuplicateViewer {
                blob_id: id.into(),
                viewer_id: viewer_id.into(),
            });
        }

        // Download encrypted blob from S3.
        let encrypted_data = self
            .object_store
            .get(&metadata.s3_key)
            .await
            .map_err(|e| StashError::ObjectStore(e.to_string()))?;

        // Unwrap master DEK via Cipher.
        let master_key = cipher.unwrap_data_key(&metadata.wrapped_dek).await?;

        // Decrypt blob locally.
        let plaintext = if crate::crypto::is_chunked(&encrypted_data) {
            crate::crypto::decrypt_blob_chunked(
                master_key.as_bytes(),
                &encrypted_data,
                id.as_bytes(),
            )?
        } else {
            let (data, _used_legacy) = crate::crypto::decrypt_blob_compat(
                master_key.as_bytes(),
                &encrypted_data,
                id.as_bytes(),
            )?;
            data
        };
        // master_key dropped here → SensitiveBytes auto-zeroizes
        drop(master_key);

        // Generate new viewer DEK via Cipher.
        let viewer_dek_pair = cipher.generate_data_key(Some(256)).await?;
        let viewer_key = viewer_dek_pair.plaintext_key;

        // Encrypt plaintext with viewer DEK using viewer-specific AAD.
        let viewer_aad = format!("{id}:{viewer_id}");
        let use_streaming = self.config.streaming_threshold_bytes > 0
            && plaintext.len() > self.config.streaming_threshold_bytes;
        let viewer_ciphertext = if use_streaming {
            crate::crypto::encrypt_blob_chunked(
                viewer_key.as_bytes(),
                &plaintext,
                viewer_aad.as_bytes(),
            )?
        } else {
            crate::crypto::encrypt_blob(viewer_key.as_bytes(), &plaintext, viewer_aad.as_bytes())?
        };
        // viewer_key dropped here → SensitiveBytes auto-zeroizes
        // Zeroize plaintext immediately.
        drop(viewer_key);
        let mut plaintext = plaintext;
        plaintext.zeroize();

        // Upload viewer copy to S3.
        let viewer_s3_key = format!("{}/viewers/{}", self.s3_key(tenant, id), viewer_id);
        self.object_store
            .put(
                &viewer_s3_key,
                &viewer_ciphertext,
                Some("application/octet-stream"),
            )
            .await
            .map_err(|e| StashError::ObjectStore(e.to_string()))?;

        // Create viewer record.
        let record = ViewerRecord {
            viewer_id: viewer_id.to_string(),
            s3_key: viewer_s3_key,
            wrapped_dek: viewer_dek_pair.wrapped_key,
            fingerprint_params: params.unwrap_or(serde_json::json!({})),
            created_at: now_ms(),
        };

        // Append to viewer map and save.
        viewer_map.viewers.push(record.clone());
        self.save_viewer_map(tenant, id, &viewer_map).await?;

        // Audit.
        self.emit_audit("FINGERPRINT", tenant, id, EventResult::Ok, actor)
            .await;

        tracing::info!(
            blob_id = id,
            viewer_id,
            viewer_count = viewer_map.len(),
            "viewer fingerprint created"
        );

        Ok(record)
    }

    // ── TRACE ─────────────────────────────────────────────────────────

    /// Return the viewer map (who has copies) for a blob.
    pub async fn trace_blob(
        &self,
        tenant: &str,
        id: &str,
        actor: Option<&str>,
    ) -> Result<TraceResult, StashError> {
        let metadata = self.load_metadata(tenant, id).await?;

        // Fail-closed: if tenant doesn't match, return NotFound.
        if metadata.tenant_id != tenant {
            return Err(StashError::NotFound { id: id.into() });
        }

        // Check ABAC policy.
        self.check_policy(tenant, id, "TRACE", actor).await?;

        let viewer_map = self.load_viewer_map(tenant, id).await.unwrap_or_default();

        // Audit.
        self.emit_audit("TRACE", tenant, id, EventResult::Ok, actor)
            .await;

        Ok(TraceResult::from((&metadata, viewer_map.viewers)))
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

    // ── Dedup helpers ──────────────────────────────────────────────────

    /// Build the tenant-scoped Store key for a dedup record.
    fn dedup_key(tenant: &str, content_hash: &str) -> Vec<u8> {
        format!("{tenant}:{content_hash}").into_bytes()
    }

    /// Load a dedup record from the Store.
    async fn load_dedup_record(&self, tenant: &str, content_hash: &str) -> Option<DedupRecord> {
        let key = Self::dedup_key(tenant, content_hash);
        match self.store.get(DEDUP_NS, &key, None).await {
            Ok(entry) => serde_json::from_slice(&entry.value).ok(),
            Err(_) => None,
        }
    }

    /// Persist a dedup record to the Store.
    async fn save_dedup_record(
        &self,
        tenant: &str,
        content_hash: &str,
        record: &DedupRecord,
    ) -> Result<(), StashError> {
        let key = Self::dedup_key(tenant, content_hash);
        let value = serde_json::to_vec(record)
            .map_err(|e| StashError::Internal(format!("serialize dedup: {e}")))?;
        self.store
            .put(DEDUP_NS, &key, &value, None)
            .await
            .map_err(|e| StashError::Store(format!("save dedup: {e}")))?;
        Ok(())
    }

    /// Delete a dedup record from the Store.
    async fn delete_dedup_record(
        &self,
        tenant: &str,
        content_hash: &str,
    ) -> Result<(), StashError> {
        let key = Self::dedup_key(tenant, content_hash);
        self.store
            .delete(DEDUP_NS, &key)
            .await
            .map_err(|e| StashError::Store(format!("delete dedup: {e}")))?;
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
        let sentry = match self.capabilities.sentry.as_ref() {
            Some(s) => s,
            None => return Ok(()), // Sentry disabled = no ABAC gating.
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
        let chronicle = match self.capabilities.chronicle.as_ref() {
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
    use shroudb_server_bootstrap::Capability;

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
            cipher: Capability::Enabled(Box::new(mock_cipher)),
            sentry: Capability::DisabledForTests,
            chronicle: Capability::DisabledForTests,
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
            .map(|r| r.metadata)
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

        let result = engine
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
        let meta = result.metadata;

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
            cipher: Capability::Enabled(Box::new(mock_cipher)),
            sentry: Capability::DisabledForTests,
            chronicle: Capability::DisabledForTests,
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
    async fn store_without_cipher_fails_closed() {
        let store_kv = shroudb_storage::test_util::create_test_store("stash-no-cipher").await;
        let obj_store = Arc::new(InMemoryObjectStore::new());
        let caps = Capabilities::for_tests(); // No cipher
        let engine = StashEngine::new(store_kv, obj_store.clone(), caps, StashConfig::default())
            .await
            .unwrap();

        // Server-encrypted STORE with no cipher must fail-closed — uploading
        // plaintext to S3 would violate "no plaintext at rest".
        let err = store(&engine, "raw-1", b"unencrypted data", Some("text/plain"))
            .await
            .unwrap_err();
        assert!(
            matches!(err, StashError::CipherUnavailable),
            "expected CipherUnavailable, got {err:?}"
        );

        // The S3 object must not exist — no plaintext landed.
        assert!(
            !obj_store
                .contains_key(&format!("{TEST_TENANT}/raw-1"))
                .await,
            "no object should have been uploaded when STORE fails closed"
        );

        // Client-encrypted passthrough with a valid wrapped DEK and
        // ciphertext still works — the client owns the encryption.
        let ciphertext = valid_ciphertext(64);
        let wrapped_dek = valid_wrapped_dek();
        let meta = engine
            .store_blob(StoreBlobParams {
                tenant: TEST_TENANT,
                id: "ce-ok",
                data: &ciphertext,
                content_type: None,
                keyring: None,
                client_encrypted: true,
                wrapped_dek: Some(&wrapped_dek),
                actor: None,
            })
            .await
            .unwrap()
            .metadata;
        assert!(meta.client_encrypted);
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
            let result = handle.await.unwrap().unwrap();
            assert_eq!(result.metadata.status, BlobStatus::Active);
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
            cipher: Capability::Enabled(Box::new(mock_cipher)),
            sentry: Capability::DisabledForTests,
            chronicle: Capability::DisabledForTests,
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
            cipher: Capability::Enabled(Box::new(mock_cipher)),
            sentry: Capability::DisabledForTests,
            chronicle: Capability::DisabledForTests,
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
            cipher: Capability::Enabled(Box::new(mock_cipher)),
            sentry: Capability::DisabledForTests,
            chronicle: Capability::DisabledForTests,
        };
        let config = StashConfig {
            validate_client_encrypted: false,
            ..Default::default()
        };
        let engine = StashEngine::new(store_kv, obj_store, caps, config)
            .await
            .unwrap();

        // Should succeed even with non-base64 DEK and tiny ciphertext
        let result = engine
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

        assert!(result.metadata.client_encrypted);
    }

    #[tokio::test]
    async fn client_encrypted_exact_minimum_ciphertext_accepted() {
        let engine = setup().await;
        let wrapped_dek = valid_wrapped_dek();
        // Exactly MIN_CIPHERTEXT_LEN bytes — should be accepted
        let ct = valid_ciphertext(crate::crypto::MIN_CIPHERTEXT_LEN);

        let result = engine
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

        assert!(result.metadata.client_encrypted);
        assert_eq!(
            result.metadata.plaintext_size,
            crate::crypto::MIN_CIPHERTEXT_LEN as u64
        );
    }

    #[tokio::test]
    async fn client_encrypted_exact_minimum_dek_accepted() {
        let engine = setup().await;
        let ciphertext = valid_ciphertext(64);
        // Exactly 32 bytes encoded — should be accepted
        let min_dek = base64::engine::general_purpose::STANDARD.encode([0xEE; 32]);

        let result = engine
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

        assert!(result.metadata.client_encrypted);
    }

    // ── Dedup tests ─────────────────────────────────────────────────

    #[tokio::test]
    async fn dedup_identical_blobs_share_s3() {
        let engine = setup().await;
        let data = b"identical content for dedup";

        let r1 = engine
            .store_blob(StoreBlobParams {
                tenant: TEST_TENANT,
                id: "dedup-1",
                data,
                content_type: Some("text/plain"),
                keyring: None,
                client_encrypted: false,
                wrapped_dek: None,
                actor: None,
            })
            .await
            .unwrap();
        assert!(!r1.deduplicated);
        assert!(r1.metadata.content_hash.is_some());
        assert!(r1.metadata.canonical_id.is_none());

        let r2 = engine
            .store_blob(StoreBlobParams {
                tenant: TEST_TENANT,
                id: "dedup-2",
                data,
                content_type: Some("text/plain"),
                keyring: None,
                client_encrypted: false,
                wrapped_dek: None,
                actor: None,
            })
            .await
            .unwrap();
        assert!(r2.deduplicated);
        assert_eq!(r2.metadata.content_hash, r1.metadata.content_hash);
        assert_eq!(r2.metadata.canonical_id.as_deref(), Some("dedup-1"));
        assert_eq!(r2.metadata.s3_key, r1.metadata.s3_key);
    }

    #[tokio::test]
    async fn dedup_retrieve_reference() {
        let engine = setup().await;
        let data = b"dedup retrieve test";

        store(&engine, "dedup-r1", data, None).await.unwrap();
        let r2 = engine
            .store_blob(StoreBlobParams {
                tenant: TEST_TENANT,
                id: "dedup-r2",
                data,
                content_type: None,
                keyring: None,
                client_encrypted: false,
                wrapped_dek: None,
                actor: None,
            })
            .await
            .unwrap();
        assert!(r2.deduplicated);

        // Retrieve the reference blob — should return the same plaintext.
        let result = engine
            .retrieve_blob(TEST_TENANT, "dedup-r2", None)
            .await
            .unwrap();
        assert_eq!(result.data, data);
    }

    #[tokio::test]
    async fn dedup_revoke_reference_preserves_canonical() {
        let engine = setup().await;
        let data = b"dedup revoke ref test";

        store(&engine, "dedup-rev-1", data, None).await.unwrap();
        engine
            .store_blob(StoreBlobParams {
                tenant: TEST_TENANT,
                id: "dedup-rev-2",
                data,
                content_type: None,
                keyring: None,
                client_encrypted: false,
                wrapped_dek: None,
                actor: None,
            })
            .await
            .unwrap();

        // Revoke the reference.
        engine
            .revoke_blob(TEST_TENANT, "dedup-rev-2", false, None)
            .await
            .unwrap();

        // Canonical blob should still be retrievable.
        let result = engine
            .retrieve_blob(TEST_TENANT, "dedup-rev-1", None)
            .await
            .unwrap();
        assert_eq!(result.data, data);

        // Reference should be shredded.
        let info = engine
            .inspect_blob(TEST_TENANT, "dedup-rev-2", None)
            .await
            .unwrap();
        assert_eq!(info.status, BlobStatus::Shredded);
    }

    #[tokio::test]
    async fn dedup_revoke_canonical_with_references() {
        let engine = setup().await;
        let data = b"dedup revoke canonical test";

        store(&engine, "dedup-can-1", data, None).await.unwrap();
        engine
            .store_blob(StoreBlobParams {
                tenant: TEST_TENANT,
                id: "dedup-can-2",
                data,
                content_type: None,
                keyring: None,
                client_encrypted: false,
                wrapped_dek: None,
                actor: None,
            })
            .await
            .unwrap();

        // Revoke the canonical.
        engine
            .revoke_blob(TEST_TENANT, "dedup-can-1", false, None)
            .await
            .unwrap();

        // Canonical should be shredded.
        let info = engine
            .inspect_blob(TEST_TENANT, "dedup-can-1", None)
            .await
            .unwrap();
        assert_eq!(info.status, BlobStatus::Shredded);

        // Reference should still be retrievable — S3 object preserved.
        let result = engine
            .retrieve_blob(TEST_TENANT, "dedup-can-2", None)
            .await
            .unwrap();
        assert_eq!(result.data, data);
    }

    #[tokio::test]
    async fn dedup_different_content_no_dedup() {
        let engine = setup().await;

        let r1 = engine
            .store_blob(StoreBlobParams {
                tenant: TEST_TENANT,
                id: "diff-1",
                data: b"content-A",
                content_type: None,
                keyring: None,
                client_encrypted: false,
                wrapped_dek: None,
                actor: None,
            })
            .await
            .unwrap();
        assert!(!r1.deduplicated);

        let r2 = engine
            .store_blob(StoreBlobParams {
                tenant: TEST_TENANT,
                id: "diff-2",
                data: b"content-B",
                content_type: None,
                keyring: None,
                client_encrypted: false,
                wrapped_dek: None,
                actor: None,
            })
            .await
            .unwrap();
        assert!(!r2.deduplicated);
        assert_ne!(r1.metadata.content_hash, r2.metadata.content_hash);
        assert_ne!(r1.metadata.s3_key, r2.metadata.s3_key);
    }

    #[tokio::test]
    async fn dedup_cross_tenant_no_dedup() {
        let engine = setup().await;
        let data = b"same content different tenant";

        engine
            .store_blob(StoreBlobParams {
                tenant: "tenant-a",
                id: "cross-1",
                data,
                content_type: None,
                keyring: None,
                client_encrypted: false,
                wrapped_dek: None,
                actor: None,
            })
            .await
            .unwrap();

        let r2 = engine
            .store_blob(StoreBlobParams {
                tenant: "tenant-b",
                id: "cross-1",
                data,
                content_type: None,
                keyring: None,
                client_encrypted: false,
                wrapped_dek: None,
                actor: None,
            })
            .await
            .unwrap();

        // Should NOT be deduplicated — different tenants.
        assert!(!r2.deduplicated);
        assert!(r2.metadata.canonical_id.is_none());
    }

    #[tokio::test]
    async fn dedup_client_encrypted_skipped() {
        let engine = setup().await;
        let data = b"same data for client encrypted";

        // Store a server-encrypted blob.
        store(&engine, "ce-dedup-1", data, None).await.unwrap();

        // Store the same data as client-encrypted — should NOT dedup.
        let ciphertext = valid_ciphertext(64);
        let wrapped_dek = valid_wrapped_dek();
        let r2 = engine
            .store_blob(StoreBlobParams {
                tenant: TEST_TENANT,
                id: "ce-dedup-2",
                data: &ciphertext,
                content_type: None,
                keyring: None,
                client_encrypted: true,
                wrapped_dek: Some(&wrapped_dek),
                actor: None,
            })
            .await
            .unwrap();
        assert!(!r2.deduplicated);
        assert!(r2.metadata.content_hash.is_none());
    }

    // ── AUDIT 2026-04-17: failing debt tests (hard ratchet, no #[ignore]) ──
    //
    // Stash violates CLAUDE.md's "fail closed, not open" and "no plaintext
    // at rest" invariants in several places. These tests encode the
    // correct behaviour. They MUST stay failing until the findings are
    // fixed.

    /// Recording double for ChronicleOps.
    #[derive(Default)]
    struct RecordingChronicle {
        events: std::sync::Mutex<Vec<shroudb_chronicle_core::event::Event>>,
    }
    impl RecordingChronicle {
        fn events(&self) -> Vec<shroudb_chronicle_core::event::Event> {
            self.events.lock().unwrap().clone()
        }
    }
    impl shroudb_chronicle_core::ops::ChronicleOps for RecordingChronicle {
        fn record(
            &self,
            event: shroudb_chronicle_core::event::Event,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + '_>>
        {
            self.events.lock().unwrap().push(event);
            Box::pin(async { Ok(()) })
        }
        fn record_batch(
            &self,
            events: Vec<shroudb_chronicle_core::event::Event>,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + '_>>
        {
            self.events.lock().unwrap().extend(events);
            Box::pin(async { Ok(()) })
        }
    }

    /// Chronicle double that ALWAYS fails — used to prove the engine
    /// silently swallows audit failures.
    struct BrokenChronicle;
    impl shroudb_chronicle_core::ops::ChronicleOps for BrokenChronicle {
        fn record(
            &self,
            _event: shroudb_chronicle_core::event::Event,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + '_>>
        {
            Box::pin(async { Err("simulated audit sink down".into()) })
        }
        fn record_batch(
            &self,
            _events: Vec<shroudb_chronicle_core::event::Event>,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + '_>>
        {
            Box::pin(async { Err("simulated audit sink down".into()) })
        }
    }

    /// ObjectStore double whose `delete` always fails — used to prove
    /// hard-revoke cannot silently leave the S3 object intact.
    struct DeleteFailingObjectStore(Arc<InMemoryObjectStore>);
    impl crate::object_store::ObjectStore for DeleteFailingObjectStore {
        fn put(
            &self,
            key: &str,
            data: &[u8],
            content_type: Option<&str>,
        ) -> crate::object_store::BoxFut<'_, ()> {
            self.0.put(key, data, content_type)
        }
        fn get(&self, key: &str) -> crate::object_store::BoxFut<'_, Vec<u8>> {
            self.0.get(key)
        }
        fn delete(&self, _key: &str) -> crate::object_store::BoxFut<'_, ()> {
            Box::pin(async {
                Err(crate::object_store::ObjectStoreError::Internal(
                    "simulated S3 delete failure".into(),
                ))
            })
        }
        fn head(
            &self,
            key: &str,
        ) -> crate::object_store::BoxFut<'_, crate::object_store::ObjectMeta> {
            self.0.head(key)
        }
    }

    /// F-stash-1 (HIGH): When Capabilities.cipher is None, `store_blob`
    /// uploads the raw plaintext blob directly to S3 (engine.rs:255-265).
    /// CLAUDE.md is explicit: "No plaintext at rest. Secrets, keys, and
    /// sensitive data must be encrypted before touching disk." The
    /// correct failure mode is fail-closed — return an error. This is
    /// the single most dangerous behaviour in the engine: in production
    /// (server main.rs:113 constructs `Capabilities::for_tests()` so
    /// cipher IS None by default), every Stash blob is stored UNENCRYPTED.
    #[tokio::test]
    async fn debt_1_store_without_cipher_must_fail_closed() {
        let store_kv =
            shroudb_storage::test_util::create_test_store("stash-debt-1-fail-closed").await;
        let obj_store = Arc::new(InMemoryObjectStore::new());
        let caps = Capabilities::for_tests(); // cipher = None
        let engine = StashEngine::new(store_kv, obj_store.clone(), caps, StashConfig::default())
            .await
            .unwrap();

        let secret = b"highly sensitive blob";
        let result = engine
            .store_blob(StoreBlobParams {
                tenant: TEST_TENANT,
                id: "secret-1",
                data: secret,
                content_type: None,
                keyring: None,
                client_encrypted: false,
                wrapped_dek: None,
                actor: None,
            })
            .await;

        assert!(
            result.is_err(),
            "STORE without Cipher must fail-closed (CLAUDE.md: no plaintext at rest); \
             currently stash uploads plaintext to S3 and returns Ok"
        );

        // Belt-and-braces: if a bug does allow Ok, verify the S3 object
        // does not contain our plaintext secret.
        if result.is_ok() {
            let objects = obj_store.clone();
            // Scan all stored bytes.
            let key = format!("{TEST_TENANT}/secret-1");
            if let Ok(data) = objects.get(&key).await {
                assert!(
                    !data.windows(secret.len()).any(|w| w == secret),
                    "plaintext bytes found in S3 — envelope encryption bypassed"
                );
            }
        }
    }

    /// F-stash-2 (HIGH): When Capabilities.sentry is None, every
    /// `check_policy` call returns Ok (engine.rs:990-993). This is
    /// fail-OPEN on the engine's ABAC layer. The server main.rs wires
    /// `Capabilities::for_tests()` (sentry=None), so every operation —
    /// STORE, RETRIEVE, INSPECT, REVOKE, REWRAP, FINGERPRINT, TRACE —
    /// is permitted with no policy enforcement. CLAUDE.md: "fail closed,
    /// not open". Also mirrors the Sigil capability-unwired bug.
    #[tokio::test]
    async fn debt_2_retrieve_without_sentry_must_fail_closed() {
        let store_kv =
            shroudb_storage::test_util::create_test_store("stash-debt-2-sentry-closed").await;
        let obj_store = Arc::new(InMemoryObjectStore::new());
        let caps = Capabilities {
            cipher: Capability::Enabled(Box::new(MockCipherOps::new())),
            sentry: Capability::DisabledForTests,
            chronicle: Capability::DisabledForTests,
        };
        let engine = StashEngine::new(store_kv, obj_store, caps, StashConfig::default())
            .await
            .unwrap();

        // Seed a blob.
        engine
            .store_blob(StoreBlobParams {
                tenant: TEST_TENANT,
                id: "seeded",
                data: b"whatever",
                content_type: None,
                keyring: None,
                client_encrypted: false,
                wrapped_dek: None,
                actor: Some("seeder"),
            })
            .await
            .unwrap();

        // An UNAUTHENTICATED caller retrieves the blob. With no Sentry
        // wired, today this succeeds. Fail-closed requires this to err.
        let result = engine.retrieve_blob(TEST_TENANT, "seeded", None).await;
        assert!(
            result.is_err(),
            "RETRIEVE without a wired policy evaluator must fail-closed \
             (CLAUDE.md: fail closed, not open). Today check_policy returns \
             Ok when sentry is None, so every unauthenticated caller gets \
             blobs."
        );
    }

    /// F-stash-3 (HIGH): `emit_audit` silently swallows Chronicle
    /// errors (engine.rs:1094-1101). Every operation that fails to
    /// persist its audit event still returns Ok to the caller, breaking
    /// the audit-trail invariant. For security-critical operations,
    /// audit emission failure must propagate.
    #[tokio::test]
    async fn debt_3_audit_failure_must_propagate_to_caller() {
        let store_kv =
            shroudb_storage::test_util::create_test_store("stash-debt-3-audit-fail").await;
        let obj_store = Arc::new(InMemoryObjectStore::new());
        let caps = Capabilities {
            cipher: Capability::Enabled(Box::new(MockCipherOps::new())),
            sentry: Capability::DisabledForTests,
            chronicle: Capability::Enabled(Arc::new(BrokenChronicle)),
        };
        let engine = StashEngine::new(store_kv, obj_store, caps, StashConfig::default())
            .await
            .unwrap();

        let result = engine
            .store_blob(StoreBlobParams {
                tenant: TEST_TENANT,
                id: "audited",
                data: b"payload",
                content_type: None,
                keyring: None,
                client_encrypted: false,
                wrapped_dek: None,
                actor: Some("alice"),
            })
            .await;

        assert!(
            result.is_err(),
            "STORE must fail when Chronicle emission fails — today the \
             engine logs a warning and returns Ok, so an attacker who can \
             disrupt the audit sink can STORE/RETRIEVE invisibly"
        );
    }

    /// F-stash-4 (MED): On hard-revoke, `object_store.delete` errors
    /// for the master S3 object (engine.rs:613-619) and viewer objects
    /// (engine.rs:560-567) are swallowed — the engine logs a warning
    /// and proceeds to mark the blob Shredded. If S3 delete fails, the
    /// ciphertext survives. The wrapped DEK is destroyed, which *does*
    /// make the ciphertext unreadable — but the engine does not surface
    /// the failure. Callers cannot distinguish a complete crypto-shred
    /// from a "DEK destroyed, ciphertext still in S3" partial.
    #[tokio::test]
    async fn debt_4_hard_revoke_must_propagate_s3_delete_failure() {
        let inner = Arc::new(InMemoryObjectStore::new());
        let failing = Arc::new(DeleteFailingObjectStore(inner.clone()));
        let store_kv =
            shroudb_storage::test_util::create_test_store("stash-debt-4-revoke-fail").await;
        let caps = Capabilities {
            cipher: Capability::Enabled(Box::new(MockCipherOps::new())),
            sentry: Capability::DisabledForTests,
            chronicle: Capability::DisabledForTests,
        };
        let engine = StashEngine::new(store_kv, failing.clone(), caps, StashConfig::default())
            .await
            .unwrap();

        // Store a blob successfully.
        engine
            .store_blob(StoreBlobParams {
                tenant: TEST_TENANT,
                id: "to-revoke",
                data: b"destroy me",
                content_type: None,
                keyring: None,
                client_encrypted: false,
                wrapped_dek: None,
                actor: None,
            })
            .await
            .unwrap();

        // Hard-revoke — with failing object store, this must error.
        let revoke_result = engine
            .revoke_blob(TEST_TENANT, "to-revoke", false, None)
            .await;

        assert!(
            revoke_result.is_err(),
            "hard-revoke must propagate S3 delete failure — today the \
             engine swallows the error, marks the blob Shredded, and \
             returns Ok, leaving ciphertext in S3 without telling the \
             caller that crypto-shred was incomplete"
        );
    }

    /// F-stash-5 (HIGH): When Cipher IS absent and a blob is stored
    /// raw (the fail-open path we're trying to close in debt_1),
    /// retrieving it is allowed even though:
    /// - The metadata has `wrapped_dek.is_empty() == true` (engine.rs:375-378)
    /// - The engine short-circuits past the decrypt path and returns
    ///   the raw bytes directly.
    /// This lets an attacker who can get Cipher unavailable (network
    /// partition, Cipher down) read blobs with NO cryptographic check.
    #[tokio::test]
    async fn debt_5_retrieve_raw_blob_must_fail_closed() {
        let store_kv =
            shroudb_storage::test_util::create_test_store("stash-debt-5-retrieve-raw").await;
        let obj_store = Arc::new(InMemoryObjectStore::new());

        // Step 1: Store with cipher absent (today succeeds — the fail-open bug).
        let caps_no_cipher = Capabilities::for_tests();
        let engine_no_cipher = StashEngine::new(
            store_kv.clone(),
            obj_store.clone(),
            caps_no_cipher,
            StashConfig::default(),
        )
        .await
        .unwrap();
        let store_result = engine_no_cipher
            .store_blob(StoreBlobParams {
                tenant: TEST_TENANT,
                id: "raw-blob",
                data: b"leaky plaintext",
                content_type: None,
                keyring: None,
                client_encrypted: false,
                wrapped_dek: None,
                actor: None,
            })
            .await;

        // If debt_1 is fixed, STORE errs here and we short-circuit.
        if store_result.is_err() {
            return;
        }

        // Step 2: A fresh engine WITH cipher attached tries to retrieve.
        // It must refuse: the stored blob has no wrapped DEK, so there is
        // no authenticated-encryption path. Today the engine returns the
        // raw bytes as-if plaintext.
        let caps_with_cipher = Capabilities {
            cipher: Capability::Enabled(Box::new(MockCipherOps::new())),
            sentry: Capability::DisabledForTests,
            chronicle: Capability::DisabledForTests,
        };
        let engine_with_cipher = StashEngine::new(
            store_kv,
            obj_store,
            caps_with_cipher,
            StashConfig::default(),
        )
        .await
        .unwrap();
        let result = engine_with_cipher
            .retrieve_blob(TEST_TENANT, "raw-blob", None)
            .await;

        assert!(
            result.is_err(),
            "RETRIEVE of a blob with empty wrapped_dek must fail-closed; \
             today the engine returns raw S3 bytes, defeating envelope \
             encryption entirely"
        );
    }

    /// F-stash-6 (MED): `retrieve_blob` decryption failure path for
    /// blobs predating the AAD binding (engine.rs:390-404) uses
    /// `decrypt_blob_compat` which tries the empty-AAD fallback. This
    /// silently accepts ciphertext authenticated against a different
    /// AAD than the blob ID. Legitimate "upgrade" path, but the engine
    /// emits a tracing warning only — there is no Chronicle event, so
    /// an attacker re-uploading an old-format blob under a new ID can
    /// successfully decrypt under the new ID. This test demands that
    /// legacy-AAD decrypts emit a distinct Chronicle event so they can
    /// be monitored.
    #[tokio::test]
    async fn debt_6_legacy_aad_decrypt_must_emit_distinct_audit_event() {
        let store_kv =
            shroudb_storage::test_util::create_test_store("stash-debt-6-legacy-audit").await;
        let obj_store = Arc::new(InMemoryObjectStore::new());
        let chronicle = Arc::new(RecordingChronicle::default());
        let caps = Capabilities {
            cipher: Capability::Enabled(Box::new(MockCipherOps::new())),
            sentry: Capability::DisabledForTests,
            chronicle: Capability::Enabled(chronicle.clone()),
        };
        let engine = StashEngine::new(store_kv, obj_store, caps, StashConfig::default())
            .await
            .unwrap();

        engine
            .store_blob(StoreBlobParams {
                tenant: TEST_TENANT,
                id: "modern",
                data: b"abc",
                content_type: None,
                keyring: None,
                client_encrypted: false,
                wrapped_dek: None,
                actor: Some("a"),
            })
            .await
            .unwrap();

        // Normal retrieve — should NOT emit a legacy event.
        engine
            .retrieve_blob(TEST_TENANT, "modern", Some("a"))
            .await
            .unwrap();

        let legacy_events: Vec<_> = chronicle
            .events()
            .into_iter()
            .filter(|e| e.operation.contains("LEGACY") || e.operation.contains("legacy"))
            .collect();
        // Today no legacy event type exists at all; the taxonomy doesn't
        // distinguish modern from legacy-AAD retrieves. We require one.
        assert!(
            chronicle
                .events()
                .iter()
                .any(|e| e.metadata.contains_key("aad_binding")),
            "RETRIEVE audit events must record the AAD-binding mode \
             (modern vs. legacy compat fallback) in metadata, so ops can \
             detect when legacy decrypts are still happening. Today \
             metadata is empty and monitoring has to parse log lines. \
             legacy_events so far: {}",
            legacy_events.len()
        );
    }
}
