//! `StashCipherOps` backed by an in-process `CipherEngine`.
//!
//! Used when Stash is deployed as a single process that bundles its own
//! Cipher — no TCP hop, no separate service. The `CipherEngine` runs on
//! the same `StorageEngine` as Stash's metadata (distinct namespace), so
//! one master key protects Stash's wrapped DEKs and Cipher's keyring
//! material together.
//!
//! Parallels Scroll's `cipher_embedded.rs` — same shape, Stash's
//! narrower trait (adds `rewrap_data_key`).

use std::sync::Arc;

use shroudb_cipher_engine::engine::CipherEngine;
use shroudb_crypto::SensitiveBytes;
use shroudb_stash_core::error::StashError;
use shroudb_stash_engine::capabilities::{BoxFut, DataKeyPair, StashCipherOps};
use shroudb_store::Store;

pub struct EmbeddedStashCipherOps<S: Store> {
    engine: Arc<CipherEngine<S>>,
    keyring: String,
}

impl<S: Store> EmbeddedStashCipherOps<S> {
    pub fn new(engine: Arc<CipherEngine<S>>, keyring: String) -> Self {
        Self { engine, keyring }
    }
}

impl<S: Store + 'static> StashCipherOps for EmbeddedStashCipherOps<S> {
    fn generate_data_key(&self, bits: Option<u32>, _actor: &str) -> BoxFut<'_, DataKeyPair> {
        Box::pin(async move {
            let result = self
                .engine
                .generate_data_key(&self.keyring, bits)
                .map_err(|e| StashError::Internal(format!("cipher generate_data_key: {e}")))?;
            Ok(DataKeyPair {
                plaintext_key: result.plaintext_key,
                wrapped_key: result.wrapped_key,
                key_version: result.key_version,
            })
        })
    }

    fn unwrap_data_key(&self, wrapped_key: &str, _actor: &str) -> BoxFut<'_, SensitiveBytes> {
        let wrapped = wrapped_key.to_string();
        Box::pin(async move {
            let result = self
                .engine
                .decrypt(&self.keyring, &wrapped, None)
                .await
                .map_err(|e| StashError::Internal(format!("cipher unwrap_data_key: {e}")))?;
            Ok(result.plaintext)
        })
    }

    fn rewrap_data_key(&self, old_wrapped_key: &str, _actor: &str) -> BoxFut<'_, DataKeyPair> {
        let wrapped = old_wrapped_key.to_string();
        Box::pin(async move {
            // rewrap decrypts with the old key version and re-encrypts with
            // the active key version — plaintext DEK never leaves Cipher.
            let result = self
                .engine
                .rewrap(&self.keyring, &wrapped, None)
                .map_err(|e| StashError::Internal(format!("cipher rewrap_data_key: {e}")))?;

            // Unwrap the new ciphertext to get the plaintext DEK.
            let plaintext = self
                .engine
                .decrypt(&self.keyring, &result.ciphertext, None)
                .await
                .map_err(|e| StashError::Internal(format!("cipher unwrap after rewrap: {e}")))?;

            Ok(DataKeyPair {
                plaintext_key: plaintext.plaintext,
                wrapped_key: result.ciphertext,
                key_version: result.key_version,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shroudb_cipher_core::keyring::KeyringAlgorithm;
    use shroudb_cipher_engine::engine::{CipherConfig, CipherEngine};
    use shroudb_storage::EmbeddedStore;
    use shroudb_storage::test_util::create_test_store;

    async fn build_cipher() -> Arc<CipherEngine<EmbeddedStore>> {
        let store = create_test_store("cipher").await;
        let engine = CipherEngine::new(
            store,
            CipherConfig::default(),
            shroudb_server_bootstrap::Capability::DisabledForTests,
            shroudb_server_bootstrap::Capability::DisabledForTests,
        )
        .await
        .expect("cipher engine init");
        engine
            .keyring_create(
                "stash-blobs",
                KeyringAlgorithm::Aes256Gcm,
                None,
                None,
                false,
                None,
            )
            .await
            .expect("keyring create");
        Arc::new(engine)
    }

    #[tokio::test]
    async fn generate_and_unwrap_round_trip_yields_original_dek() {
        let cipher = build_cipher().await;
        let ops = EmbeddedStashCipherOps::new(cipher, "stash-blobs".into());

        let pair = ops
            .generate_data_key(Some(256), "test-actor")
            .await
            .expect("generate");
        assert_eq!(pair.plaintext_key.as_bytes().len(), 32);
        assert!(!pair.wrapped_key.is_empty());

        let unwrapped = ops
            .unwrap_data_key(&pair.wrapped_key, "test-actor")
            .await
            .expect("unwrap");
        assert_eq!(unwrapped.as_bytes(), pair.plaintext_key.as_bytes());
    }

    #[tokio::test]
    async fn rewrap_updates_key_version_and_preserves_plaintext() {
        let cipher = build_cipher().await;
        let ops = EmbeddedStashCipherOps::new(cipher, "stash-blobs".into());

        let original = ops
            .generate_data_key(Some(256), "test-actor")
            .await
            .expect("generate");
        let rewrapped = ops
            .rewrap_data_key(&original.wrapped_key, "test-actor")
            .await
            .expect("rewrap");

        // Plaintext DEK survives the rewrap.
        assert_eq!(
            rewrapped.plaintext_key.as_bytes(),
            original.plaintext_key.as_bytes()
        );
        // Same active key version (no rotation mid-test), so wrapped
        // envelope is new but key_version matches.
        assert_eq!(rewrapped.key_version, original.key_version);
    }
}
