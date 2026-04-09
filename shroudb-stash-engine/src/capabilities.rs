use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use shroudb_acl::PolicyEvaluator;
use shroudb_chronicle_core::ops::ChronicleOps;
use shroudb_crypto::SensitiveBytes;
use shroudb_stash_core::error::StashError;

/// Shorthand for a pinned boxed future used in capability traits.
pub type BoxFut<'a, T> = Pin<Box<dyn Future<Output = Result<T, StashError>> + Send + 'a>>;

/// Result of a data key generation operation.
pub struct DataKeyPair {
    /// Plaintext DEK for local encryption. Must be zeroized after use.
    pub plaintext_key: SensitiveBytes,
    /// Base64-encoded CiphertextEnvelope wrapping the DEK.
    pub wrapped_key: String,
    /// Cipher key version that wrapped this DEK.
    pub key_version: u32,
}

/// Cipher operations for Stash's envelope encryption model.
///
/// Unlike Sigil's `CipherOps` (which does field-level encrypt/decrypt),
/// Stash needs `generate_data_key` (produce a random DEK and wrap it)
/// and `unwrap_data_key` (decrypt a previously wrapped DEK).
///
/// Stash performs the actual blob encryption/decryption locally using
/// the plaintext DEK. Cipher only manages the key wrapping.
pub trait StashCipherOps: Send + Sync {
    /// Generate a random data encryption key and wrap it with the keyring's active key.
    ///
    /// `bits` defaults to 256 if `None`.
    fn generate_data_key(&self, bits: Option<u32>) -> BoxFut<'_, DataKeyPair>;

    /// Unwrap a previously wrapped DEK by decrypting the CiphertextEnvelope.
    ///
    /// The returned `SensitiveBytes` contains the plaintext DEK and will be
    /// zeroized on drop.
    fn unwrap_data_key(&self, wrapped_key: &str) -> BoxFut<'_, SensitiveBytes>;

    /// Re-wrap a DEK under the current active key version. Unwraps the old
    /// wrapped key, then wraps the plaintext DEK with the keyring's current key.
    ///
    /// Returns a new `DataKeyPair` with the updated `wrapped_key` and `key_version`.
    /// The blob ciphertext is NOT re-encrypted — only the wrapping changes.
    fn rewrap_data_key(&self, old_wrapped_key: &str) -> BoxFut<'_, DataKeyPair>;
}

/// Engine capabilities provided at construction time.
///
/// In Moat (embedded mode): built from co-located engine handles.
/// In standalone mode: built from config (remote endpoints or absent).
#[derive(Default)]
pub struct Capabilities {
    pub cipher: Option<Box<dyn StashCipherOps>>,
    pub sentry: Option<Arc<dyn PolicyEvaluator>>,
    pub chronicle: Option<Arc<dyn ChronicleOps>>,
}

// Capabilities derives Default: all fields are Option, defaulting to None.
