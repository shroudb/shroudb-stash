use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use shroudb_acl::PolicyEvaluator;
use shroudb_chronicle_core::ops::ChronicleOps;
use shroudb_crypto::SensitiveBytes;
use shroudb_server_bootstrap::Capability;
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
/// Every slot is a [`Capability<T>`] — the explicit tri-state from
/// `shroudb-server-bootstrap`. *Absence is never silent.* Callers must
/// pick `Enabled`, `DisabledForTests`, or `DisabledWithJustification`.
///
/// Stash's data plane (`STORE`, `RETRIEVE`) requires Cipher and will
/// fail-closed at use site with a `CapabilityMissing("cipher")`-style
/// error when it's not `Enabled`. Metadata-only operations can work
/// without Cipher in explicit disabled modes (useful for inspection /
/// teardown of crypto-shredded blobs).
pub struct Capabilities {
    pub cipher: Capability<Box<dyn StashCipherOps>>,
    pub sentry: Capability<Arc<dyn PolicyEvaluator>>,
    pub chronicle: Capability<Arc<dyn ChronicleOps>>,
}

impl Capabilities {
    /// Construct for unit tests — every slot `DisabledForTests`.
    /// Never use in production code.
    pub fn for_tests() -> Self {
        Self {
            cipher: Capability::DisabledForTests,
            sentry: Capability::DisabledForTests,
            chronicle: Capability::DisabledForTests,
        }
    }

    /// Construct a Capabilities set with explicit values for every slot.
    /// Standalone servers should build each `Capability<...>` from config
    /// (via `shroudb-engine-bootstrap` resolvers for audit/policy plus
    /// their own cipher wiring) and pass the triple here.
    pub fn new(
        cipher: Capability<Box<dyn StashCipherOps>>,
        sentry: Capability<Arc<dyn PolicyEvaluator>>,
        chronicle: Capability<Arc<dyn ChronicleOps>>,
    ) -> Self {
        Self {
            cipher,
            sentry,
            chronicle,
        }
    }

    pub fn with_cipher(mut self, cipher: Box<dyn StashCipherOps>) -> Self {
        self.cipher = Capability::Enabled(cipher);
        self
    }

    pub fn with_sentry(mut self, sentry: Arc<dyn PolicyEvaluator>) -> Self {
        self.sentry = Capability::Enabled(sentry);
        self
    }

    pub fn with_chronicle(mut self, chronicle: Arc<dyn ChronicleOps>) -> Self {
        self.chronicle = Capability::Enabled(chronicle);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn for_tests_initializes_all_slots_disabled_for_tests() {
        let caps = Capabilities::for_tests();
        assert!(!caps.cipher.is_enabled());
        assert!(!caps.sentry.is_enabled());
        assert!(!caps.chronicle.is_enabled());
    }
}
