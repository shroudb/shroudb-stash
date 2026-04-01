use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use shroudb_stash_core::error::StashError;

/// AES-256-GCM nonce size in bytes.
const NONCE_LEN: usize = 12;
/// AES-256-GCM tag size in bytes.
const TAG_LEN: usize = 16;
/// Required DEK size for AES-256-GCM.
const KEY_LEN: usize = 32;

/// Encrypt a plaintext blob using AES-256-GCM with a random nonce.
///
/// Output format: `nonce (12 bytes) || ciphertext || tag (16 bytes)`
///
/// The DEK must be exactly 32 bytes (AES-256).
pub fn encrypt_blob(dek: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, StashError> {
    if dek.len() != KEY_LEN {
        return Err(StashError::Crypto(format!(
            "DEK must be {KEY_LEN} bytes, got {}",
            dek.len()
        )));
    }

    let rng = SystemRandom::new();

    // Generate random nonce.
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng.fill(&mut nonce_bytes)
        .map_err(|_| StashError::Crypto("CSPRNG failed generating nonce".into()))?;

    let unbound_key = UnboundKey::new(&AES_256_GCM, dek)
        .map_err(|e| StashError::Crypto(format!("invalid DEK: {e}")))?;
    let key = LessSafeKey::new(unbound_key);

    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    // Encrypt: plaintext → ciphertext || tag (in place, then prepend nonce).
    let mut in_out = plaintext.to_vec();
    key.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
        .map_err(|e| StashError::Crypto(format!("encryption failed: {e}")))?;

    // Build final output: nonce || ciphertext || tag
    let mut output = Vec::with_capacity(NONCE_LEN + in_out.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&in_out);

    Ok(output)
}

/// Decrypt a blob encrypted with `encrypt_blob`.
///
/// Input format: `nonce (12 bytes) || ciphertext || tag (16 bytes)`
///
/// Returns the plaintext bytes.
pub fn decrypt_blob(dek: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, StashError> {
    if dek.len() != KEY_LEN {
        return Err(StashError::Crypto(format!(
            "DEK must be {KEY_LEN} bytes, got {}",
            dek.len()
        )));
    }

    let min_len = NONCE_LEN + TAG_LEN;
    if ciphertext.len() < min_len {
        return Err(StashError::Crypto(format!(
            "ciphertext too short: {} bytes (minimum {min_len})",
            ciphertext.len()
        )));
    }

    // Extract nonce from the first 12 bytes.
    let mut nonce_bytes = [0u8; NONCE_LEN];
    nonce_bytes.copy_from_slice(&ciphertext[..NONCE_LEN]);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let unbound_key = UnboundKey::new(&AES_256_GCM, dek)
        .map_err(|e| StashError::Crypto(format!("invalid DEK: {e}")))?;
    let key = LessSafeKey::new(unbound_key);

    // Copy the ciphertext+tag portion for in-place decryption.
    let mut buffer = ciphertext[NONCE_LEN..].to_vec();

    let plaintext = key
        .open_in_place(nonce, Aad::empty(), &mut buffer)
        .map_err(|_| StashError::Crypto("decryption failed: authentication tag mismatch".into()))?;

    Ok(plaintext.to_vec())
}

/// Returns the encrypted size for a given plaintext size.
/// Overhead: 12 bytes nonce + 16 bytes tag = 28 bytes.
pub fn encrypted_size(plaintext_len: u64) -> u64 {
    plaintext_len + (NONCE_LEN + TAG_LEN) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn random_key() -> Vec<u8> {
        let rng = SystemRandom::new();
        let mut key = vec![0u8; KEY_LEN];
        rng.fill(&mut key).unwrap();
        key
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = random_key();
        let plaintext = b"hello, stash!";

        let ciphertext = encrypt_blob(&key, plaintext).unwrap();
        assert_ne!(ciphertext, plaintext);
        assert_eq!(ciphertext.len(), NONCE_LEN + plaintext.len() + TAG_LEN);

        let decrypted = decrypt_blob(&key, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_decrypt_empty_plaintext() {
        let key = random_key();
        let plaintext = b"";

        let ciphertext = encrypt_blob(&key, plaintext).unwrap();
        assert_eq!(ciphertext.len(), NONCE_LEN + TAG_LEN);

        let decrypted = decrypt_blob(&key, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_decrypt_large_payload() {
        let key = random_key();
        let plaintext = vec![0xABu8; 10 * 1024 * 1024]; // 10 MB

        let ciphertext = encrypt_blob(&key, &plaintext).unwrap();
        let decrypted = decrypt_blob(&key, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_key_fails() {
        let key1 = random_key();
        let key2 = random_key();
        let ciphertext = encrypt_blob(&key1, b"secret").unwrap();
        let err = decrypt_blob(&key2, &ciphertext).unwrap_err();
        assert!(matches!(err, StashError::Crypto(_)));
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = random_key();
        let mut ciphertext = encrypt_blob(&key, b"secret").unwrap();
        // Flip a byte in the ciphertext body.
        let mid = NONCE_LEN + 2;
        if mid < ciphertext.len() {
            ciphertext[mid] ^= 0xFF;
        }
        let err = decrypt_blob(&key, &ciphertext).unwrap_err();
        assert!(matches!(err, StashError::Crypto(_)));
    }

    #[test]
    fn short_ciphertext_fails() {
        let key = random_key();
        let err = decrypt_blob(&key, &[0u8; 10]).unwrap_err();
        assert!(matches!(err, StashError::Crypto(_)));
    }

    #[test]
    fn invalid_key_length_fails() {
        let short_key = vec![0u8; 16]; // AES-128, not AES-256
        let err = encrypt_blob(&short_key, b"test").unwrap_err();
        assert!(matches!(err, StashError::Crypto(_)));

        let err = decrypt_blob(&short_key, &[0u8; 40]).unwrap_err();
        assert!(matches!(err, StashError::Crypto(_)));
    }

    #[test]
    fn encrypted_size_calculation() {
        assert_eq!(encrypted_size(0), 28);
        assert_eq!(encrypted_size(100), 128);
        assert_eq!(encrypted_size(1024), 1052);
    }

    #[test]
    fn different_encryptions_produce_different_ciphertexts() {
        let key = random_key();
        let plaintext = b"same plaintext";
        let ct1 = encrypt_blob(&key, plaintext).unwrap();
        let ct2 = encrypt_blob(&key, plaintext).unwrap();
        // Random nonces should make these different.
        assert_ne!(ct1, ct2);
        // But both decrypt to the same plaintext.
        assert_eq!(
            decrypt_blob(&key, &ct1).unwrap(),
            decrypt_blob(&key, &ct2).unwrap()
        );
    }
}
