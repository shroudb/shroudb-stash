use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use shroudb_stash_core::error::StashError;

/// AES-256-GCM nonce size in bytes.
pub const NONCE_LEN: usize = 12;
/// AES-256-GCM tag size in bytes.
pub const TAG_LEN: usize = 16;
/// Required DEK size for AES-256-GCM.
const KEY_LEN: usize = 32;

/// Minimum valid ciphertext size: nonce + authentication tag.
/// Any AES-256-GCM ciphertext (even for zero-length plaintext) must contain
/// at least a 12-byte nonce and a 16-byte authentication tag.
pub const MIN_CIPHERTEXT_LEN: usize = NONCE_LEN + TAG_LEN;

/// Encrypt a plaintext blob using AES-256-GCM with a random nonce.
///
/// Output format: `nonce (12 bytes) || ciphertext || tag (16 bytes)`
///
/// The DEK must be exactly 32 bytes (AES-256).
/// `aad` is additional authenticated data binding the ciphertext to context
/// (typically the blob ID). This must match exactly during decryption.
pub fn encrypt_blob(dek: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, StashError> {
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
    key.seal_in_place_append_tag(nonce, Aad::from(aad), &mut in_out)
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
/// `aad` must match the additional authenticated data used during encryption.
/// Returns the plaintext bytes.
pub fn decrypt_blob(dek: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, StashError> {
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
        .open_in_place(nonce, Aad::from(aad), &mut buffer)
        .map_err(|_| StashError::Crypto("decryption failed: authentication tag mismatch".into()))?;

    Ok(plaintext.to_vec())
}

/// Decrypt with backward compatibility: tries AAD-bound decryption first,
/// falls back to empty AAD for blobs encrypted before AAD binding was added.
/// Returns `(plaintext, used_legacy)` where `used_legacy` is true if the
/// empty-AAD fallback was needed.
pub fn decrypt_blob_compat(
    dek: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<(Vec<u8>, bool), StashError> {
    // Try with AAD first (new format)
    match decrypt_blob(dek, ciphertext, aad) {
        Ok(plaintext) => Ok((plaintext, false)),
        Err(_) => {
            // Fall back to empty AAD (pre-migration format)
            match decrypt_blob(dek, ciphertext, b"") {
                Ok(plaintext) => Ok((plaintext, true)),
                Err(e) => Err(e),
            }
        }
    }
}

/// Returns the encrypted size for a given plaintext size (single-blob mode).
/// Overhead: 12 bytes nonce + 16 bytes tag = 28 bytes.
pub fn encrypted_size(plaintext_len: u64) -> u64 {
    plaintext_len + (NONCE_LEN + TAG_LEN) as u64
}

// ── Chunked streaming encryption ─────────────────────────────────────

/// Default chunk size for streaming encryption: 1 MB.
const CHUNK_SIZE: usize = 1024 * 1024;
/// Version byte for chunked format.
const CHUNKED_VERSION: u8 = 0x01;
/// Header size: version (1) + chunk_size (4) + chunk_count (4) = 9 bytes.
const CHUNKED_HEADER_LEN: usize = 9;
/// Per-chunk overhead: nonce (12) + tag (16) = 28 bytes.
const CHUNK_OVERHEAD: usize = NONCE_LEN + TAG_LEN;

/// Encrypt a blob using chunked streaming encryption.
///
/// Each chunk is independently encrypted with AES-256-GCM. The AAD for each
/// chunk is `blob_aad || chunk_index (4 bytes LE)`, binding every chunk to
/// both the blob identity and its position in the sequence.
///
/// Output format:
/// ```text
/// version (1 byte = 0x01)
/// chunk_size (4 bytes LE)
/// chunk_count (4 bytes LE)
/// chunk_0: nonce (12) || ciphertext || tag (16)
/// chunk_1: ...
/// ...
/// ```
///
/// Memory: only one chunk of plaintext + ciphertext is held at a time.
pub fn encrypt_blob_chunked(
    dek: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, StashError> {
    if dek.len() != KEY_LEN {
        return Err(StashError::Crypto(format!(
            "DEK must be {KEY_LEN} bytes, got {}",
            dek.len()
        )));
    }

    let chunk_count = if plaintext.is_empty() {
        0
    } else {
        plaintext.len().div_ceil(CHUNK_SIZE)
    };
    let total_size = CHUNKED_HEADER_LEN + chunk_count * CHUNK_OVERHEAD + plaintext.len();
    let mut output = Vec::with_capacity(total_size);

    // Header
    output.push(CHUNKED_VERSION);
    output.extend_from_slice(&(CHUNK_SIZE as u32).to_le_bytes());
    output.extend_from_slice(&(chunk_count as u32).to_le_bytes());

    let rng = SystemRandom::new();

    for (i, chunk) in plaintext.chunks(CHUNK_SIZE).enumerate() {
        let unbound_key = UnboundKey::new(&AES_256_GCM, dek)
            .map_err(|e| StashError::Crypto(format!("invalid DEK: {e}")))?;
        let key = LessSafeKey::new(unbound_key);

        let mut nonce_bytes = [0u8; NONCE_LEN];
        rng.fill(&mut nonce_bytes)
            .map_err(|_| StashError::Crypto("CSPRNG failed generating nonce".into()))?;
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        // AAD: blob_aad || chunk_index
        let mut chunk_aad = Vec::with_capacity(aad.len() + 4);
        chunk_aad.extend_from_slice(aad);
        chunk_aad.extend_from_slice(&(i as u32).to_le_bytes());

        let mut in_out = chunk.to_vec();
        key.seal_in_place_append_tag(nonce, Aad::from(chunk_aad.as_slice()), &mut in_out)
            .map_err(|e| StashError::Crypto(format!("chunk {i} encryption failed: {e}")))?;

        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&in_out);
        // `in_out` is dropped here — only one chunk buffer at a time
    }

    Ok(output)
}

/// Decrypt a blob encrypted with `encrypt_blob_chunked`.
///
/// Memory: only one chunk is decrypted at a time.
pub fn decrypt_blob_chunked(
    dek: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, StashError> {
    if dek.len() != KEY_LEN {
        return Err(StashError::Crypto(format!(
            "DEK must be {KEY_LEN} bytes, got {}",
            dek.len()
        )));
    }

    if ciphertext.len() < CHUNKED_HEADER_LEN {
        return Err(StashError::Crypto(
            "chunked ciphertext too short for header".into(),
        ));
    }

    if ciphertext[0] != CHUNKED_VERSION {
        return Err(StashError::Crypto(format!(
            "unsupported chunked version: {}",
            ciphertext[0]
        )));
    }

    let chunk_size = u32::from_le_bytes(ciphertext[1..5].try_into().unwrap()) as usize;
    let chunk_count = u32::from_le_bytes(ciphertext[5..9].try_into().unwrap()) as usize;

    let mut offset = CHUNKED_HEADER_LEN;
    let mut plaintext = Vec::new();

    for i in 0..chunk_count {
        // Determine expected encrypted chunk size
        let remaining = offset..ciphertext.len();
        if remaining.is_empty() {
            return Err(StashError::Crypto(format!(
                "unexpected end of data at chunk {i}"
            )));
        }

        // Each chunk: nonce (12) + encrypted_data + tag (16)
        // For the last chunk, the plaintext portion may be smaller than chunk_size
        let is_last = i == chunk_count - 1;
        let encrypted_chunk_len = if is_last {
            ciphertext.len() - offset
        } else {
            NONCE_LEN + chunk_size + TAG_LEN
        };

        if offset + encrypted_chunk_len > ciphertext.len() {
            return Err(StashError::Crypto(format!(
                "chunk {i} extends past ciphertext boundary"
            )));
        }

        let chunk_data = &ciphertext[offset..offset + encrypted_chunk_len];
        if chunk_data.len() < NONCE_LEN + TAG_LEN {
            return Err(StashError::Crypto(format!("chunk {i} too short")));
        }

        let mut nonce_bytes = [0u8; NONCE_LEN];
        nonce_bytes.copy_from_slice(&chunk_data[..NONCE_LEN]);
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        let unbound_key = UnboundKey::new(&AES_256_GCM, dek)
            .map_err(|e| StashError::Crypto(format!("invalid DEK: {e}")))?;
        let key = LessSafeKey::new(unbound_key);

        let mut chunk_aad = Vec::with_capacity(aad.len() + 4);
        chunk_aad.extend_from_slice(aad);
        chunk_aad.extend_from_slice(&(i as u32).to_le_bytes());

        let mut buffer = chunk_data[NONCE_LEN..].to_vec();
        let decrypted = key
            .open_in_place(nonce, Aad::from(chunk_aad.as_slice()), &mut buffer)
            .map_err(|_| {
                StashError::Crypto(format!("chunk {i} decryption failed: tag mismatch"))
            })?;

        plaintext.extend_from_slice(decrypted);
        offset += encrypted_chunk_len;
    }

    Ok(plaintext)
}

/// Check if ciphertext uses the chunked streaming format.
pub fn is_chunked(ciphertext: &[u8]) -> bool {
    ciphertext.first() == Some(&CHUNKED_VERSION)
}

/// Returns the encrypted size for chunked encryption.
pub fn encrypted_size_chunked(plaintext_len: u64) -> u64 {
    let chunks = if plaintext_len == 0 {
        0
    } else {
        (plaintext_len as usize).div_ceil(CHUNK_SIZE)
    };
    CHUNKED_HEADER_LEN as u64 + chunks as u64 * CHUNK_OVERHEAD as u64 + plaintext_len
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
        let aad = b"blob-123";

        let ciphertext = encrypt_blob(&key, plaintext, aad).unwrap();
        assert_ne!(ciphertext, plaintext);
        assert_eq!(ciphertext.len(), NONCE_LEN + plaintext.len() + TAG_LEN);

        let decrypted = decrypt_blob(&key, &ciphertext, aad).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_decrypt_empty_plaintext() {
        let key = random_key();
        let plaintext = b"";
        let aad = b"blob-empty";

        let ciphertext = encrypt_blob(&key, plaintext, aad).unwrap();
        assert_eq!(ciphertext.len(), NONCE_LEN + TAG_LEN);

        let decrypted = decrypt_blob(&key, &ciphertext, aad).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_decrypt_large_payload() {
        let key = random_key();
        let plaintext = vec![0xABu8; 10 * 1024 * 1024]; // 10 MB
        let aad = b"blob-large";

        let ciphertext = encrypt_blob(&key, &plaintext, aad).unwrap();
        let decrypted = decrypt_blob(&key, &ciphertext, aad).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_key_fails() {
        let key1 = random_key();
        let key2 = random_key();
        let aad = b"blob-key-test";
        let ciphertext = encrypt_blob(&key1, b"secret", aad).unwrap();
        let err = decrypt_blob(&key2, &ciphertext, aad).unwrap_err();
        assert!(matches!(err, StashError::Crypto(_)));
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = random_key();
        let aad = b"blob-tamper";
        let mut ciphertext = encrypt_blob(&key, b"secret", aad).unwrap();
        // Flip a byte in the ciphertext body.
        let mid = NONCE_LEN + 2;
        if mid < ciphertext.len() {
            ciphertext[mid] ^= 0xFF;
        }
        let err = decrypt_blob(&key, &ciphertext, aad).unwrap_err();
        assert!(matches!(err, StashError::Crypto(_)));
    }

    #[test]
    fn short_ciphertext_fails() {
        let key = random_key();
        let err = decrypt_blob(&key, &[0u8; 10], b"").unwrap_err();
        assert!(matches!(err, StashError::Crypto(_)));
    }

    #[test]
    fn invalid_key_length_fails() {
        let short_key = vec![0u8; 16]; // AES-128, not AES-256
        let err = encrypt_blob(&short_key, b"test", b"").unwrap_err();
        assert!(matches!(err, StashError::Crypto(_)));

        let err = decrypt_blob(&short_key, &[0u8; 40], b"").unwrap_err();
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
        let aad = b"blob-diff";
        let ct1 = encrypt_blob(&key, plaintext, aad).unwrap();
        let ct2 = encrypt_blob(&key, plaintext, aad).unwrap();
        // Random nonces should make these different.
        assert_ne!(ct1, ct2);
        // But both decrypt to the same plaintext.
        assert_eq!(
            decrypt_blob(&key, &ct1, aad).unwrap(),
            decrypt_blob(&key, &ct2, aad).unwrap()
        );
    }

    #[test]
    fn wrong_aad_fails_decrypt() {
        let key = random_key();
        let plaintext = b"sensitive data";
        let aad_a = b"blob-A";
        let aad_b = b"blob-B";

        // Encrypt with blob-A's ID as AAD
        let ciphertext = encrypt_blob(&key, plaintext, aad_a).unwrap();

        // Decrypt with correct AAD succeeds
        let decrypted = decrypt_blob(&key, &ciphertext, aad_a).unwrap();
        assert_eq!(decrypted, plaintext);

        // Decrypt with wrong AAD (transplant to blob-B) fails
        let err = decrypt_blob(&key, &ciphertext, aad_b).unwrap_err();
        assert!(
            matches!(err, StashError::Crypto(_)),
            "transplanted ciphertext should fail authentication"
        );
    }

    // ── Chunked streaming tests ──────────────────────────────────────

    #[test]
    fn chunked_roundtrip_small() {
        let key = random_key();
        let plaintext = b"small blob";
        let aad = b"blob-chunked-small";

        let ct = encrypt_blob_chunked(&key, plaintext, aad).unwrap();
        assert!(is_chunked(&ct));

        let decrypted = decrypt_blob_chunked(&key, &ct, aad).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn chunked_roundtrip_multi_chunk() {
        let key = random_key();
        // 2.5 chunks worth of data
        let plaintext = vec![0xCDu8; CHUNK_SIZE * 2 + CHUNK_SIZE / 2];
        let aad = b"blob-multi-chunk";

        let ct = encrypt_blob_chunked(&key, &plaintext, aad).unwrap();
        assert!(is_chunked(&ct));
        assert_eq!(ct[0], CHUNKED_VERSION);

        let decrypted = decrypt_blob_chunked(&key, &ct, aad).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn chunked_wrong_aad_fails() {
        let key = random_key();
        let plaintext = vec![0xAAu8; CHUNK_SIZE + 100];

        let ct = encrypt_blob_chunked(&key, &plaintext, b"blob-A").unwrap();
        let err = decrypt_blob_chunked(&key, &ct, b"blob-B").unwrap_err();
        assert!(matches!(err, StashError::Crypto(_)));
    }

    #[test]
    fn chunked_empty_plaintext() {
        let key = random_key();
        let ct = encrypt_blob_chunked(&key, b"", b"blob-empty-chunked").unwrap();
        let decrypted = decrypt_blob_chunked(&key, &ct, b"blob-empty-chunked").unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn non_chunked_not_detected_as_chunked() {
        let key = random_key();
        let ct = encrypt_blob(&key, b"hello", b"blob").unwrap();
        assert!(!is_chunked(&ct));
    }

    // ── Backward compatibility tests ─────────────────────────────────

    #[test]
    fn compat_decrypts_old_empty_aad_blobs() {
        let key = random_key();
        let plaintext = b"legacy blob data";

        // Simulate a blob encrypted with the old code (empty AAD)
        let old_ciphertext = encrypt_blob(&key, plaintext, b"").unwrap();

        // New compat decrypt with blob ID as AAD should fall back to empty AAD
        let (decrypted, used_legacy) =
            decrypt_blob_compat(&key, &old_ciphertext, b"blob-123").unwrap();
        assert_eq!(decrypted, plaintext);
        assert!(used_legacy, "should have used legacy empty-AAD fallback");
    }

    #[test]
    fn compat_prefers_new_aad_when_available() {
        let key = random_key();
        let plaintext = b"new blob data";
        let aad = b"blob-456";

        // Encrypt with proper AAD
        let ciphertext = encrypt_blob(&key, plaintext, aad).unwrap();

        // Compat decrypt should succeed with primary AAD, not legacy
        let (decrypted, used_legacy) = decrypt_blob_compat(&key, &ciphertext, aad).unwrap();
        assert_eq!(decrypted, plaintext);
        assert!(!used_legacy, "should not use legacy fallback for new blobs");
    }

    #[test]
    fn compat_fails_when_both_aad_wrong() {
        let key = random_key();
        let plaintext = b"data";

        // Encrypt with AAD "blob-A"
        let ciphertext = encrypt_blob(&key, plaintext, b"blob-A").unwrap();

        // Try to compat-decrypt with AAD "blob-B" — neither blob-B nor empty AAD will match
        let err = decrypt_blob_compat(&key, &ciphertext, b"blob-B").unwrap_err();
        assert!(matches!(err, StashError::Crypto(_)));
    }
}
