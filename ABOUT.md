# Understanding Stash

## For Everyone: What Stash Does

Applications that store files, images, documents, or any binary data face a common problem: data at rest in object storage (S3, MinIO, R2) is only as secure as the bucket's access controls. If a bucket is misconfigured, every file inside is exposed. If a backup is compromised, every file is readable.

**Stash is an encrypted blob storage engine.** You store a blob through Stash; Stash encrypts it before it touches S3 and keeps the encryption key locked inside Cipher. To read the blob back, you go through Stash, which decrypts it for you. The S3 bucket only ever holds encrypted data that is worthless without the key.

- **Server-side envelope encryption** — Cipher generates the data encryption key, Stash encrypts the blob locally, uploads only ciphertext
- **Client-encrypted passthrough** — for clients that handle their own crypto, Stash stores the ciphertext as-is
- **Crypto-shredding** — hard revoke destroys the encryption key, making the blob permanently unrecoverable without touching every S3 copy
- **Soft revoke** — marks the blob as revoked for legal/forensic holds without destroying data
- **Metadata without decryption** — INSPECT reads blob metadata (size, type, status) without downloading or decrypting

## For Technical Leaders: Architecture and Trade-offs

### The Problem

Storing sensitive data in S3 is a known risk surface. S3 server-side encryption (SSE-S3, SSE-KMS) encrypts at rest but: the cloud provider holds the keys, any principal with `s3:GetObject` sees plaintext, and revoking access means changing IAM policies — not destroying data. For regulated industries or privacy-sensitive applications, this is insufficient.

### What Stash Is

Stash is a **client-side envelope encryption layer** that sits between your application and S3. It uses Cipher (ShrouDB's encryption engine) for key management and performs AES-256-GCM encryption locally before uploading to S3.

The key insight: **separating the key from the ciphertext** means compromising S3 doesn't compromise data, and destroying the key provably destroys access to the data.

### Key Architectural Decisions

| Decision | Rationale |
|----------|-----------|
| **Envelope encryption** | A unique DEK per blob, wrapped by Cipher's keyring. Rotating the keyring doesn't require re-encrypting every blob — just rewrapping the DEK. |
| **Local encryption** | Stash encrypts the blob in its own process, then uploads ciphertext to S3. This avoids streaming plaintext over the network to Cipher. |
| **Metadata in ShrouDB, blobs in S3** | Metadata (wrapped DEK, status, timestamps) lives in the ShrouDB Store with encryption at rest. Blobs live in S3 because the Store isn't designed for multi-GB objects. |
| **Crypto-shredding over deletion** | Deleting from S3 may not immediately purge all replicas and backups. Destroying the DEK makes all copies unrecoverable regardless of S3's internal retention. |
| **Client-encrypted passthrough** | Advanced clients that manage their own encryption can use Stash purely for metadata tracking and access control, without Stash seeing plaintext. |
| **Viewer maps for forensic watermarking (v0.2)** | The metadata structure includes viewer→S3 key mappings from day one, enabling future FINGERPRINT functionality (per-viewer watermarking for leak tracing) without schema migration. This is forensic attribution, not content deduplication. |

### Data Flow

```
STORE:
  App → plaintext blob → Stash
    → Cipher.GENERATE_DATA_KEY → {plaintext_dek, wrapped_dek}
    → AES-256-GCM(plaintext_dek, blob) → ciphertext
    → S3.PUT(ciphertext)
    → Store.PUT(wrapped_dek, s3_key, metadata)
    → zeroize(plaintext_dek)

RETRIEVE:
  App → RETRIEVE id → Stash
    → Store.GET(metadata)
    → S3.GET(ciphertext)
    → Cipher.DECRYPT(wrapped_dek) → plaintext_dek
    → AES-256-GCM_OPEN(plaintext_dek, ciphertext) → plaintext
    → zeroize(plaintext_dek)
    → plaintext blob → App

REVOKE (hard):
  → Store.GET(metadata)
  → S3.DELETE(master_blob)
  → S3.DELETE(viewer_copies...)
  → Store.PUT(status=shredded, wrapped_dek="")
  → wrapped_dek is gone → ciphertext is garbage
```

### Operational Model

- **Object store:** Any S3-compatible backend (AWS S3, MinIO, Cloudflare R2, etc.) configured via bucket/region/endpoint.
- **Encryption:** AES-256-GCM with random 96-bit nonces. 28 bytes overhead per blob (12 nonce + 16 tag).
- **Key management:** Delegated to Cipher. Stash never generates or stores raw key material. DEKs exist in memory only during encrypt/decrypt.
- **Access control:** Sentry ABAC policies gate every operation. Separate permissions for STORE, RETRIEVE, INSPECT, REVOKE.
- **Audit:** Every operation emits a Chronicle event (STORE, RETRIEVE, INSPECT, REVOKE_SOFT, REVOKE_HARD).

### Ecosystem

Stash is one engine in the ShrouDB ecosystem:

- **ShrouDB** — encrypted versioned KV store (the foundation)
- **Cipher** — encryption-as-a-service (key management, DEK generation)
- **Stash** — encrypted blob storage (this engine)
- **Sigil** — credential envelope (password hashing, JWT, field-level crypto)
- **Veil** — blind indexing (searchable encryption)
- **Keep** — versioned secret storage
- **Forge** — certificate management
- **Sentry** — authorization policies
- **Courier** — notification queues
- **Chronicle** — audit event engine
