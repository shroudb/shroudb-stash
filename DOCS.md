# Stash Reference

Complete reference for the ShrouDB Stash encrypted blob storage engine.

## Commands

### STORE

Store an encrypted blob.

```
STORE <id> <data_b64> [KEYRING <name>] [CONTENT_TYPE <mime>] [CLIENT_ENCRYPTED <wrapped_dek>]
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `id` | yes | Unique blob identifier |
| `data_b64` | yes | Base64-encoded blob data |
| `KEYRING` | no | Cipher keyring name (default: `stash-blobs`) |
| `CONTENT_TYPE` | no | MIME type (e.g. `image/png`, `application/pdf`) |
| `CLIENT_ENCRYPTED` | no | Passthrough mode — value is the wrapped DEK |

**Response:**

```json
{
  "status": "ok",
  "id": "my-doc",
  "s3_key": "stash/my-doc",
  "keyring": "stash-blobs",
  "key_version": 1,
  "plaintext_size": 12345,
  "encrypted_size": 12373,
  "client_encrypted": false,
  "content_hash": "…",
  "deduplicated": false
}
```

**Errors:**

| Code | Condition |
|------|-----------|
| `EXISTS` | Blob with this ID already exists |
| `CIPHER_UNAVAILABLE` | Cipher engine not available |
| `INVALID_ARGUMENT` | `CLIENT_ENCRYPTED` without wrapped DEK |
| `DENIED` | ABAC policy denied the operation |
| `OBJECT_STORE` | S3 upload failed |

### RETRIEVE

Retrieve and decrypt a blob.

```
RETRIEVE <id>
```

**Response:** RESP3 Array of two BulkStrings:

1. `metadata_json` — JSON object with `status`, `id`, `content_type`, `plaintext_size`, `client_encrypted`
2. `blob_bytes` — raw plaintext bytes (or ciphertext for client-encrypted blobs)

For client-encrypted blobs, metadata includes `wrapped_dek` — the client uses this to decrypt.

**Errors:**

| Code | Condition |
|------|-----------|
| `NOTFOUND` | Blob does not exist |
| `REVOKED` | Blob was soft-revoked |
| `SHREDDED` | Blob was hard-revoked (crypto-shredded) |
| `CIPHER_UNAVAILABLE` | Cipher engine not available for decryption |
| `DENIED` | ABAC policy denied the operation |
| `OBJECT_STORE` | S3 download failed |
| `CRYPTO` | Decryption failed (corrupted blob or wrong key) |

### INSPECT

Read blob metadata without downloading or decrypting.

```
INSPECT <id>
```

**Response:**

```json
{
  "status": "ok",
  "id": "my-doc",
  "blob_status": "active",
  "content_type": "application/pdf",
  "plaintext_size": 12345,
  "encrypted_size": 12373,
  "keyring": "stash-blobs",
  "key_version": 1,
  "client_encrypted": false,
  "viewer_count": 0,
  "created_at": 1700000000000,
  "updated_at": 1700000000000
}
```

**Errors:**

| Code | Condition |
|------|-----------|
| `NOTFOUND` | Blob does not exist |
| `DENIED` | ABAC policy denied the operation |

### REVOKE

Revoke a blob.

```
REVOKE <id> [SOFT]
```

| Mode | Behavior |
|------|----------|
| **Hard (default)** | Crypto-shred: destroy wrapped DEK, delete all S3 objects (master + viewer copies), tombstone metadata |
| **Soft (`SOFT` flag)** | Mark as revoked in metadata. Sentry blocks future RETRIEVE. All data preserved. |

**Response:**

```json
{
  "status": "ok",
  "id": "my-doc",
  "revoke_mode": "hard"
}
```

**Errors:**

| Code | Condition |
|------|-----------|
| `NOTFOUND` | Blob does not exist |
| `SHREDDED` | Blob already crypto-shredded |
| `DENIED` | ABAC policy denied the operation |

### REWRAP

Re-wrap a blob's DEK under the current Cipher key version. The blob ciphertext is not re-encrypted — only the key wrapping changes.

```
REWRAP <id>
```

**Response:**

```json
{
  "status": "ok",
  "id": "my-doc",
  "key_version": 2,
  "updated_at": 1700000000000
}
```

**Errors:**

| Code | Condition |
|------|-----------|
| `NOTFOUND` | Blob does not exist |
| `SHREDDED` | Blob has been crypto-shredded |
| `CIPHER_UNAVAILABLE` | Cipher engine not available |
| `DENIED` | ABAC policy denied the operation |

### FINGERPRINT

Create a viewer-specific encrypted copy of a blob for leak tracing.

```
FINGERPRINT <id> <viewer_id> [PARAMS <json>]
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `id` | yes | Blob identifier |
| `viewer_id` | yes | Viewer identifier for the fingerprinted copy |
| `PARAMS` | no | JSON string of fingerprint parameters passed to the processor |

**Response:**

```json
{
  "status": "ok",
  "viewer_id": "viewer-1",
  "s3_key": "stash/my-doc/viewers/viewer-1",
  "created_at": 1700000000000
}
```

**Errors:**

| Code | Condition |
|------|-----------|
| `NOTFOUND` | Blob does not exist |
| `REVOKED` | Blob has been soft-revoked |
| `SHREDDED` | Blob has been crypto-shredded |
| `DUPLICATE_VIEWER` | Viewer already has a fingerprinted copy |
| `CLIENT_ENCRYPTED` | Cannot fingerprint a client-encrypted blob |
| `CIPHER_UNAVAILABLE` | Cipher engine not available |
| `DENIED` | ABAC policy denied the operation |

### TRACE

Return the viewer map (who has fingerprinted copies) for a blob.

```
TRACE <id>
```

**Response:**

```json
{
  "status": "ok",
  "id": "my-doc",
  "blob_status": "active",
  "viewer_count": 2,
  "viewers": [
    { "viewer_id": "viewer-a", "s3_key": "…", "created_at": 1700000000000 },
    { "viewer_id": "viewer-b", "s3_key": "…", "created_at": 1700000000000 }
  ]
}
```

**Errors:**

| Code | Condition |
|------|-----------|
| `NOTFOUND` | Blob does not exist |
| `DENIED` | ABAC policy denied the operation |

### LIST

List blobs for the current tenant.

```
LIST [LIMIT <n>]
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `LIMIT` | no | Maximum number of blobs to return (default: 100) |

**Response:**

```json
{
  "status": "ok",
  "tenant": "my-tenant",
  "count": 2,
  "blobs": [ … ]
}
```

**Errors:**

| Code | Condition |
|------|-----------|
| `DENIED` | ABAC policy denied the operation |

### HEALTH

```
HEALTH
→ { "status": "ok" }
```

### PING

```
PING
→ "PONG"
```

### COMMAND

```
COMMAND
→ {
    "count": 12,
    "commands": [
      "AUTH", "STORE", "RETRIEVE", "INSPECT", "REWRAP",
      "REVOKE", "FINGERPRINT", "TRACE", "LIST",
      "HEALTH", "PING", "COMMAND LIST"
    ]
  }
```

## ACL Requirements

| Command | Requirement | Scope |
|---------|------------|-------|
| AUTH, HEALTH, PING, COMMAND | None | Public |
| STORE | Namespace `stash.<id>` | Write |
| RETRIEVE | Namespace `stash.<id>` | Read |
| INSPECT | Namespace `stash.<id>` | Read |
| REWRAP | Namespace `stash.<id>` | Write |
| REVOKE | Namespace `stash.<id>` | Write |
| FINGERPRINT | Namespace `stash.<id>` | Write |
| TRACE | Namespace `stash.<id>` | Read |
| LIST | Namespace `stash.*` | Read |

## Encryption Details

### Blob Encryption

- Algorithm: AES-256-GCM
- Nonce: Random 96-bit (12 bytes), generated per blob via ring CSPRNG
- Output format: `nonce (12 bytes) || ciphertext || tag (16 bytes)`
- Overhead: 28 bytes per blob

### Key Management

- DEK generated by Cipher's `GENERATE_DATA_KEY` (256-bit)
- DEK wrapped in a `CiphertextEnvelope` by Cipher's active keyring key
- Wrapped DEK stored in metadata as base64
- On RETRIEVE: wrapped DEK decrypted by Cipher, plaintext DEK used for blob decryption
- Plaintext DEK held in `SensitiveBytes` (zeroized on drop via `zeroize` crate)

### Crypto-Shredding

Hard revoke destroys the wrapped DEK by clearing it from metadata. Without the DEK, the AES-256-GCM ciphertext in S3 is computationally unrecoverable. S3 objects are also deleted as a defense-in-depth measure, but the key destruction alone is sufficient for data destruction.

## Moat Configuration

```toml
[engines.stash]
enabled = true
bucket = "my-encrypted-blobs"          # S3 bucket name (required)
region = "us-east-1"                   # AWS region (default: us-east-1)
endpoint = "https://minio:9000"        # Custom S3-compatible endpoint (optional)
keyring = "stash-blobs"                # Cipher keyring name (default: stash-blobs)
s3_key_prefix = "stash/"              # S3 key prefix (optional)
```

### S3 Credentials

Stash uses the standard AWS credential chain:
1. Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
2. AWS config files (`~/.aws/credentials`)
3. Instance profile (EC2/ECS/EKS)
4. Container credentials (ECS task role)

For S3-compatible services (MinIO, R2), set the `endpoint` and configure credentials via environment variables.
