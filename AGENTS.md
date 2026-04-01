# Stash — Agent Instructions

> Encrypted blob storage engine: stores blobs in S3-compatible backends with envelope encryption via Cipher, metadata tracking, access gating, and crypto-shred revocation.

## Quick Context

- **Role in ecosystem**: Binary large object storage — Stash handles files, images, documents; other engines handle structured data
- **Deployment modes**: embedded | remote (TCP port 6699)
- **Wire protocol**: RESP3
- **Backing store**: ShrouDB Store trait (metadata) + S3-compatible object store (encrypted blobs)
- **Cipher dependency**: optional — when absent, Stash operates as a raw (unencrypted) passthrough to S3

## Workspace Layout

```
shroudb-stash-core/       # Domain types: BlobMetadata, BlobStatus, StashError, ViewerRecord
shroudb-stash-engine/     # Store + ObjectStore logic, AES-256-GCM blob encryption, capabilities
shroudb-stash-protocol/   # RESP3 command parsing + dispatch
shroudb-stash-server/     # Standalone TCP binary
shroudb-stash-client/     # Typed Rust SDK
shroudb-stash-cli/        # CLI tool
```

## RESP3 Commands

### Blob Operations

| Command | Args | Returns | Description |
|---------|------|---------|-------------|
| `STORE` | `<id> <data_b64> [KEYRING <name>] [CONTENT_TYPE <mime>] [CLIENT_ENCRYPTED <wrapped_dek>]` | `{status, id, s3_key, keyring, key_version, plaintext_size, encrypted_size, client_encrypted}` | Encrypt and upload blob to S3 |
| `RETRIEVE` | `<id>` | `[metadata_json, blob_bytes]` | Download and decrypt blob (RESP3 Array) |
| `INSPECT` | `<id>` | `{status, id, blob_status, content_type, plaintext_size, encrypted_size, keyring, key_version, client_encrypted, viewer_count, created_at, updated_at}` | Metadata-only read (no S3, no Cipher) |
| `REVOKE` | `<id> [SOFT]` | `{status, id, revoke_mode}` | Hard (crypto-shred, default) or soft revoke |

### Operational

| Command | Args | Returns | Description |
|---------|------|---------|-------------|
| `AUTH` | `<token>` | `{status}` | Authenticate connection |
| `HEALTH` | — | `{status}` | Health check |
| `PING` | — | `PONG` | Liveness |
| `COMMAND` | — | `{count, commands}` | List commands |

### Command Examples

```
> STORE my-doc SGVsbG8gV29ybGQ= CONTENT_TYPE application/pdf
{"status":"ok","id":"my-doc","s3_key":"my-doc","keyring":"stash-blobs","key_version":1,"plaintext_size":11,"encrypted_size":39,"client_encrypted":false}

> RETRIEVE my-doc
[{"status":"ok","id":"my-doc","content_type":"application/pdf","plaintext_size":11,"client_encrypted":false}, <raw_bytes>]

> INSPECT my-doc
{"status":"ok","id":"my-doc","blob_status":"active","content_type":"application/pdf","plaintext_size":11,"encrypted_size":39,"keyring":"stash-blobs","key_version":1,"client_encrypted":false,"viewer_count":0,"created_at":1700000000000,"updated_at":1700000000000}

> REVOKE my-doc
{"status":"ok","id":"my-doc","revoke_mode":"hard"}
```

## Public API (Embedded Mode)

### Core Types

```rust
pub enum BlobStatus { Active, Revoked, Shredded }
pub struct BlobMetadata { pub id: String, pub s3_key: String, pub wrapped_dek: String, pub keyring: String, pub key_version: u32, pub content_type: Option<String>, pub plaintext_size: u64, pub encrypted_size: u64, pub client_encrypted: bool, pub status: BlobStatus, pub created_at: u64, pub updated_at: u64 }
pub struct ViewerRecord { pub viewer_id: String, pub s3_key: String, pub wrapped_dek: String, pub fingerprint_params: serde_json::Value, pub created_at: u64 }  // forensic watermark copy, not deduplication
pub struct ViewerMap { pub viewers: Vec<ViewerRecord> }
pub struct InspectResult { /* fields from BlobMetadata + viewer_count */ }
pub struct RetrieveResult { pub data: Vec<u8>, pub metadata: BlobMetadata, pub wrapped_dek: Option<String> }
```

### Capability Traits

```rust
pub trait StashCipherOps: Send + Sync {
    fn generate_data_key(&self, bits: Option<u32>) -> BoxFut<'_, DataKeyPair>;
    fn unwrap_data_key(&self, wrapped_key: &str) -> BoxFut<'_, SensitiveBytes>;
}

pub struct Capabilities {
    pub cipher: Option<Box<dyn StashCipherOps>>,
    pub sentry: Option<Arc<dyn PolicyEvaluator>>,
    pub chronicle: Option<Arc<dyn ChronicleOps>>,
}
```

### Usage Pattern

```rust
use shroudb_stash_engine::{StashEngine, StashConfig, StoreBlobParams, Capabilities};

let config = StashConfig { default_keyring: "stash-blobs".into(), s3_key_prefix: None };
let engine = StashEngine::new(store, object_store, capabilities, config).await?;

let meta = engine.store_blob(StoreBlobParams {
    id: "doc-1", data: &bytes, content_type: Some("application/pdf"),
    keyring: None, client_encrypted: false, wrapped_dek: None, actor: None,
}).await?;

let result = engine.retrieve_blob("doc-1", None).await?;
```

## Encryption Model

### Server-side (Cipher available)

```
STORE: Cipher.GENERATE_DATA_KEY → plaintext DEK + wrapped DEK
       AES-256-GCM(DEK, blob) → ciphertext (nonce || ct || tag, 28 bytes overhead)
       S3.PUT(ciphertext)
       Store.PUT(wrapped_dek, s3_key, metadata)
       zeroize(DEK)

RETRIEVE: Store.GET(metadata) → wrapped_dek
          S3.GET(ciphertext)
          Cipher.DECRYPT(wrapped_dek) → DEK
          AES-256-GCM_OPEN(DEK, ciphertext) → plaintext
          zeroize(DEK)
```

### Raw passthrough (Cipher absent)

When Cipher is not available, Stash stores blobs without encryption. Data is uploaded to S3 as-is. Metadata is still tracked. Access control (Sentry) and audit (Chronicle) still apply.

### Client-encrypted passthrough

When `CLIENT_ENCRYPTED <wrapped_dek>` is set, the client has already encrypted the data. Stash stores the ciphertext and wrapped DEK in metadata. RETRIEVE returns raw ciphertext + wrapped DEK for client-side decryption.

## Revocation Model

| Mode | Behavior |
|------|----------|
| **Hard (default)** | Crypto-shred: clear wrapped DEK from metadata, delete S3 object (master + all viewer copies), set status=shredded. Ciphertext becomes unrecoverable. |
| **Soft** | Set status=revoked. Sentry denies future RETRIEVE. All data preserved for legal/forensic holds. |

## Configuration

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `server.tcp_bind` | `SocketAddr` | `"0.0.0.0:6699"` | TCP listen address |
| `store.mode` | `String` | `"embedded"` | Storage mode |
| `store.data_dir` | `PathBuf` | `"./stash-data"` | Data directory |
| `engine.bucket` | `String` | — | S3 bucket name (required) |
| `engine.region` | `String` | `"us-east-1"` | AWS region |
| `engine.endpoint` | `Option<String>` | `None` | Custom S3 endpoint (MinIO, R2) |
| `engine.keyring` | `String` | `"stash-blobs"` | Cipher keyring name |
| `engine.s3_key_prefix` | `Option<String>` | `None` | S3 key prefix |
| `auth.method` | `Option<String>` | `None` | `"token"` to enable auth |

## Data Model

- **Metadata namespace**: `stash.meta` — blob metadata (JSON-serialized `BlobMetadata`)
- **Viewer namespace**: `stash.viewers` — viewer maps (JSON-serialized `ViewerMap`)
- **S3 objects**: encrypted blobs keyed by blob ID (with optional prefix)

### Object Store Trait

```rust
pub trait ObjectStore: Send + Sync {
    fn put(&self, key: &str, data: &[u8], content_type: Option<&str>) -> BoxFut<'_, ()>;
    fn get(&self, key: &str) -> BoxFut<'_, Vec<u8>>;
    fn delete(&self, key: &str) -> BoxFut<'_, ()>;
    fn head(&self, key: &str) -> BoxFut<'_, ObjectMeta>;
}
```

Implementations: `S3ObjectStore` (production, `aws-sdk-s3`), `InMemoryObjectStore` (testing).

## ACL Requirements

| Command | Requirement | Scope |
|---------|------------|-------|
| AUTH, HEALTH, PING, COMMAND | None | Public |
| STORE, REVOKE | Namespace `stash.<id>` | Write |
| RETRIEVE, INSPECT | Namespace `stash.<id>` | Read |

## Integration Patterns

Stash is used by applications for encrypted file/blob storage:

- **Moat**: Feature-gated (`stash`), initialized after Cipher + Sentry + Chronicle. Cipher auto-seeds `stash-blobs` keyring.
- **Cipher**: Provides `StashCipherOps` via `EmbeddedStashCipherOps` adapter (calls `generate_data_key` and `decrypt`). Optional — Stash degrades gracefully to raw passthrough without Cipher.
- **Sentry**: Provides `PolicyEvaluator` for ABAC gating on all operations.
- **Chronicle**: Receives audit events for STORE, RETRIEVE, INSPECT, REVOKE_SOFT, REVOKE_HARD.

## Common Mistakes

- Stash does NOT require Cipher — when Cipher is absent, blobs are stored unencrypted. This is a valid mode for metadata-tracked S3 access with ACL enforcement, but data is not encrypted at rest.
- RETRIEVE returns a RESP3 **Array** (not a single BulkString like other engines). The array contains `[metadata_json, blob_bytes]`. Client libraries must handle this format.
- Hard revoke is irreversible. The wrapped DEK is destroyed — even if the S3 delete fails, the ciphertext is unrecoverable.
- `CLIENT_ENCRYPTED` mode stores blob as-is. Stash cannot verify the integrity of client-encrypted data.
- The `ViewerMap` structure exists for v0.2 forensic FINGERPRINT functionality (per-viewer watermarking for leak tracing, not deduplication). In v0.1, viewer maps are always empty.

## Planned (v0.2)

| Command | Description |
|---------|-------------|
| `TRACE <id>` | Query access history + forensic fingerprint records from Chronicle/metadata |
| `FINGERPRINT <id> --viewer <viewer_id>` | Forensic watermarking: decrypt blob, dispatch to remote processor to embed a per-viewer watermark, re-encrypt as a viewer-specific copy. Used to trace leaked files back to the viewer who received them — not deduplication. |

## Related Crates

| Crate | Relationship |
|-------|-------------|
| `shroudb-store` | Provides Store trait for metadata persistence |
| `shroudb-cipher-engine` | Provides `generate_data_key` and `decrypt` for envelope encryption |
| `shroudb-acl` | Provides ACL types and PolicyEvaluator trait |
| `shroudb-chronicle-core` | Provides ChronicleOps trait for audit event ingestion |
| `aws-sdk-s3` | S3-compatible object storage client |
