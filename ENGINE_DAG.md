# Stash Engine DAG

## Overview

Stash is ShrouDB's encrypted blob storage engine. It sits between applications and any S3-compatible object store (AWS S3, MinIO, Cloudflare R2) and applies envelope encryption locally before the blob touches the bucket: a per-blob AES-256-GCM data encryption key (DEK) is generated via Cipher, the blob is encrypted in the Stash process, the ciphertext is uploaded to S3, and the Cipher-wrapped DEK is persisted in the ShrouDB Store alongside the object's metadata. Blob identity is tracked by tenant-scoped SHA-256 plaintext fingerprints for content-addressed deduplication, and viewer-specific copies are indexed in a per-blob viewer map so fingerprinted copies can be traced and cascaded on revoke. Revocation is crypto-shred by default — the wrapped DEK is destroyed, all S3 objects (master plus viewer copies) are deleted, and the metadata is tombstoned — with an opt-in soft revoke that preserves ciphertext and DEK for legal or forensic holds.

## Crate dependency DAG

```
                        shroudb-stash-cli
                               |
                               v
                      shroudb-stash-client
                               (TCP / RESP3)
                               ^
                               |
                      shroudb-stash-server  (bin: shroudb-stash)
                               |
              +----------------+----------------+
              |                                 |
              v                                 v
    shroudb-stash-protocol              shroudb-stash-engine
              |                                 |
              +----------------+----------------+
                               |
                               v
                      shroudb-stash-core
```

Internal crates (all at workspace version 0.6.1):

- `shroudb-stash-core` — domain types: `BlobMetadata`, `BlobStatus` (Active/Revoked/Shredded), `ViewerMap`, `ViewerRecord`, `StashError`. No engine deps (only `serde`, `serde_json`, `thiserror`).
- `shroudb-stash-engine` — `StashEngine`, `StashConfig`, `Capabilities`, `StashCipherOps` trait, `ObjectStore` trait, `S3ObjectStore` (behind default `s3` feature), local AES-256-GCM crypto, dedup records, viewer maps. Pins commons crates `shroudb-acl`, `shroudb-audit`, `shroudb-chronicle-core`, `shroudb-crypto`, `shroudb-store`, and `shroudb-server-bootstrap` (for the `Capability<T>` tri-state). Does not pin any sibling engine's crate.
- `shroudb-stash-protocol` — RESP3 command parsing and dispatch over `shroudb-protocol-wire`.
- `shroudb-stash-server` — TCP server binary, config loader, S3 bootstrapping, token-auth wiring, audit/policy capability resolution via `shroudb-engine-bootstrap`. Pins `shroudb-cipher-engine`, `shroudb-cipher-core`, and `shroudb-cipher-client` to offer an in-process embedded Cipher option and a (stubbed) remote Cipher path directly from the standalone binary — the engine crate itself stays cipher-crate-free.
- `shroudb-stash-client` — async Rust client SDK (RESP3 over TCP).
- `shroudb-stash-cli` — command-line wrapper around the client.

## Capabilities

- Envelope encryption: per-blob AES-256-GCM with 96-bit random nonces, DEK wrapped by Cipher.
- Client-encrypted passthrough: accepts pre-encrypted blobs with a client-supplied wrapped DEK; validates base64 and minimum sizes (wrapped DEK >= 32 bytes, ciphertext >= 28 bytes for nonce + tag) when `validate_client_encrypted` is on.
- Chunked streaming encryption above `streaming_threshold_bytes` (default 10 MB) to bound memory.
- AAD binding: blob ID is used as additional authenticated data on encrypt; a legacy compat path handles blobs stored before AAD binding and warns.
- Content-addressed deduplication: tenant-scoped SHA-256 of plaintext; duplicate STOREs become metadata-only references sharing the canonical S3 object, DEK, and keyring, tracked by a reference count in `stash.dedup`.
- Metadata-only INSPECT: reads size, status, content type, keyring, key version, viewer count without any S3 or Cipher interaction.
- REWRAP: re-wraps a blob's DEK under the current Cipher key version without re-encrypting the ciphertext.
- FINGERPRINT / TRACE: per-viewer encrypted copies with a viewer map indexed in `stash.viewers`.
- Hard revoke (crypto-shred): destroys the wrapped DEK, deletes master and cascading viewer copies, decrements dedup reference counts, deletes the S3 object only when the canonical and all references are shredded.
- Soft revoke: flips status to `Revoked`, preserves ciphertext and DEK for legal holds; RETRIEVE is denied.
- Fail-closed tenant isolation: metadata mismatch returns `NotFound` to avoid existence leaks.
- Pluggable object store: `ObjectStore` trait; the default `S3ObjectStore` covers AWS S3 and any S3-compatible endpoint.
- Store modes: embedded (local `shroudb-storage`) or remote (`shroudb-client::RemoteStore`).
- Namespaces auto-created on engine startup: `stash.meta`, `stash.viewers`, `stash.dedup`.

## Engine dependencies

The Stash **engine** crate (`shroudb-stash-engine`) does not pin any sibling engine's crate. Capabilities for Cipher, Sentry, and Chronicle are supplied through trait objects on the `Capabilities` struct at engine construction time. The engine-facing *commons* crates it pins are `shroudb-chronicle-core` (for `ChronicleOps` and event types), `shroudb-acl` (for `PolicyEvaluator`), `shroudb-audit`, `shroudb-crypto` (for `SensitiveBytes`), and `shroudb-store`. Cipher has no commons crate in this workspace — it is consumed purely through the local `StashCipherOps` trait defined in `shroudb-stash-engine::capabilities`.

The standalone **server** crate (`shroudb-stash-server`) is the only place that pins Cipher's crates (`shroudb-cipher-engine`, `shroudb-cipher-core`, `shroudb-cipher-client`), and it does so only to construct an embedded `CipherEngine` (or a remote client, pending) behind the `[cipher]` config section. This keeps the engine crate cipher-crate-free while giving the standalone binary an out-of-the-box envelope-encryption option without needing Moat.

Each slot is a `Capability<T>` tri-state (from commons crate `shroudb-server-bootstrap`): `Enabled(T)`, `DisabledForTests`, or `DisabledWithJustification(reason)`. Absence is never silent — binaries must pick a variant explicitly, and disabled slots surface a justification string at startup.

### Dependency: Cipher

- **Integration shape**: `StashCipherOps` trait in `shroudb-stash-engine::capabilities` (methods: `generate_data_key`, `unwrap_data_key`, `rewrap_data_key`). Injected via `Capabilities::cipher: Capability<Box<dyn StashCipherOps>>`. No crate pin in the engine crate. In the standalone server, the slot is resolved from the optional `[cipher]` config block: `mode = "embedded"` wires an in-process `CipherEngine` (from `shroudb-cipher-engine`) that shares the Stash `StorageEngine` under a separate `cipher` namespace; `mode = "remote"` is a validated config path that currently bails at startup pending wiring; an absent section resolves to `DisabledWithJustification`.
- **What breaks without it**: REWRAP fails with `CipherUnavailable`. RETRIEVE of server-encrypted blobs (non-empty `wrapped_dek`, `client_encrypted=false`) fails with `CipherUnavailable`. New STOREs succeed but degrade to unencrypted passthrough — the blob is uploaded to S3 as-is, metadata records an empty `wrapped_dek` and `key_version=0`, and a warning is logged. Client-encrypted STORE and RETRIEVE still work end-to-end. INSPECT, LIST, FINGERPRINT metadata ops, TRACE, and soft revoke do not touch Cipher and are unaffected.
- **What works with it**: Full envelope encryption — Cipher generates a 256-bit DEK, Stash encrypts locally with AES-256-GCM (chunked above 10 MB), uploads ciphertext to S3, and stores the wrapped DEK. RETRIEVE unwraps the DEK and decrypts locally. REWRAP rotates DEKs under a new Cipher key version without touching S3. Hard revoke crypto-shreds by destroying the wrapped DEK.

### Dependency: Sentry

- **Integration shape**: `shroudb_acl::PolicyEvaluator` trait (from commons crate `shroudb-acl`). Injected via `Capabilities::sentry: Capability<Arc<dyn PolicyEvaluator>>`. No Sentry crate pin. In the standalone server, the slot is resolved from the `[policy]` config block by `shroudb-engine-bootstrap` (`remote` | `embedded` | `disabled`); a missing `[policy]` section defaults to `embedded` on the shared `StorageEngine`.
- **What breaks without it**: ABAC policy checks are skipped. STORE, RETRIEVE, INSPECT, REWRAP, and REVOKE proceed on authenticated connections without resource-level authorization, relying only on connection-layer token auth and tenant isolation.
- **What works with it**: Every operation calls `check_policy` against the injected evaluator with namespaced resources (`stash.<id>`) and action-specific principals. Denied requests return `StashError::Denied` and an audit event is emitted with `EventResult::Denied`.

### Dependency: Chronicle

- **Integration shape**: `shroudb_chronicle_core::ops::ChronicleOps` trait and `shroudb_chronicle_core::event::{Engine, Event, EventResult}` (from pinned crate `shroudb-chronicle-core`). Injected via `Capabilities::chronicle: Capability<Arc<dyn ChronicleOps>>`. In the standalone server, the slot is resolved from the `[audit]` config block by `shroudb-engine-bootstrap` (`remote` | `embedded` | `disabled`); a missing `[audit]` section defaults to `embedded` on the shared `StorageEngine`.
- **What breaks without it**: No audit trail. STORE, RETRIEVE, INSPECT, REWRAP, REVOKE_SOFT, and REVOKE_HARD still succeed, but `emit_audit` becomes a no-op — nothing is recorded for regulated-audit replay.
- **What works with it**: Every command that mutates state or accesses a blob emits a Chronicle event tagged `Engine::Stash` with the action, tenant, blob id, and `EventResult::Ok` or `EventResult::Denied`.

## Reverse dependencies

- `shroudb-moat` pins `shroudb-stash-protocol`, `shroudb-stash-engine`, and `shroudb-stash-core` behind its `stash` feature. The moat feature definition is `stash = [..., "cipher"]`, so enabling Stash in Moat also enables Cipher in the same process, which is what provides a concrete `StashCipherOps` implementation in the embedded deployment.
- `shroudb-stash-cli` consumes `shroudb-stash-client` for command-line operations.
- Application code consumes `shroudb-stash-client` directly over TCP/RESP3 for standalone deployments.

## Deployment modes

**Standalone (`shroudb-stash` binary, crate `shroudb-stash-server`)**
- Single-engine process exposing RESP3 over TCP (optional TLS via `tokio-rustls`).
- `main.rs` builds `Capabilities` explicitly: `sentry` and `chronicle` are resolved from the `[policy]` and `[audit]` config blocks via `shroudb-engine-bootstrap`. Both blocks are optional — a missing section defaults to `mode = "embedded"` on the shared `StorageEngine` (engine-bootstrap 0.3.0 behaviour); embedded init failures still surface at startup. `cipher` is resolved from the optional `[cipher]` config block: `mode = "embedded"` spawns an in-process `CipherEngine` on the same `StorageEngine` as Stash's metadata (distinct namespace), seeds the configured keyring, starts the rotation scheduler, and wires an `EmbeddedStashCipherOps` adapter; `mode = "remote"` is config-validated but not yet plumbed and fails startup with a clear message; an absent `[cipher]` section resolves to `Capability::DisabledWithJustification`, in which case server-side STORE degrades to unencrypted passthrough (with a warning) and server-side RETRIEVE fails-closed with `CipherUnavailable`.
- Store backend selectable per `store.mode` config: `embedded` (local RocksDB via `shroudb-storage`) or `remote` (`shroudb-client::RemoteStore` over TCP). Embedded Cipher requires embedded Store (same `StorageEngine`).
- S3 target is configured by `engine.bucket`, `engine.region`, `engine.endpoint` and is not optional — the engine requires a reachable object store to boot.

**Embedded (inside Moat)**
- `shroudb-moat` compiles Stash's engine and protocol crates into its multi-engine binary under the `stash` feature.
- Moat's `stash` feature forces Cipher to be co-compiled and wires a concrete `StashCipherOps` implementation into `Capabilities::cipher`. Sentry and Chronicle implementations are supplied by Moat's own capability wiring when their features are enabled.
- The same engine code runs in both modes; only the `Capabilities` the binary injects differ.

**External dependency: S3**
S3 (or any S3-compatible endpoint) is not an engine — it is a required external service. The `ObjectStore` trait lets tests substitute in-memory implementations, but every production deployment binds an `S3ObjectStore` built from `aws-sdk-s3`.
