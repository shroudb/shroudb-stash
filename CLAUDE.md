# Stash

Encrypted blob storage engine for ShrouDB.

## Identity

Stash is an **encrypted blob storage engine** backed by S3-compatible object stores. Applications store blobs through Stash; Stash encrypts them via Cipher's envelope encryption and uploads the ciphertext to S3. Metadata (wrapped data encryption keys, S3 locations, revocation status) lives in the ShrouDB Store. The application never handles raw encryption keys.

ShrouDB is **not Redis**. It uses RESP3 as a wire protocol because RESP3 is efficient binary framing — not because ShrouDB is related to Redis in any way.

## Security posture

ShrouDB is security infrastructure. Every change must be evaluated through a security lens:

- **Fail closed, not open.** When in doubt, deny access, reject the request, or return an error. Never default to permissive behavior for convenience.
- **No plaintext at rest.** All blobs are encrypted before upload to S3. Data encryption keys are wrapped by Cipher and only unwrapped transiently for encrypt/decrypt operations.
- **Minimize exposure windows.** Plaintext DEKs are held in `SensitiveBytes` (zeroized on drop). Plaintext blob data should not persist in memory longer than necessary.
- **Cryptographic choices are not negotiable.** AES-256-GCM with random nonces for blob encryption. Key wrapping delegated to Cipher. No shortcuts.
- **Every shortcut is a vulnerability.** Skipping validation, hardcoding credentials, disabling TLS for testing, using `unsafe` without justification, suppressing security-relevant warnings — these are not acceptable trade-offs regardless of time pressure.
- **Audit surface changes require scrutiny.** Any change that modifies encryption, key handling, S3 access, or authorization must be reviewed with the assumption that an attacker will examine it.

## Pre-push checklist (mandatory — no exceptions)

Every check below **must** pass locally before pushing to any branch.

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

### Rules

1. **Run all checks before every push.** No shortcuts, no "I'll fix it in the next commit."
2. **Pre-existing issues must be fixed.** If any check reveals warnings, formatting drift, or any other issue — even if you didn't introduce it — fix it in the same changeset.
3. **Never suppress or bypass checks.** Do not add `#[allow(...)]` to silence clippy, do not push with known failures.
4. **Warnings are errors.** `RUSTFLAGS="-D warnings"` is set in CI. Clippy runs with `-D warnings`.
5. **Documentation must stay in sync.** Any change that affects commands, config keys, public API, or user-facing behavior **must** include corresponding updates to docs in the same changeset.
6. **`protocol.toml` must stay in sync.** Any change to commands, parameters, response fields, or error codes **must** include a corresponding update to `protocol.toml` in the same changeset.
7. **Cross-repo impact must be addressed.** If a change affects shared types, protocols, or APIs consumed by other ShrouDB repos, update those downstream repos in the same effort.

## Architecture

```
shroudb-stash-core/        — domain types (BlobMetadata, BlobStatus, StashError, ViewerRecord)
shroudb-stash-engine/      — Store + ObjectStore logic (StashEngine, capabilities, local crypto)
shroudb-stash-protocol/    — RESP3 command parsing + dispatch (Moat integration path)
```

### Storage model

- **Blobs** → S3-compatible object store (encrypted with AES-256-GCM using a random DEK)
- **Metadata** → ShrouDB Store (`stash.meta` namespace: wrapped DEK, S3 key, status, timestamps)
- **Viewer maps** → ShrouDB Store (`stash.viewers` namespace: viewer→S3 key mappings for FINGERPRINT)

### Encryption model

Stash uses Cipher's **envelope encryption** pattern:

1. STORE: Cipher generates a random DEK (`GENERATE_DATA_KEY`), Stash encrypts the blob locally with AES-256-GCM, uploads ciphertext to S3, stores the Cipher-wrapped DEK in metadata.
2. RETRIEVE: Stash loads the wrapped DEK from metadata, Cipher unwraps it (DECRYPT), Stash decrypts the blob locally, returns plaintext.
3. Client-encrypted mode: When `--client-encrypted` is set, Stash stores the blob as-is (passthrough). The client provides the wrapped DEK and is responsible for encryption/decryption.

### Revocation model

- **Hard revoke (default):** Crypto-shred — destroy the wrapped DEK, delete S3 objects (master + all viewer copies), tombstone metadata. Data is unrecoverable.
- **Soft revoke:** Mark as revoked in metadata. Sentry denies future RETRIEVE requests. Blobs and DEKs preserved for legal/forensic holds.

## Dependencies

- **Upstream:** commons (shroudb-store, shroudb-acl, shroudb-crypto, shroudb-chronicle-core), aws-sdk-s3
- **Downstream:** shroudb-moat (embeds engine + protocol)
- **Capability deps:** Cipher (envelope encryption), Sentry (ABAC policy gating), Chronicle (audit events)

## No dated audit markdown files

Audit findings live in two places:
1. Failing tests named `debt_<n>_<what>_must_<expected>` (hard ratchet — no `#[ignore]`).
2. This repo's `TODOS.md`, indexing the debt tests by ID.

Do NOT create:
- `ENGINE_REVIEW*.md`, `*_REVIEW*.md`, `AUDIT_*.md`, `REVIEW_*.md`
- Any dated snapshot (`*_2026-*.md`, etc.)
- Status / progress / summary markdown that ages out of date

Past audits accumulated 17+ `ENGINE_REVIEW_v*.md` files claiming "zero open items, production-ready" while real gaps went unfixed. New agents read them as truth. They were all deleted 2026-04-17. The forcing function now is `cargo test -p <crate> debt_` — the tests are the source, `TODOS.md` is the index, and nothing else counts.
