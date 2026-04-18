# TODOS

## Debt

Each item below is captured as a FAILING test in this repo. The test is the forcing function — this file only indexes them. When a test goes green, check its item off or delete the entry.

Rules:
- Do NOT `#[ignore]` a debt test to make CI pass.
- A visible ratchet (`#[ignore = "DEBT-X: <reason>"]`) requires a matching line in this file AND a clear reason on the attribute. Use sparingly.
- `cargo test -p shroudb-stash-engine debt_` is the live punch list.

### CRITICAL

**DEBT-1** is a live security violation: with the production default (`Capabilities::default()` → cipher=None), STORE uploads **raw plaintext to S3**. Fix-closed and fix first.

### Cross-cutting root causes

1. **`Capabilities::default()` leaves cipher, sentry, chronicle all None.** `main.rs:113` uses this default. Engine has no config surface to populate them.
2. **Fail-open on every security capability when absent.** `check_policy` returns `Ok(())` unconditionally when sentry=None. `store_blob` uploads plaintext when cipher=None. `emit_audit` logs-and-continues on Chronicle failure.
3. **Empty-DEK retrieve path returns raw bytes.** Combined with #1, an attacker who forces cipher-outage during STORE can later retrieve with no authenticated decrypt.

### Open

- [x] **DEBT-1 (CRITICAL)** — STORE without cipher must fail-closed, not upload plaintext. Test: `debt_1_store_without_cipher_must_fail_closed` @ `shroudb-stash-engine/src/engine.rs`.
- [x] **DEBT-2** — RETRIEVE without Sentry must fail-closed, not permit. Test: `debt_2_retrieve_without_sentry_must_fail_closed` @ same file.
- [x] **DEBT-3** — audit failure must propagate to caller (currently logged and ignored). Test: `debt_3_audit_failure_must_propagate_to_caller` @ same file.
- [x] **DEBT-4** — hard-revoke must propagate S3 delete failure (currently marks Shredded but ciphertext survives). Test: `debt_4_hard_revoke_must_propagate_s3_delete_failure` @ same file.
- [x] **DEBT-5** — empty-`wrapped_dek` retrieve path must fail-closed, not return raw bytes. Test: `debt_5_retrieve_raw_blob_must_fail_closed` @ same file.
- [x] **DEBT-6** — legacy-AAD decrypt must emit a distinct audit event (currently silent `tracing::warn!` with no Chronicle record). Test: `debt_6_legacy_aad_decrypt_must_emit_distinct_audit_event` @ same file.
- [ ] **F-stash-8 (L)** — `dispatch.rs:39` — when `auth_context` is None, tenant silently defaults to `"default"`. Combined with DEBT-2, unauthenticated caller lands on tenant `"default"` with no checks. *No debt test yet; add one before fixing.*
