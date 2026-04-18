use shroudb_acl::{AclRequirement, AuthContext};
use shroudb_protocol_wire::WIRE_PROTOCOL;
use shroudb_stash_engine::engine::{StashEngine, StoreBlobParams, StoreResult};
use shroudb_store::Store;

use crate::commands::StashCommand;
use crate::response::StashResponse;

const SUPPORTED_COMMANDS: &[&str] = &[
    "AUTH",
    "STORE",
    "RETRIEVE",
    "INSPECT",
    "REWRAP",
    "REVOKE",
    "FINGERPRINT",
    "TRACE",
    "LIST",
    "HEALTH",
    "PING",
    "COMMAND LIST",
    "HELLO",
];

/// Dispatch a parsed command to the StashEngine and produce a response.
///
/// `auth_context` is the authenticated identity for this connection/request.
/// `None` means the connection has not completed AUTH yet.
///
/// Fail-closed posture for tenant-scoped commands: if `auth_context` is
/// `None`, commands that touch a tenant namespace are refused outright
/// rather than falling back to a synthesised `"default"` tenant. Only
/// the infrastructure commands that carry `AclRequirement::None`
/// (HEALTH / PING / COMMAND LIST / HELLO / AUTH) may proceed without
/// an established identity.
pub async fn dispatch<S: Store>(
    engine: &StashEngine<S>,
    cmd: StashCommand,
    auth_context: Option<&AuthContext>,
) -> StashResponse {
    let requirement = cmd.acl_requirement();

    // Refuse tenant-scoped commands when no auth context has been
    // established. The default-tenant fallback would otherwise let an
    // unauthenticated caller read or mutate whatever blobs live under
    // tenant "default".
    if auth_context.is_none() && !matches!(requirement, AclRequirement::None) {
        return StashResponse::error(
            "access denied: command requires an authenticated context (AUTH first)",
        );
    }

    // Check ACL requirement before dispatch.
    if let Err(e) = shroudb_acl::check_dispatch_acl(auth_context, &requirement) {
        return StashResponse::error(e);
    }

    let tenant = auth_context.map(|c| c.tenant.as_str()).unwrap_or("default");
    let actor = auth_context.map(|c| c.actor.as_str());

    match cmd {
        StashCommand::Auth { .. } => StashResponse::error("AUTH handled at connection layer"),

        // ── STORE ─────────────────────────────────────────────────────
        StashCommand::Store {
            id,
            data,
            keyring,
            content_type,
            client_encrypted,
            wrapped_dek,
        } => {
            match engine
                .store_blob(StoreBlobParams {
                    tenant,
                    id: &id,
                    data: &data,
                    content_type: content_type.as_deref(),
                    keyring: keyring.as_deref(),
                    client_encrypted,
                    wrapped_dek: wrapped_dek.as_deref(),
                    actor,
                })
                .await
            {
                Ok(StoreResult {
                    metadata: meta,
                    deduplicated,
                }) => StashResponse::ok(serde_json::json!({
                    "status": "ok",
                    "id": meta.id,
                    "s3_key": meta.s3_key,
                    "keyring": meta.keyring,
                    "key_version": meta.key_version,
                    "plaintext_size": meta.plaintext_size,
                    "encrypted_size": meta.encrypted_size,
                    "client_encrypted": meta.client_encrypted,
                    "content_hash": meta.content_hash,
                    "deduplicated": deduplicated,
                })),
                Err(e) => StashResponse::error(e.to_string()),
            }
        }

        // ── RETRIEVE ──────────────────────────────────────────────────
        StashCommand::Retrieve { id } => match engine.retrieve_blob(tenant, &id, actor).await {
            Ok(result) => {
                let mut meta_json = serde_json::json!({
                    "status": "ok",
                    "id": result.metadata.id,
                    "content_type": result.metadata.content_type,
                    "plaintext_size": result.metadata.plaintext_size,
                    "client_encrypted": result.metadata.client_encrypted,
                });

                // Include wrapped DEK for client-encrypted blobs.
                if let Some(ref dek) = result.wrapped_dek {
                    meta_json["wrapped_dek"] = serde_json::json!(dek);
                }

                StashResponse::blob(meta_json, result.data)
            }
            Err(e) => StashResponse::error(e.to_string()),
        },

        // ── INSPECT ───────────────────────────────────────────────────
        StashCommand::Inspect { id } => match engine.inspect_blob(tenant, &id, actor).await {
            Ok(info) => StashResponse::ok(serde_json::json!({
                "status": "ok",
                "id": info.id,
                "blob_status": info.status,
                "content_type": info.content_type,
                "plaintext_size": info.plaintext_size,
                "encrypted_size": info.encrypted_size,
                "keyring": info.keyring,
                "key_version": info.key_version,
                "client_encrypted": info.client_encrypted,
                "viewer_count": info.viewer_count,
                "created_at": info.created_at,
                "updated_at": info.updated_at,
            })),
            Err(e) => StashResponse::error(e.to_string()),
        },

        // ── REVOKE ────────────────────────────────────────────────────
        StashCommand::Revoke { id, soft } => {
            match engine.revoke_blob(tenant, &id, soft, actor).await {
                Ok(()) => {
                    let mode = if soft { "soft" } else { "hard" };
                    StashResponse::ok(serde_json::json!({
                        "status": "ok",
                        "id": id,
                        "revoke_mode": mode,
                    }))
                }
                Err(e) => StashResponse::error(e.to_string()),
            }
        }

        StashCommand::Rewrap { id } => match engine.rewrap_blob(tenant, &id, actor).await {
            Ok(meta) => StashResponse::ok(serde_json::json!({
                "status": "ok",
                "id": meta.id,
                "key_version": meta.key_version,
                "updated_at": meta.updated_at,
            })),
            Err(e) => StashResponse::error(e.to_string()),
        },

        // ── FINGERPRINT ──────────────────────────────────────────────
        StashCommand::Fingerprint {
            id,
            viewer_id,
            params,
        } => {
            let parsed_params = match params {
                Some(ref json_str) => match serde_json::from_str(json_str) {
                    Ok(v) => Some(v),
                    Err(e) => {
                        return StashResponse::error(format!("invalid PARAMS json: {e}"));
                    }
                },
                None => None,
            };

            match engine
                .fingerprint_blob(tenant, &id, &viewer_id, parsed_params, actor)
                .await
            {
                Ok(record) => StashResponse::ok(serde_json::json!({
                    "status": "ok",
                    "viewer_id": record.viewer_id,
                    "s3_key": record.s3_key,
                    "created_at": record.created_at,
                })),
                Err(e) => StashResponse::error(e.to_string()),
            }
        }

        // ── TRACE ────────────────────────────────────────────────────
        StashCommand::Trace { id } => match engine.trace_blob(tenant, &id, actor).await {
            Ok(result) => {
                let viewers: Vec<serde_json::Value> = result
                    .viewers
                    .iter()
                    .map(|v| {
                        serde_json::json!({
                            "viewer_id": v.viewer_id,
                            "s3_key": v.s3_key,
                            "created_at": v.created_at,
                        })
                    })
                    .collect();

                StashResponse::ok(serde_json::json!({
                    "status": "ok",
                    "id": result.id,
                    "blob_status": result.status,
                    "viewer_count": result.viewer_count,
                    "viewers": viewers,
                }))
            }
            Err(e) => StashResponse::error(e.to_string()),
        },

        // ── LIST ──────────────────────────────────────────────────────
        StashCommand::List { limit } => {
            let lim = limit.unwrap_or(100);
            match engine.list_blobs(tenant, lim, actor).await {
                Ok(blobs) => StashResponse::ok(serde_json::json!({
                    "status": "ok",
                    "tenant": tenant,
                    "count": blobs.len(),
                    "blobs": blobs,
                })),
                Err(e) => StashResponse::error(e.to_string()),
            }
        }

        // ── Operational ───────────────────────────────────────────────
        StashCommand::Health => StashResponse::ok(serde_json::json!({
            "status": "ok",
        })),

        StashCommand::Ping => StashResponse::ok(serde_json::json!("PONG")),

        StashCommand::CommandList => StashResponse::ok(serde_json::json!({
            "count": SUPPORTED_COMMANDS.len(),
            "commands": SUPPORTED_COMMANDS,
        })),

        StashCommand::Hello => StashResponse::ok(serde_json::json!({
            "engine": "stash",
            "version": env!("CARGO_PKG_VERSION"),
            "protocol": WIRE_PROTOCOL,
            "commands": SUPPORTED_COMMANDS,
            "capabilities": Vec::<&str>::new(),
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::parse_command;
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use shroudb_crypto::SensitiveBytes;
    use shroudb_stash_engine::capabilities::{Capabilities, DataKeyPair, StashCipherOps};
    use shroudb_stash_engine::engine::StashConfig;
    use shroudb_stash_engine::object_store::InMemoryObjectStore;
    use std::sync::Arc;

    struct MockCipherOps {
        dek: [u8; 32],
    }

    impl MockCipherOps {
        fn new() -> Self {
            let mut dek = [0u8; 32];
            ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut dek)
                .expect("CSPRNG failed — system entropy source is broken");
            Self { dek }
        }
    }

    impl StashCipherOps for MockCipherOps {
        fn generate_data_key(
            &self,
            _bits: Option<u32>,
        ) -> shroudb_stash_engine::capabilities::BoxFut<'_, DataKeyPair> {
            Box::pin(async move {
                Ok(DataKeyPair {
                    plaintext_key: SensitiveBytes::new(self.dek.to_vec()),
                    wrapped_key: STANDARD.encode(b"mock-wrapped-dek"),
                    key_version: 1,
                })
            })
        }

        fn unwrap_data_key(
            &self,
            _wrapped_key: &str,
        ) -> shroudb_stash_engine::capabilities::BoxFut<'_, SensitiveBytes> {
            Box::pin(async move { Ok(SensitiveBytes::new(self.dek.to_vec())) })
        }

        fn rewrap_data_key(
            &self,
            _old_wrapped_key: &str,
        ) -> shroudb_stash_engine::capabilities::BoxFut<'_, DataKeyPair> {
            Box::pin(async move {
                Ok(DataKeyPair {
                    plaintext_key: SensitiveBytes::new(self.dek.to_vec()),
                    wrapped_key: STANDARD.encode(b"mock-rewrapped-dek"),
                    key_version: 2,
                })
            })
        }
    }

    /// PolicyEvaluator double that always permits — the dispatch layer's
    /// tests exercise protocol wiring, not ABAC policy, so they use this
    /// rather than `Capability::DisabledForTests` (which the engine now
    /// treats as fail-closed).
    struct AllowAllSentry;
    impl shroudb_acl::PolicyEvaluator for AllowAllSentry {
        fn evaluate(
            &self,
            _request: &shroudb_acl::PolicyRequest,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<shroudb_acl::PolicyDecision, shroudb_acl::AclError>,
                    > + Send
                    + '_,
            >,
        > {
            Box::pin(async {
                Ok(shroudb_acl::PolicyDecision {
                    effect: shroudb_acl::PolicyEffect::Permit,
                    matched_policy: Some("test-allow-all".into()),
                    token: None,
                    cache_until: None,
                })
            })
        }
    }

    async fn setup() -> StashEngine<shroudb_storage::EmbeddedStore> {
        let store = shroudb_storage::test_util::create_test_store("stash-proto-test").await;
        let obj_store = Arc::new(InMemoryObjectStore::new());
        let caps = Capabilities {
            cipher: shroudb_server_bootstrap::Capability::Enabled(Box::new(MockCipherOps::new())),
            sentry: shroudb_server_bootstrap::Capability::Enabled(Arc::new(AllowAllSentry)),
            chronicle: shroudb_server_bootstrap::Capability::DisabledForTests,
        };
        StashEngine::new(store, obj_store, caps, StashConfig::default())
            .await
            .unwrap()
    }

    fn test_ctx() -> AuthContext {
        AuthContext::platform("test-tenant", "test-actor")
    }

    #[tokio::test]
    async fn full_store_retrieve_flow() {
        let engine = setup().await;
        let ctx = test_ctx();

        let data_b64 = STANDARD.encode(b"hello stash protocol");
        let cmd =
            parse_command(&["STORE", "proto-1", &data_b64, "CONTENT_TYPE", "text/plain"]).unwrap();
        let resp = dispatch(&engine, cmd, Some(&ctx)).await;
        assert!(resp.is_ok(), "store failed: {resp:?}");

        let cmd = parse_command(&["RETRIEVE", "proto-1"]).unwrap();
        let resp = dispatch(&engine, cmd, Some(&ctx)).await;
        match resp {
            StashResponse::Blob { data, metadata } => {
                assert_eq!(data, b"hello stash protocol");
                assert_eq!(metadata["content_type"], "text/plain");
            }
            other => panic!("expected Blob response, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn store_inspect_revoke_flow() {
        let engine = setup().await;
        let ctx = test_ctx();

        let data_b64 = STANDARD.encode(b"secret");
        let cmd = parse_command(&["STORE", "sir-1", &data_b64]).unwrap();
        let resp = dispatch(&engine, cmd, Some(&ctx)).await;
        assert!(resp.is_ok());

        // Inspect
        let cmd = parse_command(&["INSPECT", "sir-1"]).unwrap();
        let resp = dispatch(&engine, cmd, Some(&ctx)).await;
        assert!(resp.is_ok());
        match &resp {
            StashResponse::Ok(v) => {
                assert_eq!(v["blob_status"], "active");
                assert_eq!(v["plaintext_size"], 6);
            }
            _ => panic!("expected Ok"),
        }

        // Soft revoke
        let cmd = parse_command(&["REVOKE", "sir-1", "SOFT"]).unwrap();
        let resp = dispatch(&engine, cmd, Some(&ctx)).await;
        assert!(resp.is_ok());
        match &resp {
            StashResponse::Ok(v) => assert_eq!(v["revoke_mode"], "soft"),
            _ => panic!("expected Ok"),
        }

        // Retrieve should fail
        let cmd = parse_command(&["RETRIEVE", "sir-1"]).unwrap();
        let resp = dispatch(&engine, cmd, Some(&ctx)).await;
        assert!(!resp.is_ok());
    }

    #[tokio::test]
    async fn hard_revoke_flow() {
        let engine = setup().await;
        let ctx = test_ctx();

        let data_b64 = STANDARD.encode(b"shred-me");
        let cmd = parse_command(&["STORE", "shred-1", &data_b64]).unwrap();
        dispatch(&engine, cmd, Some(&ctx)).await;

        let cmd = parse_command(&["REVOKE", "shred-1"]).unwrap();
        let resp = dispatch(&engine, cmd, Some(&ctx)).await;
        assert!(resp.is_ok());
        match &resp {
            StashResponse::Ok(v) => assert_eq!(v["revoke_mode"], "hard"),
            _ => panic!("expected Ok"),
        }

        // Inspect shows shredded
        let cmd = parse_command(&["INSPECT", "shred-1"]).unwrap();
        let resp = dispatch(&engine, cmd, Some(&ctx)).await;
        match &resp {
            StashResponse::Ok(v) => assert_eq!(v["blob_status"], "shredded"),
            _ => panic!("expected Ok"),
        }
    }

    #[tokio::test]
    async fn health_and_ping() {
        let engine = setup().await;

        let cmd = parse_command(&["HEALTH"]).unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        assert!(resp.is_ok());

        let cmd = parse_command(&["PING"]).unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        assert!(resp.is_ok());
    }

    #[tokio::test]
    async fn retrieve_not_found() {
        let engine = setup().await;
        let ctx = test_ctx();
        let cmd = parse_command(&["RETRIEVE", "nope"]).unwrap();
        let resp = dispatch(&engine, cmd, Some(&ctx)).await;
        assert!(!resp.is_ok());
    }

    #[tokio::test]
    async fn acl_blocks_unauthorized_write() {
        let engine = setup().await;

        let ctx = AuthContext::tenant(
            "t1",
            "read-user",
            vec![shroudb_acl::Grant {
                namespace: "stash.blob-1".into(),
                scopes: vec![shroudb_acl::Scope::Read],
            }],
            None,
        );

        let data_b64 = STANDARD.encode(b"data");
        let cmd = parse_command(&["STORE", "blob-1", &data_b64]).unwrap();
        let resp = dispatch(&engine, cmd, Some(&ctx)).await;
        assert!(!resp.is_ok());
        match resp {
            StashResponse::Error(msg) => assert!(msg.contains("access denied")),
            _ => panic!("expected error"),
        }
    }

    #[tokio::test]
    async fn command_list() {
        let engine = setup().await;
        let cmd = parse_command(&["COMMAND"]).unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        match resp {
            StashResponse::Ok(v) => {
                assert!(v["count"].as_u64().unwrap() > 0);
                assert!(v["commands"].as_array().is_some());
            }
            _ => panic!("expected Ok"),
        }
    }

    #[tokio::test]
    async fn list_blobs() {
        let engine = setup().await;
        let ctx = test_ctx();

        // Store two blobs
        let data_b64 = STANDARD.encode(b"blob-a-data");
        let cmd = parse_command(&["STORE", "list-a", &data_b64]).unwrap();
        let resp = dispatch(&engine, cmd, Some(&ctx)).await;
        assert!(resp.is_ok(), "store list-a failed: {resp:?}");

        let data_b64 = STANDARD.encode(b"blob-b-data");
        let cmd = parse_command(&["STORE", "list-b", &data_b64]).unwrap();
        let resp = dispatch(&engine, cmd, Some(&ctx)).await;
        assert!(resp.is_ok(), "store list-b failed: {resp:?}");

        // LIST should return both
        let cmd = parse_command(&["LIST"]).unwrap();
        let resp = dispatch(&engine, cmd, Some(&ctx)).await;
        assert!(resp.is_ok(), "list failed: {resp:?}");
        match &resp {
            StashResponse::Ok(v) => {
                assert_eq!(v["tenant"], "test-tenant");
                assert_eq!(v["count"], 2);
                let blobs = v["blobs"].as_array().unwrap();
                assert_eq!(blobs.len(), 2);
            }
            _ => panic!("expected Ok"),
        }

        // LIST with LIMIT 1 should return 1
        let cmd = parse_command(&["LIST", "LIMIT", "1"]).unwrap();
        let resp = dispatch(&engine, cmd, Some(&ctx)).await;
        assert!(resp.is_ok());
        match &resp {
            StashResponse::Ok(v) => {
                assert_eq!(v["count"], 1);
            }
            _ => panic!("expected Ok"),
        }
    }

    #[tokio::test]
    async fn tenant_isolation() {
        let engine = setup().await;

        let ctx_a = AuthContext::platform("tenant-a", "actor-a");
        let ctx_b = AuthContext::platform("tenant-b", "actor-b");

        // Store a blob as tenant-a
        let data_b64 = STANDARD.encode(b"tenant-a-secret");
        let cmd = parse_command(&["STORE", "isolated-1", &data_b64]).unwrap();
        let resp = dispatch(&engine, cmd, Some(&ctx_a)).await;
        assert!(resp.is_ok(), "store failed: {resp:?}");

        // tenant-a can retrieve it
        let cmd = parse_command(&["RETRIEVE", "isolated-1"]).unwrap();
        let resp = dispatch(&engine, cmd, Some(&ctx_a)).await;
        assert!(resp.is_ok(), "tenant-a retrieve should succeed");

        // tenant-b cannot retrieve it (NotFound, not access denied)
        let cmd = parse_command(&["RETRIEVE", "isolated-1"]).unwrap();
        let resp = dispatch(&engine, cmd, Some(&ctx_b)).await;
        assert!(!resp.is_ok(), "tenant-b retrieve should fail");

        // tenant-b cannot inspect it
        let cmd = parse_command(&["INSPECT", "isolated-1"]).unwrap();
        let resp = dispatch(&engine, cmd, Some(&ctx_b)).await;
        assert!(!resp.is_ok(), "tenant-b inspect should fail");

        // tenant-a can inspect it
        let cmd = parse_command(&["INSPECT", "isolated-1"]).unwrap();
        let resp = dispatch(&engine, cmd, Some(&ctx_a)).await;
        assert!(resp.is_ok(), "tenant-a inspect should succeed");
    }

    #[tokio::test]
    async fn fingerprint_creates_viewer_copy() {
        let engine = setup().await;
        let ctx = test_ctx();

        // Store a blob
        let data_b64 = STANDARD.encode(b"fingerprint-me");
        let cmd = parse_command(&["STORE", "fp-1", &data_b64]).unwrap();
        let resp = dispatch(&engine, cmd, Some(&ctx)).await;
        assert!(resp.is_ok(), "store failed: {resp:?}");

        // Fingerprint for viewer-1
        let cmd = parse_command(&["FINGERPRINT", "fp-1", "viewer-1"]).unwrap();
        let resp = dispatch(&engine, cmd, Some(&ctx)).await;
        assert!(resp.is_ok(), "fingerprint failed: {resp:?}");
        match &resp {
            StashResponse::Ok(v) => {
                assert_eq!(v["status"], "ok");
                assert_eq!(v["viewer_id"], "viewer-1");
                assert!(v["s3_key"].as_str().unwrap().contains("viewers/viewer-1"));
                assert!(v["created_at"].as_u64().is_some());
            }
            _ => panic!("expected Ok"),
        }

        // Inspect should show viewer_count=1
        let cmd = parse_command(&["INSPECT", "fp-1"]).unwrap();
        let resp = dispatch(&engine, cmd, Some(&ctx)).await;
        match &resp {
            StashResponse::Ok(v) => {
                assert_eq!(v["viewer_count"], 1);
            }
            _ => panic!("expected Ok from inspect"),
        }
    }

    #[tokio::test]
    async fn fingerprint_duplicate_viewer_rejected() {
        let engine = setup().await;
        let ctx = test_ctx();

        let data_b64 = STANDARD.encode(b"dup-viewer-test");
        let cmd = parse_command(&["STORE", "fp-dup", &data_b64]).unwrap();
        dispatch(&engine, cmd, Some(&ctx)).await;

        // First fingerprint succeeds
        let cmd = parse_command(&["FINGERPRINT", "fp-dup", "viewer-1"]).unwrap();
        let resp = dispatch(&engine, cmd, Some(&ctx)).await;
        assert!(resp.is_ok());

        // Second fingerprint for same viewer fails
        let cmd = parse_command(&["FINGERPRINT", "fp-dup", "viewer-1"]).unwrap();
        let resp = dispatch(&engine, cmd, Some(&ctx)).await;
        assert!(!resp.is_ok(), "duplicate fingerprint should fail");
        match resp {
            StashResponse::Error(msg) => {
                assert!(
                    msg.contains("already fingerprinted"),
                    "error should mention duplicate: {msg}"
                );
            }
            _ => panic!("expected Error"),
        }
    }

    #[tokio::test]
    async fn trace_returns_viewer_map() {
        let engine = setup().await;
        let ctx = test_ctx();

        let data_b64 = STANDARD.encode(b"trace-test");
        let cmd = parse_command(&["STORE", "tr-1", &data_b64]).unwrap();
        dispatch(&engine, cmd, Some(&ctx)).await;

        // Fingerprint two viewers
        let cmd = parse_command(&["FINGERPRINT", "tr-1", "viewer-a"]).unwrap();
        let resp = dispatch(&engine, cmd, Some(&ctx)).await;
        assert!(resp.is_ok(), "fingerprint viewer-a failed: {resp:?}");

        let cmd = parse_command(&["FINGERPRINT", "tr-1", "viewer-b"]).unwrap();
        let resp = dispatch(&engine, cmd, Some(&ctx)).await;
        assert!(resp.is_ok(), "fingerprint viewer-b failed: {resp:?}");

        // TRACE should return both viewers
        let cmd = parse_command(&["TRACE", "tr-1"]).unwrap();
        let resp = dispatch(&engine, cmd, Some(&ctx)).await;
        assert!(resp.is_ok(), "trace failed: {resp:?}");
        match &resp {
            StashResponse::Ok(v) => {
                assert_eq!(v["status"], "ok");
                assert_eq!(v["id"], "tr-1");
                assert_eq!(v["blob_status"], "active");
                assert_eq!(v["viewer_count"], 2);
                let viewers = v["viewers"].as_array().unwrap();
                assert_eq!(viewers.len(), 2);
                let viewer_ids: Vec<&str> = viewers
                    .iter()
                    .map(|v| v["viewer_id"].as_str().unwrap())
                    .collect();
                assert!(viewer_ids.contains(&"viewer-a"));
                assert!(viewer_ids.contains(&"viewer-b"));
            }
            _ => panic!("expected Ok"),
        }
    }

    #[tokio::test]
    async fn fingerprint_revoked_blob_rejected() {
        let engine = setup().await;
        let ctx = test_ctx();

        let data_b64 = STANDARD.encode(b"revoke-fp-test");
        let cmd = parse_command(&["STORE", "fp-rev", &data_b64]).unwrap();
        dispatch(&engine, cmd, Some(&ctx)).await;

        // Soft revoke
        let cmd = parse_command(&["REVOKE", "fp-rev", "SOFT"]).unwrap();
        dispatch(&engine, cmd, Some(&ctx)).await;

        // Fingerprint should fail
        let cmd = parse_command(&["FINGERPRINT", "fp-rev", "viewer-1"]).unwrap();
        let resp = dispatch(&engine, cmd, Some(&ctx)).await;
        assert!(!resp.is_ok(), "fingerprint on revoked blob should fail");
        match resp {
            StashResponse::Error(msg) => {
                assert!(
                    msg.contains("revoked"),
                    "error should mention revoked: {msg}"
                );
            }
            _ => panic!("expected Error"),
        }
    }

    /// F-stash-8 (L): when `auth_context` is None, dispatch used to
    /// silently synthesise `tenant = "default"` for tenant-scoped
    /// commands, so a connection that never authenticated could land
    /// on a real tenant's namespace. Fail-closed behaviour is to
    /// refuse tenant-scoped commands outright when no auth context
    /// has been established — the caller must show identity first.
    ///
    /// Infrastructure commands (HEALTH, PING, COMMAND LIST, HELLO)
    /// legitimately run without auth and are covered by
    /// `health_and_ping` and `command_list`.
    #[tokio::test]
    async fn debt_stash_8_tenant_scoped_dispatch_without_auth_must_fail_closed() {
        let engine = setup().await;

        // Every tenant-scoped mutation/read must be refused without
        // auth context — no silent "default" tenant synthesis.
        let tenant_scoped: &[&[&str]] = &[
            &["STORE", "nd-1", &STANDARD.encode(b"x")],
            &["RETRIEVE", "nd-1"],
            &["INSPECT", "nd-1"],
            &["REWRAP", "nd-1"],
            &["REVOKE", "nd-1"],
            &["FINGERPRINT", "nd-1", "viewer-1"],
            &["TRACE", "nd-1"],
            &["LIST"],
        ];

        for args in tenant_scoped {
            let cmd = parse_command(args).unwrap();
            let resp = dispatch(&engine, cmd, None).await;
            assert!(
                !resp.is_ok(),
                "{:?} must fail-closed without auth_context; got {:?}",
                args,
                resp
            );
            match resp {
                StashResponse::Error(msg) => {
                    let lower = msg.to_lowercase();
                    assert!(
                        lower.contains("auth")
                            || lower.contains("denied")
                            || lower.contains("tenant"),
                        "error for {args:?} should name the missing auth context, got: {msg}"
                    );
                }
                other => panic!("expected Error for {args:?}, got {other:?}"),
            }
        }
    }
}
