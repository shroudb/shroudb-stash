use shroudb_acl::AuthContext;
use shroudb_stash_engine::engine::{StashEngine, StoreBlobParams};
use shroudb_store::Store;

use crate::commands::StashCommand;
use crate::response::StashResponse;

const SUPPORTED_COMMANDS: &[&str] = &[
    "AUTH",
    "STORE",
    "RETRIEVE",
    "INSPECT",
    "REVOKE",
    "HEALTH",
    "PING",
    "COMMAND LIST",
];

/// Dispatch a parsed command to the StashEngine and produce a response.
///
/// `auth_context` is the authenticated identity for this connection/request.
/// `None` means auth is disabled (dev mode / no auth config).
pub async fn dispatch<S: Store>(
    engine: &StashEngine<S>,
    cmd: StashCommand,
    auth_context: Option<&AuthContext>,
) -> StashResponse {
    // Check ACL requirement before dispatch.
    let requirement = cmd.acl_requirement();
    if let Some(ctx) = auth_context
        && let Err(e) = ctx.check(&requirement)
    {
        return StashResponse::error(format!("access denied: {e}"));
    }

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
                Ok(meta) => StashResponse::ok(serde_json::json!({
                    "status": "ok",
                    "id": meta.id,
                    "s3_key": meta.s3_key,
                    "keyring": meta.keyring,
                    "key_version": meta.key_version,
                    "plaintext_size": meta.plaintext_size,
                    "encrypted_size": meta.encrypted_size,
                    "client_encrypted": meta.client_encrypted,
                })),
                Err(e) => StashResponse::error(e.to_string()),
            }
        }

        // ── RETRIEVE ──────────────────────────────────────────────────
        StashCommand::Retrieve { id } => match engine.retrieve_blob(&id, actor).await {
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
        StashCommand::Inspect { id } => match engine.inspect_blob(&id, actor).await {
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
        StashCommand::Revoke { id, soft } => match engine.revoke_blob(&id, soft, actor).await {
            Ok(()) => {
                let mode = if soft { "soft" } else { "hard" };
                StashResponse::ok(serde_json::json!({
                    "status": "ok",
                    "id": id,
                    "revoke_mode": mode,
                }))
            }
            Err(e) => StashResponse::error(e.to_string()),
        },

        // ── Operational ───────────────────────────────────────────────
        StashCommand::Health => StashResponse::ok(serde_json::json!({
            "status": "ok",
        })),

        StashCommand::Ping => StashResponse::ok(serde_json::json!("PONG")),

        StashCommand::CommandList => StashResponse::ok(serde_json::json!({
            "count": SUPPORTED_COMMANDS.len(),
            "commands": SUPPORTED_COMMANDS,
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
            ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut dek).unwrap();
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
    }

    async fn setup() -> StashEngine<shroudb_storage::EmbeddedStore> {
        let store = shroudb_storage::test_util::create_test_store("stash-proto-test").await;
        let obj_store = Arc::new(InMemoryObjectStore::new());
        let caps = Capabilities {
            cipher: Some(Box::new(MockCipherOps::new())),
            sentry: None,
            chronicle: None,
        };
        StashEngine::new(store, obj_store, caps, StashConfig::default())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn full_store_retrieve_flow() {
        let engine = setup().await;

        let data_b64 = STANDARD.encode(b"hello stash protocol");
        let cmd =
            parse_command(&["STORE", "proto-1", &data_b64, "CONTENT_TYPE", "text/plain"]).unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        assert!(resp.is_ok(), "store failed: {resp:?}");

        let cmd = parse_command(&["RETRIEVE", "proto-1"]).unwrap();
        let resp = dispatch(&engine, cmd, None).await;
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

        let data_b64 = STANDARD.encode(b"secret");
        let cmd = parse_command(&["STORE", "sir-1", &data_b64]).unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        assert!(resp.is_ok());

        // Inspect
        let cmd = parse_command(&["INSPECT", "sir-1"]).unwrap();
        let resp = dispatch(&engine, cmd, None).await;
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
        let resp = dispatch(&engine, cmd, None).await;
        assert!(resp.is_ok());
        match &resp {
            StashResponse::Ok(v) => assert_eq!(v["revoke_mode"], "soft"),
            _ => panic!("expected Ok"),
        }

        // Retrieve should fail
        let cmd = parse_command(&["RETRIEVE", "sir-1"]).unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        assert!(!resp.is_ok());
    }

    #[tokio::test]
    async fn hard_revoke_flow() {
        let engine = setup().await;

        let data_b64 = STANDARD.encode(b"shred-me");
        let cmd = parse_command(&["STORE", "shred-1", &data_b64]).unwrap();
        dispatch(&engine, cmd, None).await;

        let cmd = parse_command(&["REVOKE", "shred-1"]).unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        assert!(resp.is_ok());
        match &resp {
            StashResponse::Ok(v) => assert_eq!(v["revoke_mode"], "hard"),
            _ => panic!("expected Ok"),
        }

        // Inspect shows shredded
        let cmd = parse_command(&["INSPECT", "shred-1"]).unwrap();
        let resp = dispatch(&engine, cmd, None).await;
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
        let cmd = parse_command(&["RETRIEVE", "nope"]).unwrap();
        let resp = dispatch(&engine, cmd, None).await;
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
}
