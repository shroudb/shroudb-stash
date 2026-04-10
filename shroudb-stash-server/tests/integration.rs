mod common;

use base64::Engine as _;
use common::*;

// ═══════════════════════════════════════════════════════════════════════
// Health & Ping
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_health() {
    let server = TestServer::start().await;
    let mut client = shroudb_stash_client::StashClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    client.health().await.expect("health check failed");
}

// ═══════════════════════════════════════════════════════════════════════
// Store and Retrieve — in-memory
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_store_and_retrieve() {
    let server = TestServer::start().await;
    let mut client = shroudb_stash_client::StashClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    let plaintext = b"hello, stash integration test!";

    let store_result = client
        .store("blob-1", plaintext, None, Some("text/plain"))
        .await
        .expect("store failed");

    assert_eq!(store_result.id, "blob-1");
    assert_eq!(store_result.plaintext_size, plaintext.len() as u64);
    assert!(!store_result.client_encrypted);
    assert!(store_result.encrypted_size > store_result.plaintext_size);

    let retrieve_result = client.retrieve("blob-1").await.expect("retrieve failed");

    assert_eq!(retrieve_result.data, plaintext);
    assert_eq!(retrieve_result.id, "blob-1");
    assert_eq!(retrieve_result.content_type.as_deref(), Some("text/plain"));
    assert!(!retrieve_result.client_encrypted);
    assert!(retrieve_result.wrapped_dek.is_none());
}

// ═══════════════════════════════════════════════════════════════════════
// Store and Retrieve — MinIO S3 backend
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_store_and_retrieve_minio() {
    let server = match TestServer::start_with_config(TestServerConfig {
        use_minio: true,
        ..Default::default()
    })
    .await
    {
        Some(s) => s,
        None => {
            eprintln!("skipping: Docker unavailable");
            return;
        }
    };
    let mut client = shroudb_stash_client::StashClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    let plaintext = b"hello from MinIO!";

    let store_result = client
        .store("minio-blob-1", plaintext, None, Some("text/plain"))
        .await
        .expect("store to MinIO failed");

    assert_eq!(store_result.id, "minio-blob-1");
    assert!(!store_result.client_encrypted);

    // Verify the object exists in S3 directly.
    let s3 = server.s3_client().await.expect("s3 client");
    let head = s3
        .head_object()
        .bucket(server.s3_bucket.as_ref().unwrap())
        .key("default/minio-blob-1")
        .send()
        .await
        .expect("S3 HEAD should find the object");
    assert!(head.content_length().unwrap_or(0) > 0);

    // Retrieve via Stash and verify roundtrip.
    let retrieve_result = client
        .retrieve("minio-blob-1")
        .await
        .expect("retrieve from MinIO failed");
    assert_eq!(retrieve_result.data, plaintext);
}

// ═══════════════════════════════════════════════════════════════════════
// Hard revoke deletes S3 objects (MinIO)
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_hard_revoke_deletes_s3_object_minio() {
    let server = match TestServer::start_with_config(TestServerConfig {
        use_minio: true,
        ..Default::default()
    })
    .await
    {
        Some(s) => s,
        None => {
            eprintln!("skipping: Docker unavailable");
            return;
        }
    };
    let mut client = shroudb_stash_client::StashClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    client
        .store("revoke-s3", b"delete from S3", None, None)
        .await
        .expect("store failed");

    // Verify object exists in S3.
    let s3 = server.s3_client().await.expect("s3 client");
    let bucket = server.s3_bucket.as_ref().unwrap();
    s3.head_object()
        .bucket(bucket)
        .key("default/revoke-s3")
        .send()
        .await
        .expect("object should exist before revoke");

    // Hard revoke.
    client
        .revoke("revoke-s3", false)
        .await
        .expect("revoke failed");

    // Verify S3 object is deleted.
    let head_err = s3
        .head_object()
        .bucket(bucket)
        .key("default/revoke-s3")
        .send()
        .await;
    assert!(
        head_err.is_err(),
        "S3 object should be deleted after hard revoke"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Large blob roundtrip via MinIO
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_large_blob_minio() {
    let server = match TestServer::start_with_config(TestServerConfig {
        use_minio: true,
        ..Default::default()
    })
    .await
    {
        Some(s) => s,
        None => {
            eprintln!("skipping: Docker unavailable");
            return;
        }
    };
    let mut client = shroudb_stash_client::StashClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    // 512 KB blob.
    let large_data = vec![0xCDu8; 512 * 1024];

    client
        .store(
            "large-minio",
            &large_data,
            None,
            Some("application/octet-stream"),
        )
        .await
        .expect("store large blob to MinIO failed");

    let result = client
        .retrieve("large-minio")
        .await
        .expect("retrieve large blob from MinIO failed");
    assert_eq!(result.data, large_data);
}

// ═══════════════════════════════════════════════════════════════════════
// Binary data with null bytes
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_binary_with_null_bytes() {
    let server = TestServer::start().await;
    let mut client = shroudb_stash_client::StashClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    // Binary data with null bytes, high bytes, and control characters.
    let binary_data: Vec<u8> = (0..=255).collect();

    client
        .store(
            "binary-1",
            &binary_data,
            None,
            Some("application/octet-stream"),
        )
        .await
        .expect("store binary data failed");

    let result = client
        .retrieve("binary-1")
        .await
        .expect("retrieve binary data failed");
    assert_eq!(result.data, binary_data);
}

// ═══════════════════════════════════════════════════════════════════════
// Client-encrypted passthrough
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_client_encrypted_passthrough() {
    let server = TestServer::start().await;
    let mut client = shroudb_stash_client::StashClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    // Valid ciphertext: at least 28 bytes (12-byte nonce + 16-byte auth tag)
    let ciphertext = &[0xAA; 64];
    // Valid wrapped DEK: base64-encoded, at least 32 bytes decoded
    let wrapped_dek_str = base64::engine::general_purpose::STANDARD.encode([0xBB; 48]);
    let wrapped_dek = wrapped_dek_str.as_str();

    let store_result = client
        .store_client_encrypted(
            "ce-1",
            ciphertext,
            wrapped_dek,
            Some("application/octet-stream"),
        )
        .await
        .expect("store client-encrypted failed");

    assert_eq!(store_result.id, "ce-1");
    assert!(store_result.client_encrypted);

    // Retrieve should return raw ciphertext + wrapped DEK.
    let result = client.retrieve("ce-1").await.expect("retrieve failed");
    assert_eq!(result.data, ciphertext);
    assert!(result.client_encrypted);
    assert_eq!(result.wrapped_dek.as_deref(), Some(wrapped_dek));

    // Inspect should show client_encrypted.
    let info = client.inspect("ce-1").await.expect("inspect failed");
    assert!(info.client_encrypted);
}

#[tokio::test]
async fn test_client_encrypted_rejects_invalid_dek() {
    let server = TestServer::start().await;
    let mut client = shroudb_stash_client::StashClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    let ciphertext = &[0xAA; 64];

    // Non-base64 wrapped DEK should be rejected
    let err = client
        .store_client_encrypted("ce-bad", ciphertext, "not!!!valid===base64", None)
        .await;
    assert!(err.is_err(), "should reject non-base64 wrapped DEK");

    // Too-short wrapped DEK should be rejected (16 bytes < 32 minimum)
    let short_dek = base64::engine::general_purpose::STANDARD.encode([0xCC; 16]);
    let err = client
        .store_client_encrypted("ce-short-dek", ciphertext, &short_dek, None)
        .await;
    assert!(err.is_err(), "should reject too-short wrapped DEK");
}

#[tokio::test]
async fn test_client_encrypted_rejects_short_ciphertext() {
    let server = TestServer::start().await;
    let mut client = shroudb_stash_client::StashClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    let valid_dek = base64::engine::general_purpose::STANDARD.encode([0xBB; 48]);

    // 10 bytes is less than 28-byte minimum (nonce + tag)
    let short_ct = &[0xDD; 10];
    let err = client
        .store_client_encrypted("ce-short-ct", short_ct, &valid_dek, None)
        .await;
    assert!(err.is_err(), "should reject too-short ciphertext");
}

// ═══════════════════════════════════════════════════════════════════════
// Inspect
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_inspect() {
    let server = TestServer::start().await;
    let mut client = shroudb_stash_client::StashClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    let plaintext = b"inspect me";
    client
        .store("inspect-1", plaintext, None, Some("application/pdf"))
        .await
        .expect("store failed");

    let info = client.inspect("inspect-1").await.expect("inspect failed");

    assert_eq!(info.id, "inspect-1");
    assert_eq!(info.blob_status, "active");
    assert_eq!(info.content_type.as_deref(), Some("application/pdf"));
    assert_eq!(info.plaintext_size, plaintext.len() as u64);
    assert!(info.encrypted_size > info.plaintext_size);
    assert!(!info.client_encrypted);
    assert_eq!(info.viewer_count, 0);
    assert!(info.created_at > 0);
    assert!(info.updated_at > 0);
}

// ═══════════════════════════════════════════════════════════════════════
// Store multiple, verify each retrievable
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_multiple_blobs() {
    let server = TestServer::start().await;
    let mut client = shroudb_stash_client::StashClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    for i in 0..5 {
        let id = format!("multi-{i}");
        let data = format!("data-{i}");
        client
            .store(&id, data.as_bytes(), None, None)
            .await
            .unwrap_or_else(|e| panic!("store {id} failed: {e}"));
    }

    for i in 0..5 {
        let id = format!("multi-{i}");
        let expected = format!("data-{i}");
        let result = client
            .retrieve(&id)
            .await
            .unwrap_or_else(|e| panic!("retrieve {id} failed: {e}"));
        assert_eq!(result.data, expected.as_bytes());
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Hard revoke (crypto-shred)
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_hard_revoke() {
    let server = TestServer::start().await;
    let mut client = shroudb_stash_client::StashClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    client
        .store("del-1", b"delete me", None, None)
        .await
        .expect("store failed");

    // Verify retrievable before revoke.
    client
        .retrieve("del-1")
        .await
        .expect("retrieve should work before revoke");

    // Hard revoke.
    let revoke_result = client.revoke("del-1", false).await.expect("revoke failed");
    assert_eq!(revoke_result.id, "del-1");
    assert_eq!(revoke_result.revoke_mode, "hard");

    // Retrieve should fail.
    let err = client.retrieve("del-1").await;
    assert!(err.is_err(), "retrieve after hard revoke should fail");

    // Inspect should show shredded.
    let info = client
        .inspect("del-1")
        .await
        .expect("inspect after revoke should work");
    assert_eq!(info.blob_status, "shredded");
}

// ═══════════════════════════════════════════════════════════════════════
// Double hard revoke fails
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_double_hard_revoke_fails() {
    let server = TestServer::start().await;
    let mut client = shroudb_stash_client::StashClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    client
        .store("double-rev", b"data", None, None)
        .await
        .expect("store failed");

    client
        .revoke("double-rev", false)
        .await
        .expect("first revoke should succeed");

    let err = client.revoke("double-rev", false).await;
    assert!(
        err.is_err(),
        "second hard revoke should fail (already shredded)"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Soft revoke blocks retrieve but preserves metadata
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_soft_revoke() {
    let server = TestServer::start().await;
    let mut client = shroudb_stash_client::StashClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    client
        .store("soft-1", b"soft revoke test", None, None)
        .await
        .expect("store failed");

    let revoke_result = client
        .revoke("soft-1", true)
        .await
        .expect("soft revoke failed");
    assert_eq!(revoke_result.revoke_mode, "soft");

    // Retrieve should fail.
    let err = client.retrieve("soft-1").await;
    assert!(err.is_err(), "retrieve after soft revoke should fail");

    // Inspect should show revoked status.
    let info = client.inspect("soft-1").await.expect("inspect should work");
    assert_eq!(info.blob_status, "revoked");
}

// ═══════════════════════════════════════════════════════════════════════
// Store with metadata (content type, custom keyring)
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_store_with_metadata() {
    let server = TestServer::start().await;
    let mut client = shroudb_stash_client::StashClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    let png_data = b"\x89PNG\r\n\x1a\nfake-png-data";

    let store_result = client
        .store(
            "meta-1",
            png_data,
            Some("custom-keyring"),
            Some("image/png"),
        )
        .await
        .expect("store with metadata failed");

    assert_eq!(store_result.id, "meta-1");
    assert_eq!(store_result.keyring, "custom-keyring");

    let info = client.inspect("meta-1").await.expect("inspect failed");
    assert_eq!(info.content_type.as_deref(), Some("image/png"));
    assert_eq!(info.keyring, "custom-keyring");
    assert_eq!(info.plaintext_size, png_data.len() as u64);

    let result = client.retrieve("meta-1").await.expect("retrieve failed");
    assert_eq!(result.data, png_data);
    assert_eq!(result.content_type.as_deref(), Some("image/png"));
}

// ═══════════════════════════════════════════════════════════════════════
// Duplicate store rejected
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_duplicate_store_rejected() {
    let server = TestServer::start().await;
    let mut client = shroudb_stash_client::StashClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    client
        .store("dup-1", b"first", None, None)
        .await
        .expect("first store failed");

    let err = client.store("dup-1", b"second", None, None).await;
    assert!(err.is_err(), "duplicate store should fail");
}

// ═══════════════════════════════════════════════════════════════════════
// Nonexistent object returns error
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_nonexistent_object_returns_error() {
    let server = TestServer::start().await;
    let mut client = shroudb_stash_client::StashClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    let err = client.retrieve("does-not-exist").await;
    assert!(err.is_err(), "retrieve nonexistent blob should fail");

    let err = client.inspect("does-not-exist").await;
    assert!(err.is_err(), "inspect nonexistent blob should fail");

    let err = client.revoke("does-not-exist", false).await;
    assert!(err.is_err(), "revoke nonexistent blob should fail");
}

// ═══════════════════════════════════════════════════════════════════════
// Large blob roundtrip — in-memory
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_large_blob_roundtrip() {
    let server = TestServer::start().await;
    let mut client = shroudb_stash_client::StashClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    let large_data = vec![0xABu8; 256 * 1024];

    client
        .store(
            "large-1",
            &large_data,
            None,
            Some("application/octet-stream"),
        )
        .await
        .expect("store large blob failed");

    let result = client
        .retrieve("large-1")
        .await
        .expect("retrieve large blob failed");
    assert_eq!(result.data, large_data);
}

// ═══════════════════════════════════════════════════════════════════════
// ACL: Three token types (admin, app read+write, readonly)
// ═══════════════════════════════════════════════════════════════════════

fn auth_server_config() -> TestServerConfig {
    TestServerConfig {
        tokens: vec![
            TestToken {
                raw: "admin-token".to_string(),
                tenant: "tenant-a".to_string(),
                actor: "admin".to_string(),
                platform: true,
                grants: vec![],
            },
            TestToken {
                raw: "app-token".to_string(),
                tenant: "tenant-a".to_string(),
                actor: "my-app".to_string(),
                platform: false,
                grants: vec![TestGrant {
                    namespace: "*".to_string(),
                    scopes: vec!["read".to_string(), "write".to_string()],
                }],
            },
            TestToken {
                raw: "readonly-token".to_string(),
                tenant: "tenant-a".to_string(),
                actor: "reader".to_string(),
                platform: false,
                grants: vec![TestGrant {
                    namespace: "*".to_string(),
                    scopes: vec!["read".to_string()],
                }],
            },
        ],
        ..Default::default()
    }
}

#[tokio::test]
async fn test_acl_unauthenticated_rejected() {
    let server = TestServer::start_with_config(auth_server_config())
        .await
        .expect("test server failed to start");
    let mut client = shroudb_stash_client::StashClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    // Health is public.
    client.health().await.expect("health should be public");

    // Write operations should fail without auth.
    let err = client.store("test", b"data", None, None).await;
    assert!(err.is_err(), "unauthenticated store should fail");

    // Read operations should fail without auth.
    let err = client.retrieve("test").await;
    assert!(err.is_err(), "unauthenticated retrieve should fail");

    let err = client.inspect("test").await;
    assert!(err.is_err(), "unauthenticated inspect should fail");
}

#[tokio::test]
async fn test_acl_admin_full_access() {
    let server = TestServer::start_with_config(auth_server_config())
        .await
        .expect("test server failed to start");
    let mut client = shroudb_stash_client::StashClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    client.auth("admin-token").await.expect("admin auth failed");

    client
        .store("admin-blob", b"admin data", None, Some("text/plain"))
        .await
        .expect("admin should be able to store");

    let result = client
        .retrieve("admin-blob")
        .await
        .expect("admin should be able to retrieve");
    assert_eq!(result.data, b"admin data");

    let info = client
        .inspect("admin-blob")
        .await
        .expect("admin should be able to inspect");
    assert_eq!(info.blob_status, "active");

    client
        .revoke("admin-blob", true)
        .await
        .expect("admin should be able to revoke");
}

#[tokio::test]
async fn test_acl_app_token_read_write() {
    let server = TestServer::start_with_config(auth_server_config())
        .await
        .expect("test server failed to start");
    let mut client = shroudb_stash_client::StashClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    client.auth("app-token").await.expect("app auth failed");

    // App token has read + write.
    client
        .store("app-blob", b"app data", None, None)
        .await
        .expect("app should be able to store");

    let result = client
        .retrieve("app-blob")
        .await
        .expect("app should be able to retrieve");
    assert_eq!(result.data, b"app data");

    client
        .inspect("app-blob")
        .await
        .expect("app should be able to inspect");

    client
        .revoke("app-blob", false)
        .await
        .expect("app should be able to revoke");
}

#[tokio::test]
async fn test_acl_readonly_token_cannot_write() {
    let server = TestServer::start_with_config(auth_server_config())
        .await
        .expect("test server failed to start");

    // First, store a blob with admin so readonly has something to read.
    let mut admin = shroudb_stash_client::StashClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");
    admin.auth("admin-token").await.expect("admin auth failed");
    admin
        .store("ro-blob", b"readable data", None, None)
        .await
        .expect("admin store failed");

    // Now connect with readonly token.
    let mut client = shroudb_stash_client::StashClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");
    client
        .auth("readonly-token")
        .await
        .expect("readonly auth failed");

    // Read operations should work.
    let result = client
        .retrieve("ro-blob")
        .await
        .expect("readonly should be able to retrieve");
    assert_eq!(result.data, b"readable data");

    client
        .inspect("ro-blob")
        .await
        .expect("readonly should be able to inspect");

    // Write operations should fail.
    let err = client.store("new-blob", b"data", None, None).await;
    assert!(err.is_err(), "readonly should not be able to store");

    let err = client.revoke("ro-blob", false).await;
    assert!(err.is_err(), "readonly should not be able to revoke");
}

#[tokio::test]
async fn test_acl_wrong_token_rejected() {
    let server = TestServer::start_with_config(auth_server_config())
        .await
        .expect("test server failed to start");
    let mut client = shroudb_stash_client::StashClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    let err = client.auth("totally-wrong-token").await;
    assert!(err.is_err(), "wrong token should be rejected");
}

// ═══════════════════════════════════════════════════════════════════════
// Cipher-less mode: raw passthrough to S3
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_no_cipher_raw_store_retrieve() {
    let server = TestServer::start_with_config(TestServerConfig {
        no_cipher: true,
        ..Default::default()
    })
    .await
    .expect("test server failed to start");
    let mut client = shroudb_stash_client::StashClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    let plaintext = b"stored without encryption";

    let store_result = client
        .store("raw-1", plaintext, None, Some("text/plain"))
        .await
        .expect("store should succeed without Cipher");

    assert_eq!(store_result.id, "raw-1");
    // Raw mode: plaintext_size == encrypted_size (no crypto overhead).
    assert_eq!(store_result.plaintext_size, store_result.encrypted_size);

    // Retrieve should return raw bytes.
    let result = client.retrieve("raw-1").await.expect("retrieve failed");
    assert_eq!(result.data, plaintext);
}

#[tokio::test]
async fn test_no_cipher_inspect_and_revoke() {
    let server = TestServer::start_with_config(TestServerConfig {
        no_cipher: true,
        ..Default::default()
    })
    .await
    .expect("test server failed to start");
    let mut client = shroudb_stash_client::StashClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    client
        .store("raw-rev", b"revoke me raw", None, None)
        .await
        .expect("store failed");

    // Inspect works.
    let info = client.inspect("raw-rev").await.expect("inspect failed");
    assert_eq!(info.blob_status, "active");
    assert_eq!(info.plaintext_size, info.encrypted_size);

    // Hard revoke works.
    let revoke_result = client
        .revoke("raw-rev", false)
        .await
        .expect("revoke failed");
    assert_eq!(revoke_result.revoke_mode, "hard");

    // Retrieve fails after revoke.
    let err = client.retrieve("raw-rev").await;
    assert!(err.is_err());

    // Inspect shows shredded.
    let info = client.inspect("raw-rev").await.expect("inspect failed");
    assert_eq!(info.blob_status, "shredded");
}

#[tokio::test]
async fn test_no_cipher_with_minio() {
    let server = match TestServer::start_with_config(TestServerConfig {
        no_cipher: true,
        use_minio: true,
        ..Default::default()
    })
    .await
    {
        Some(s) => s,
        None => {
            eprintln!("skipping: Docker unavailable");
            return;
        }
    };
    let mut client = shroudb_stash_client::StashClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    let data = b"raw MinIO blob";

    client
        .store("raw-minio-1", data, None, Some("text/plain"))
        .await
        .expect("raw store to MinIO failed");

    // Verify S3 object contains the raw (unencrypted) data directly.
    let s3 = server.s3_client().await.expect("s3 client");
    let bucket = server.s3_bucket.as_ref().unwrap();
    let obj = s3
        .get_object()
        .bucket(bucket)
        .key("default/raw-minio-1")
        .send()
        .await
        .expect("S3 GET should find the raw object");
    let s3_bytes = obj
        .body
        .collect()
        .await
        .expect("read body")
        .into_bytes()
        .to_vec();
    // In raw mode, S3 contains the plaintext directly.
    assert_eq!(s3_bytes, data);

    // Retrieve via Stash roundtrips.
    let result = client
        .retrieve("raw-minio-1")
        .await
        .expect("retrieve failed");
    assert_eq!(result.data, data);
}
