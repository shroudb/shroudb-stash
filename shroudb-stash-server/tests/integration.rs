mod common;

use common::*;

// ═══════════════════════════════════════════════════════════════════════
// Health
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
// Store and Retrieve
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_store_and_retrieve() {
    let server = TestServer::start().await;
    let mut client = shroudb_stash_client::StashClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    let plaintext = b"hello, stash integration test!";

    // Store
    let store_result = client
        .store("blob-1", plaintext, None, Some("text/plain"))
        .await
        .expect("store failed");

    assert_eq!(store_result.id, "blob-1");
    assert_eq!(store_result.plaintext_size, plaintext.len() as u64);
    assert!(!store_result.client_encrypted);
    assert!(store_result.encrypted_size > store_result.plaintext_size);

    // Retrieve
    let retrieve_result = client.retrieve("blob-1").await.expect("retrieve failed");

    assert_eq!(retrieve_result.data, plaintext);
    assert_eq!(retrieve_result.id, "blob-1");
    assert_eq!(retrieve_result.content_type.as_deref(), Some("text/plain"));
    assert!(!retrieve_result.client_encrypted);
    assert!(retrieve_result.wrapped_dek.is_none());
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
    assert!(!info.client_encrypted);
    assert_eq!(info.viewer_count, 0);
    assert!(info.created_at > 0);
    assert!(info.updated_at > 0);
}

// ═══════════════════════════════════════════════════════════════════════
// Store multiple, verify each retrievable
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_list_objects() {
    let server = TestServer::start().await;
    let mut client = shroudb_stash_client::StashClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    // Store multiple blobs
    for i in 0..3 {
        let id = format!("multi-{i}");
        let data = format!("data-{i}");
        client
            .store(&id, data.as_bytes(), None, None)
            .await
            .unwrap_or_else(|e| panic!("store {id} failed: {e}"));
    }

    // Verify each is independently retrievable and correct
    for i in 0..3 {
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
// Delete (revoke)
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_delete_object() {
    let server = TestServer::start().await;
    let mut client = shroudb_stash_client::StashClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    client
        .store("del-1", b"delete me", None, None)
        .await
        .expect("store failed");

    // Verify retrievable before revoke
    client
        .retrieve("del-1")
        .await
        .expect("retrieve should work before revoke");

    // Hard revoke (crypto-shred)
    let revoke_result = client.revoke("del-1", false).await.expect("revoke failed");
    assert_eq!(revoke_result.id, "del-1");
    assert_eq!(revoke_result.revoke_mode, "hard");

    // Retrieve should fail after hard revoke
    let err = client.retrieve("del-1").await;
    assert!(err.is_err(), "retrieve after hard revoke should fail");

    // Inspect should show shredded status
    let info = client
        .inspect("del-1")
        .await
        .expect("inspect after revoke should work");
    assert_eq!(info.blob_status, "shredded");
}

// ═══════════════════════════════════════════════════════════════════════
// Store with metadata (content type)
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

    // Verify metadata preserved via inspect
    let info = client.inspect("meta-1").await.expect("inspect failed");

    assert_eq!(info.content_type.as_deref(), Some("image/png"));
    assert_eq!(info.keyring, "custom-keyring");
    assert_eq!(info.plaintext_size, png_data.len() as u64);

    // Verify data roundtrips
    let result = client.retrieve("meta-1").await.expect("retrieve failed");
    assert_eq!(result.data, png_data);
    assert_eq!(result.content_type.as_deref(), Some("image/png"));
}

// ═══════════════════════════════════════════════════════════════════════
// ACL: Unauthenticated rejected
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
                    namespace: "stash.*".to_string(),
                    scopes: vec!["read".to_string(), "write".to_string()],
                }],
            },
        ],
    }
}

#[tokio::test]
async fn test_acl_unauthenticated_rejected() {
    let server = TestServer::start_with_config(auth_server_config()).await;
    let mut client = shroudb_stash_client::StashClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    // Health is public -- should work without auth
    client.health().await.expect("health should be public");

    // Store requires Write -- should fail without auth
    let err = client.store("test", b"data", None, None).await;
    assert!(err.is_err(), "unauthenticated store should fail");

    // Retrieve requires Read -- should fail without auth
    let err = client.retrieve("test").await;
    assert!(err.is_err(), "unauthenticated retrieve should fail");

    // Inspect requires Read -- should fail without auth
    let err = client.inspect("test").await;
    assert!(err.is_err(), "unauthenticated inspect should fail");
}

// ═══════════════════════════════════════════════════════════════════════
// ACL: Admin full access
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_acl_admin_full_access() {
    let server = TestServer::start_with_config(auth_server_config()).await;
    let mut client = shroudb_stash_client::StashClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    // Authenticate as admin (platform token)
    client.auth("admin-token").await.expect("admin auth failed");

    // Admin can store
    client
        .store("admin-blob", b"admin data", None, Some("text/plain"))
        .await
        .expect("admin should be able to store");

    // Admin can retrieve
    let result = client
        .retrieve("admin-blob")
        .await
        .expect("admin should be able to retrieve");
    assert_eq!(result.data, b"admin data");

    // Admin can inspect
    let info = client
        .inspect("admin-blob")
        .await
        .expect("admin should be able to inspect");
    assert_eq!(info.blob_status, "active");

    // Admin can revoke
    client
        .revoke("admin-blob", true)
        .await
        .expect("admin should be able to revoke");
}

// ═══════════════════════════════════════════════════════════════════════
// ACL: Wrong token rejected
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_acl_wrong_token_rejected() {
    let server = TestServer::start_with_config(auth_server_config()).await;
    let mut client = shroudb_stash_client::StashClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    let err = client.auth("totally-wrong-token").await;
    assert!(err.is_err(), "wrong token should be rejected");
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

    // Retrieve nonexistent
    let err = client.retrieve("does-not-exist").await;
    assert!(err.is_err(), "retrieve nonexistent blob should fail");

    // Inspect nonexistent
    let err = client.inspect("does-not-exist").await;
    assert!(err.is_err(), "inspect nonexistent blob should fail");

    // Revoke nonexistent
    let err = client.revoke("does-not-exist", false).await;
    assert!(err.is_err(), "revoke nonexistent blob should fail");
}

// ═══════════════════════════════════════════════════════════════════════
// Soft revoke blocks retrieve but preserves metadata
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_soft_revoke_blocks_retrieve() {
    let server = TestServer::start().await;
    let mut client = shroudb_stash_client::StashClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    client
        .store("soft-1", b"soft revoke test", None, None)
        .await
        .expect("store failed");

    // Soft revoke
    let revoke_result = client
        .revoke("soft-1", true)
        .await
        .expect("soft revoke failed");
    assert_eq!(revoke_result.revoke_mode, "soft");

    // Retrieve should fail
    let err = client.retrieve("soft-1").await;
    assert!(err.is_err(), "retrieve after soft revoke should fail");

    // Inspect should show revoked status
    let info = client.inspect("soft-1").await.expect("inspect should work");
    assert_eq!(info.blob_status, "revoked");
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
// Large blob roundtrip
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_large_blob_roundtrip() {
    let server = TestServer::start().await;
    let mut client = shroudb_stash_client::StashClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    // 256 KB blob
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
