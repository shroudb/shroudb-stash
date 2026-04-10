//! Typed Rust client library for Stash.
//!
//! Provides a high-level async API for interacting with a Stash server
//! over TCP (RESP3 wire protocol).

mod connection;
mod error;

pub use error::ClientError;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use connection::Connection;

/// Result from a STORE operation.
#[derive(Debug, Clone)]
pub struct StoreResult {
    pub id: String,
    pub s3_key: String,
    pub keyring: String,
    pub key_version: u32,
    pub plaintext_size: u64,
    pub encrypted_size: u64,
    pub client_encrypted: bool,
}

/// Result from a RETRIEVE operation.
#[derive(Debug, Clone)]
pub struct RetrieveResult {
    pub data: Vec<u8>,
    pub id: String,
    pub content_type: Option<String>,
    pub plaintext_size: u64,
    pub client_encrypted: bool,
    pub wrapped_dek: Option<String>,
}

/// Result from an INSPECT operation.
#[derive(Debug, Clone)]
pub struct InspectResult {
    pub id: String,
    pub blob_status: String,
    pub content_type: Option<String>,
    pub plaintext_size: u64,
    pub encrypted_size: u64,
    pub keyring: String,
    pub key_version: u32,
    pub client_encrypted: bool,
    pub viewer_count: u64,
    pub created_at: u64,
    pub updated_at: u64,
}

/// Result from a REVOKE operation.
#[derive(Debug, Clone)]
pub struct RevokeResult {
    pub id: String,
    pub revoke_mode: String,
}

/// A Stash client connected via TCP.
pub struct StashClient {
    conn: Connection,
}

impl StashClient {
    /// Connect directly to a standalone Stash server.
    pub async fn connect(addr: &str) -> Result<Self, ClientError> {
        let conn = Connection::connect(addr).await?;
        Ok(Self { conn })
    }

    /// Connect to a Stash engine through a Moat gateway.
    ///
    /// Commands are automatically prefixed with `STASH` for Moat routing.
    /// Meta-commands (AUTH, HEALTH, PING) are sent without prefix.
    pub async fn connect_moat(addr: &str) -> Result<Self, ClientError> {
        let conn = Connection::connect_moat(addr).await?;
        Ok(Self { conn })
    }

    /// Authenticate this connection.
    pub async fn auth(&mut self, token: &str) -> Result<(), ClientError> {
        let resp = self.meta_command(&["AUTH", token]).await?;
        check_status(&resp)
    }

    /// Health check.
    pub async fn health(&mut self) -> Result<(), ClientError> {
        let resp = self.meta_command(&["HEALTH"]).await?;
        check_status(&resp)
    }

    // ── Blob operations ────────────────────────────────────────────

    /// Store an encrypted blob.
    pub async fn store(
        &mut self,
        id: &str,
        data: &[u8],
        keyring: Option<&str>,
        content_type: Option<&str>,
    ) -> Result<StoreResult, ClientError> {
        let data_b64 = STANDARD.encode(data);
        let mut args = vec!["STORE", id, &data_b64];
        if let Some(kr) = keyring {
            args.push("KEYRING");
            args.push(kr);
        }
        if let Some(ct) = content_type {
            args.push("CONTENT_TYPE");
            args.push(ct);
        }
        let resp = self.command(&args).await?;
        check_status(&resp)?;
        Ok(StoreResult {
            id: string_field(&resp, "id")?,
            s3_key: string_field(&resp, "s3_key")?,
            keyring: string_field(&resp, "keyring")?,
            key_version: u32_field(&resp, "key_version")?,
            plaintext_size: u64_field(&resp, "plaintext_size")?,
            encrypted_size: u64_field(&resp, "encrypted_size")?,
            client_encrypted: bool_field(&resp, "client_encrypted")?,
        })
    }

    /// Store a pre-encrypted blob (client-encrypted passthrough).
    pub async fn store_client_encrypted(
        &mut self,
        id: &str,
        ciphertext: &[u8],
        wrapped_dek: &str,
        content_type: Option<&str>,
    ) -> Result<StoreResult, ClientError> {
        let data_b64 = STANDARD.encode(ciphertext);
        let mut args = vec!["STORE", id, &data_b64, "CLIENT_ENCRYPTED", wrapped_dek];
        if let Some(ct) = content_type {
            args.push("CONTENT_TYPE");
            args.push(ct);
        }
        let resp = self.command(&args).await?;
        check_status(&resp)?;
        Ok(StoreResult {
            id: string_field(&resp, "id")?,
            s3_key: string_field(&resp, "s3_key")?,
            keyring: string_field(&resp, "keyring")?,
            key_version: u32_field(&resp, "key_version")?,
            plaintext_size: u64_field(&resp, "plaintext_size")?,
            encrypted_size: u64_field(&resp, "encrypted_size")?,
            client_encrypted: bool_field(&resp, "client_encrypted")?,
        })
    }

    /// Retrieve and decrypt a blob.
    ///
    /// Returns the blob data along with metadata. For client-encrypted blobs,
    /// the raw ciphertext and wrapped DEK are returned.
    pub async fn retrieve(&mut self, id: &str) -> Result<RetrieveResult, ClientError> {
        let resp = self.conn.send_command_raw(&["RETRIEVE", id]).await?;

        // RETRIEVE returns a RESP3 Array: [metadata_json, blob_bytes]
        let parts = resp
            .as_array()
            .ok_or_else(|| ClientError::ResponseFormat("expected array response".into()))?;

        if parts.len() != 2 {
            return Err(ClientError::ResponseFormat(format!(
                "expected 2-element array, got {}",
                parts.len()
            )));
        }

        let meta: serde_json::Value = serde_json::from_value(parts[0].clone())
            .map_err(|e| ClientError::ResponseFormat(format!("invalid metadata: {e}")))?;

        let data = match &parts[1] {
            serde_json::Value::String(s) => STANDARD
                .decode(s)
                .map_err(|e| ClientError::ResponseFormat(format!("invalid blob data: {e}")))?,
            serde_json::Value::Array(arr) => arr
                .iter()
                .filter_map(|v| v.as_u64().map(|n| n as u8))
                .collect(),
            _ => {
                return Err(ClientError::ResponseFormat(
                    "unexpected blob data format".into(),
                ));
            }
        };

        Ok(RetrieveResult {
            data,
            id: meta["id"].as_str().unwrap_or_default().to_string(),
            content_type: meta["content_type"].as_str().map(String::from),
            plaintext_size: meta["plaintext_size"].as_u64().unwrap_or(0),
            client_encrypted: meta["client_encrypted"].as_bool().unwrap_or(false),
            wrapped_dek: meta["wrapped_dek"].as_str().map(String::from),
        })
    }

    /// Inspect blob metadata without downloading or decrypting.
    pub async fn inspect(&mut self, id: &str) -> Result<InspectResult, ClientError> {
        let resp = self.command(&["INSPECT", id]).await?;
        check_status(&resp)?;
        Ok(InspectResult {
            id: string_field(&resp, "id")?,
            blob_status: string_field(&resp, "blob_status")?,
            content_type: resp["content_type"].as_str().map(String::from),
            plaintext_size: u64_field(&resp, "plaintext_size")?,
            encrypted_size: u64_field(&resp, "encrypted_size")?,
            keyring: string_field(&resp, "keyring")?,
            key_version: u32_field(&resp, "key_version")?,
            client_encrypted: bool_field(&resp, "client_encrypted")?,
            viewer_count: resp["viewer_count"].as_u64().unwrap_or(0),
            created_at: u64_field(&resp, "created_at")?,
            updated_at: u64_field(&resp, "updated_at")?,
        })
    }

    /// Revoke a blob (hard crypto-shred by default).
    pub async fn revoke(&mut self, id: &str, soft: bool) -> Result<RevokeResult, ClientError> {
        let mut args = vec!["REVOKE", id];
        if soft {
            args.push("SOFT");
        }
        let resp = self.command(&args).await?;
        check_status(&resp)?;
        Ok(RevokeResult {
            id: string_field(&resp, "id")?,
            revoke_mode: string_field(&resp, "revoke_mode")?,
        })
    }

    // ── Internal ────────────────────────────────────────────────────

    async fn command(&mut self, args: &[&str]) -> Result<serde_json::Value, ClientError> {
        self.conn.send_command(args).await
    }

    async fn meta_command(&mut self, args: &[&str]) -> Result<serde_json::Value, ClientError> {
        self.conn.send_meta_command(args).await
    }
}

fn check_status(resp: &serde_json::Value) -> Result<(), ClientError> {
    if let Some(status) = resp.get("status").and_then(|s| s.as_str())
        && status == "ok"
    {
        return Ok(());
    }
    if resp.is_array() || resp.is_object() {
        return Ok(());
    }
    Err(ClientError::ResponseFormat("unexpected response".into()))
}

fn string_field(resp: &serde_json::Value, field: &str) -> Result<String, ClientError> {
    resp[field]
        .as_str()
        .map(String::from)
        .ok_or_else(|| ClientError::ResponseFormat(format!("missing {field}")))
}

fn u32_field(resp: &serde_json::Value, field: &str) -> Result<u32, ClientError> {
    resp[field]
        .as_u64()
        .map(|v| v as u32)
        .ok_or_else(|| ClientError::ResponseFormat(format!("missing {field}")))
}

fn u64_field(resp: &serde_json::Value, field: &str) -> Result<u64, ClientError> {
    resp[field]
        .as_u64()
        .ok_or_else(|| ClientError::ResponseFormat(format!("missing {field}")))
}

fn bool_field(resp: &serde_json::Value, field: &str) -> Result<bool, ClientError> {
    resp[field]
        .as_bool()
        .ok_or_else(|| ClientError::ResponseFormat(format!("missing {field}")))
}
