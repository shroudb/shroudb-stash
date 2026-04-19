use std::net::SocketAddr;
use std::path::PathBuf;

use serde::Deserialize;
use shroudb_acl::ServerAuthConfig;
use shroudb_engine_bootstrap::{AuditConfig, PolicyConfig};

#[derive(Debug, Deserialize, Default)]
pub struct StashServerConfig {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub store: StoreConfig,
    #[serde(default)]
    pub engine: EngineConfig,
    #[serde(default)]
    pub auth: ServerAuthConfig,
    /// Cipher (envelope-encryption) capability slot.
    ///
    /// Two modes:
    /// - `mode = "remote"`: point at an external `shroudb-cipher` server
    /// - `mode = "embedded"`: bundle an in-process `CipherEngine` on the
    ///   same `StorageEngine` as Stash's metadata (distinct namespace).
    ///   Requires `store.mode = "embedded"`.
    ///
    /// Omit the section to run Stash without Cipher — STORE/RETRIEVE
    /// will fail-closed with `CapabilityMissing("cipher")`.
    #[serde(default)]
    pub cipher: Option<CipherConfig>,
    /// Audit (Chronicle) capability slot. Absent = resolved as embedded
    /// Chronicle on the shared StorageEngine (the default mode declared
    /// by `shroudb-engine-bootstrap` 0.3.0). Embedded init failures
    /// still surface at startup — absence is not an error, a broken
    /// embedded sink is.
    #[serde(default)]
    pub audit: Option<AuditConfig>,
    /// Policy (Sentry) capability slot. Same contract as `audit`:
    /// absent = embedded Sentry on the shared StorageEngine.
    #[serde(default)]
    pub policy: Option<PolicyConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CipherConfig {
    #[serde(default = "default_cipher_mode")]
    pub mode: String,
    #[serde(default = "default_cipher_keyring")]
    pub keyring: String,

    // Remote mode — validation accepts `mode = "remote"` but the actual
    // TCP-client wiring lands in a follow-up (see stash-server main.rs
    // for the bail! message). `addr` is validated here so config tests
    // catch typos early; `auth_token` will join once remote wiring exists.
    #[serde(default)]
    pub addr: Option<String>,

    // Embedded mode
    #[serde(default = "default_rotation_days")]
    pub rotation_days: u32,
    #[serde(default = "default_drain_days")]
    pub drain_days: u32,
    #[serde(default = "default_scheduler_interval_secs")]
    pub scheduler_interval_secs: u64,
    #[serde(default = "default_cipher_algorithm")]
    pub algorithm: String,
}

impl CipherConfig {
    pub fn is_embedded(&self) -> bool {
        self.mode == "embedded"
    }

    pub fn is_remote(&self) -> bool {
        self.mode == "remote"
    }

    pub fn validate(&self, store_mode: &str) -> anyhow::Result<()> {
        match self.mode.as_str() {
            "remote" => {
                if self.addr.is_none() {
                    anyhow::bail!("cipher.mode = \"remote\" requires cipher.addr");
                }
            }
            "embedded" => {
                if store_mode != "embedded" {
                    anyhow::bail!(
                        "cipher.mode = \"embedded\" requires store.mode = \"embedded\" \
                         (embedded Cipher shares the StorageEngine with Stash)"
                    );
                }
            }
            other => anyhow::bail!(
                "unknown cipher.mode: {other:?} (expected \"remote\" or \"embedded\")"
            ),
        }
        Ok(())
    }
}

fn default_cipher_mode() -> String {
    "remote".into()
}
fn default_cipher_keyring() -> String {
    "stash-blobs".into()
}
fn default_rotation_days() -> u32 {
    90
}
fn default_drain_days() -> u32 {
    30
}
fn default_scheduler_interval_secs() -> u64 {
    3600
}
fn default_cipher_algorithm() -> String {
    "aes-256-gcm".into()
}

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_tcp_bind")]
    pub tcp_bind: SocketAddr,
    #[serde(default)]
    pub log_level: Option<String>,
    #[serde(default)]
    pub tls: Option<shroudb_server_tcp::TlsConfig>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            tcp_bind: default_tcp_bind(),
            log_level: None,
            tls: None,
        }
    }
}

fn default_tcp_bind() -> SocketAddr {
    "0.0.0.0:6699".parse().expect("valid hardcoded address")
}

#[derive(Debug, Deserialize)]
pub struct StoreConfig {
    #[serde(default = "default_mode")]
    pub mode: String,
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
    #[serde(default)]
    pub uri: Option<String>,
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            mode: default_mode(),
            data_dir: default_data_dir(),
            uri: None,
        }
    }
}

fn default_mode() -> String {
    "embedded".to_string()
}

fn default_data_dir() -> PathBuf {
    PathBuf::from("./stash-data")
}

#[derive(Debug, Deserialize)]
pub struct EngineConfig {
    /// S3 bucket name.
    pub bucket: String,
    /// AWS region.
    #[serde(default = "default_region")]
    pub region: String,
    /// Custom S3-compatible endpoint.
    #[serde(default)]
    pub endpoint: Option<String>,
    /// Cipher keyring for envelope encryption.
    #[serde(default = "default_keyring")]
    pub keyring: String,
    /// S3 key prefix.
    #[serde(default)]
    pub s3_key_prefix: Option<String>,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            bucket: "stash-blobs".to_string(),
            region: default_region(),
            endpoint: None,
            keyring: default_keyring(),
            s3_key_prefix: None,
        }
    }
}

fn default_region() -> String {
    "us-east-1".to_string()
}

fn default_keyring() -> String {
    "stash-blobs".to_string()
}

/// Load config from a TOML file, or return defaults.
pub fn load_config(path: Option<&str>) -> anyhow::Result<StashServerConfig> {
    match path {
        Some(p) => {
            let raw = std::fs::read_to_string(p)
                .map_err(|e| anyhow::anyhow!("failed to read config: {e}"))?;
            let config: StashServerConfig =
                toml::from_str(&raw).map_err(|e| anyhow::anyhow!("failed to parse config: {e}"))?;
            Ok(config)
        }
        None => Ok(StashServerConfig::default()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults_to_embedded_mode() {
        let cfg = StashServerConfig::default();
        assert_eq!(cfg.store.mode, "embedded");
        assert!(cfg.store.uri.is_none());
    }

    #[test]
    fn config_parses_remote_mode_with_uri() {
        let toml = r#"
[store]
mode = "remote"
uri = "shroudb://token@127.0.0.1:6399"
"#;
        let cfg: StashServerConfig = toml::from_str(toml).expect("parse failed");
        assert_eq!(cfg.store.mode, "remote");
        assert_eq!(
            cfg.store.uri.as_deref(),
            Some("shroudb://token@127.0.0.1:6399")
        );
    }

    #[test]
    fn config_parses_remote_mode_tls_uri() {
        let toml = r#"
[store]
mode = "remote"
uri = "shroudb+tls://token@store.example.com:6399"
"#;
        let cfg: StashServerConfig = toml::from_str(toml).expect("parse failed");
        assert_eq!(cfg.store.mode, "remote");
        assert_eq!(
            cfg.store.uri.as_deref(),
            Some("shroudb+tls://token@store.example.com:6399")
        );
    }
}
