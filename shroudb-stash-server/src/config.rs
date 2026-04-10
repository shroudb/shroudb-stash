use std::net::SocketAddr;
use std::path::PathBuf;

use serde::Deserialize;
use shroudb_acl::ServerAuthConfig;

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
