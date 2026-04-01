mod config;
mod tcp;

use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use shroudb_stash_engine::capabilities::Capabilities;
use shroudb_stash_engine::engine::{StashConfig, StashEngine};
use shroudb_stash_engine::s3::{S3Config, S3ObjectStore};
use shroudb_storage::{
    ChainedMasterKeySource, EnvMasterKey, EphemeralKey, FileMasterKey, MasterKeySource,
    StorageEngineConfig,
};

use crate::config::load_config;

#[derive(Parser)]
#[command(name = "shroudb-stash", about = "Stash encrypted blob storage engine")]
struct Cli {
    /// Path to config file.
    #[arg(short, long, env = "STASH_CONFIG")]
    config: Option<String>,

    /// Data directory (overrides config).
    #[arg(long, env = "STASH_DATA_DIR")]
    data_dir: Option<String>,

    /// TCP bind address (overrides config).
    #[arg(long, env = "STASH_TCP_BIND")]
    tcp_bind: Option<String>,

    /// Log level.
    #[arg(long, env = "STASH_LOG_LEVEL", default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Load config
    let mut cfg = load_config(cli.config.as_deref())?;

    // Logging
    let log_level = if cli.log_level != "info" {
        cli.log_level.clone()
    } else {
        cfg.server
            .log_level
            .take()
            .unwrap_or_else(|| "info".to_string())
    };
    let filter = tracing_subscriber::EnvFilter::try_new(&log_level)
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .json()
        .init();

    // Disable core dumps — sensitive key material must not leak to disk.
    shroudb_crypto::disable_core_dumps();

    // CLI overrides
    if let Some(ref dir) = cli.data_dir {
        cfg.store.data_dir = dir.into();
    }
    if let Some(ref bind) = cli.tcp_bind {
        cfg.server.tcp_bind = bind.parse().context("invalid TCP bind address")?;
    }

    // Store mode validation
    if cfg.store.mode == "remote" {
        anyhow::bail!(
            "remote store mode not yet implemented (uri: {:?})",
            cfg.store.uri
        );
    }

    // Master key
    let key_source: Box<dyn MasterKeySource> = Box::new(ChainedMasterKeySource::new(vec![
        Box::new(EnvMasterKey::new()),
        Box::new(FileMasterKey::new()),
        Box::new(EphemeralKey),
    ]));

    // Storage engine
    let engine_config = StorageEngineConfig {
        data_dir: cfg.store.data_dir.clone(),
        ..Default::default()
    };
    let storage_engine = shroudb_storage::StorageEngine::open(engine_config, key_source.as_ref())
        .await
        .context("failed to open storage engine")?;
    let store = Arc::new(shroudb_storage::EmbeddedStore::new(
        Arc::new(storage_engine),
        "stash",
    ));

    // S3 object store
    let s3_config = S3Config {
        bucket: cfg.engine.bucket.clone(),
        region: cfg.engine.region.clone(),
        endpoint: cfg.engine.endpoint.clone(),
    };
    let object_store: Arc<dyn shroudb_stash_engine::object_store::ObjectStore> = Arc::new(
        S3ObjectStore::new(s3_config)
            .await
            .context("failed to connect to S3")?,
    );

    // Stash engine
    let stash_config = StashConfig {
        default_keyring: cfg.engine.keyring.clone(),
        s3_key_prefix: cfg.engine.s3_key_prefix.clone(),
    };
    let capabilities = Capabilities::default();
    let engine = Arc::new(
        StashEngine::new(store, object_store, capabilities, stash_config)
            .await
            .context("failed to initialize stash engine")?,
    );

    // Shutdown signal
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // Auth
    let token_validator = config::build_token_validator(&cfg.auth);
    if token_validator.is_some() {
        tracing::info!(tokens = cfg.auth.tokens.len(), "token-based auth enabled");
    }

    // TCP server
    let tcp_listener = tokio::net::TcpListener::bind(cfg.server.tcp_bind)
        .await
        .context("failed to bind TCP")?;

    let tcp_engine = engine.clone();
    let tcp_validator = token_validator.clone();
    let tcp_shutdown = shutdown_rx.clone();
    let tcp_handle = tokio::spawn(async move {
        tcp::run_tcp(tcp_listener, tcp_engine, tcp_validator, tcp_shutdown).await;
    });

    // Banner
    eprintln!();
    eprintln!("Stash v{}", env!("CARGO_PKG_VERSION"));
    eprintln!("├─ tcp:     {}", cfg.server.tcp_bind);
    eprintln!("├─ data:    {}", cfg.store.data_dir.display());
    eprintln!("├─ bucket:  {}", cfg.engine.bucket);
    eprintln!(
        "└─ key:     {}",
        if std::env::var("SHROUDB_MASTER_KEY").is_ok()
            || std::env::var("SHROUDB_MASTER_KEY_FILE").is_ok()
        {
            "configured"
        } else {
            "ephemeral (dev mode)"
        }
    );
    eprintln!();
    eprintln!("Ready.");

    // Wait for shutdown
    tokio::signal::ctrl_c()
        .await
        .context("failed to listen for ctrl-c")?;
    tracing::info!("shutting down");
    let _ = shutdown_tx.send(true);
    let _ = tcp_handle.await;

    Ok(())
}
