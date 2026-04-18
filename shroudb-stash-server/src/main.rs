mod config;
mod tcp;

use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use shroudb_stash_engine::capabilities::Capabilities;
use shroudb_stash_engine::engine::{StashConfig, StashEngine};
use shroudb_stash_engine::s3::{S3Config, S3ObjectStore};
use shroudb_store::Store;

use crate::config::{StashServerConfig, load_config};

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

    // Resolve log level
    let log_level = if cli.log_level != "info" {
        cli.log_level.clone()
    } else {
        cfg.server
            .log_level
            .take()
            .unwrap_or_else(|| "info".to_string())
    };

    // Bootstrap: logging + core dumps + key source
    let key_source = shroudb_server_bootstrap::bootstrap(&log_level);

    // CLI overrides
    if let Some(ref dir) = cli.data_dir {
        cfg.store.data_dir = dir.into();
    }
    if let Some(ref bind) = cli.tcp_bind {
        cfg.server.tcp_bind = bind.parse().context("invalid TCP bind address")?;
    }

    // Store: embedded or remote
    match cfg.store.mode.as_str() {
        "embedded" => {
            let storage =
                shroudb_server_bootstrap::open_storage(&cfg.store.data_dir, key_source.as_ref())
                    .await
                    .context("failed to open storage engine")?;
            let store = Arc::new(shroudb_storage::EmbeddedStore::new(
                storage.clone(),
                "stash",
            ));
            run_server(cfg, store, Some(storage)).await
        }
        "remote" => {
            let uri = cfg
                .store
                .uri
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("remote mode requires store.uri"))?;
            tracing::info!(uri, "connecting to remote store");
            let store = Arc::new(
                shroudb_client::RemoteStore::connect(uri)
                    .await
                    .context("failed to connect to remote store")?,
            );
            run_server(cfg, store, None).await
        }
        other => anyhow::bail!("unknown store mode: {other}"),
    }
}

async fn run_server<S: Store + 'static>(
    cfg: StashServerConfig,
    store: Arc<S>,
    storage: Option<Arc<shroudb_storage::StorageEngine>>,
) -> anyhow::Result<()> {
    use shroudb_server_bootstrap::Capability;

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

    // Resolve [audit] and [policy] capabilities — no silent None.
    let audit_cfg = cfg.audit.clone().ok_or_else(|| {
        anyhow::anyhow!(
            "missing [audit] config section. Pick one:\n  \
             [audit] mode = \"remote\" addr = \"chronicle.internal:7300\"\n  \
             [audit] mode = \"embedded\"\n  \
             [audit] mode = \"disabled\" justification = \"<reason>\""
        )
    })?;
    let audit_cap = audit_cfg
        .resolve(storage.clone())
        .await
        .context("failed to resolve [audit] capability")?;
    let policy_cfg = cfg.policy.clone().ok_or_else(|| {
        anyhow::anyhow!(
            "missing [policy] config section. Pick one:\n  \
             [policy] mode = \"remote\" addr = \"sentry.internal:7100\"\n  \
             [policy] mode = \"embedded\"\n  \
             [policy] mode = \"disabled\" justification = \"<reason>\""
        )
    })?;
    let policy_cap = policy_cfg
        .resolve(storage.clone(), audit_cap.as_ref().cloned())
        .await
        .context("failed to resolve [policy] capability")?;

    // Cipher for Stash is not yet wired at the standalone-server layer:
    // STORE/RETRIEVE rely on envelope encryption via Cipher. Until this
    // server gets its own [cipher] config + wiring (mirroring Scroll), the
    // slot is explicit DisabledWithJustification so operators see WHY
    // data-plane ops refuse. Embedded Cipher wiring via Moat is the
    // supported path in the meantime.
    let cipher_cap =
        Capability::<Box<dyn shroudb_stash_engine::capabilities::StashCipherOps>>::disabled(
            "stash-server standalone cipher wiring not yet implemented; use Moat for embedded cipher",
        );

    // Stash engine
    let stash_config = StashConfig {
        default_keyring: cfg.engine.keyring.clone(),
        s3_key_prefix: cfg.engine.s3_key_prefix.clone(),
        ..Default::default()
    };
    let capabilities = Capabilities::new(cipher_cap, policy_cap, audit_cap);
    let engine = Arc::new(
        StashEngine::new(store, object_store, capabilities, stash_config)
            .await
            .context("failed to initialize stash engine")?,
    );

    // Shutdown signal
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // Auth
    let token_validator = cfg.auth.build_validator();
    if token_validator.is_some() {
        tracing::info!(tokens = cfg.auth.tokens.len(), "token-based auth enabled");
    }

    // TCP server
    let tcp_listener = tokio::net::TcpListener::bind(cfg.server.tcp_bind)
        .await
        .context("failed to bind TCP")?;

    let tls_acceptor = cfg
        .server
        .tls
        .as_ref()
        .map(shroudb_server_tcp::build_tls_acceptor)
        .transpose()
        .context("failed to build TLS acceptor")?;

    let tcp_engine = engine.clone();
    let tcp_validator = token_validator.clone();
    let tcp_shutdown = shutdown_rx.clone();
    let tcp_handle = tokio::spawn(async move {
        tcp::run_tcp(
            tcp_listener,
            tcp_engine,
            tcp_validator,
            tcp_shutdown,
            tls_acceptor,
        )
        .await;
    });

    // Banner (Stash has extra bucket line)
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
    shroudb_server_bootstrap::wait_for_shutdown(shutdown_tx).await?;
    let _ = tcp_handle.await;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_debug_asserts() {
        Cli::command().debug_assert();
    }

    #[test]
    fn cli_accepts_config_flag() {
        let parsed = Cli::try_parse_from(["shroudb-stash", "--config", "stash.toml"]).unwrap();
        assert_eq!(parsed.config.as_deref(), Some("stash.toml"));
    }
}
