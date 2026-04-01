use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use shroudb_crypto::SensitiveBytes;
use shroudb_stash_engine::capabilities::{BoxFut, Capabilities, DataKeyPair, StashCipherOps};
use shroudb_stash_engine::engine::{StashConfig, StashEngine};
use shroudb_stash_engine::object_store::InMemoryObjectStore;

/// Mock CipherOps that generates deterministic but functional keys.
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
    fn generate_data_key(&self, _bits: Option<u32>) -> BoxFut<'_, DataKeyPair> {
        Box::pin(async move {
            Ok(DataKeyPair {
                plaintext_key: SensitiveBytes::new(self.dek.to_vec()),
                wrapped_key: STANDARD.encode(b"mock-wrapped-dek"),
                key_version: 1,
            })
        })
    }

    fn unwrap_data_key(&self, _wrapped_key: &str) -> BoxFut<'_, SensitiveBytes> {
        Box::pin(async move { Ok(SensitiveBytes::new(self.dek.to_vec())) })
    }
}

/// Test server configuration.
#[derive(Default)]
pub struct TestServerConfig {
    /// Auth tokens. Empty = auth disabled.
    pub tokens: Vec<TestToken>,
}

pub struct TestToken {
    pub raw: String,
    pub tenant: String,
    pub actor: String,
    pub platform: bool,
    pub grants: Vec<TestGrant>,
}

pub struct TestGrant {
    pub namespace: String,
    pub scopes: Vec<String>,
}

/// A running in-process test server. Shuts down on drop.
pub struct TestServer {
    pub tcp_addr: String,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    _tcp_handle: tokio::task::JoinHandle<()>,
}

impl TestServer {
    /// Start a test server with default config (no auth).
    pub async fn start() -> Self {
        Self::start_with_config(TestServerConfig::default()).await
    }

    /// Start a test server with custom config.
    pub async fn start_with_config(config: TestServerConfig) -> Self {
        // Bind to an ephemeral port.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("failed to bind ephemeral port");
        let tcp_addr = listener.local_addr().expect("local addr").to_string();

        // Build the in-process engine with InMemoryObjectStore.
        let store = shroudb_storage::test_util::create_test_store("stash-integ").await;
        let obj_store = Arc::new(InMemoryObjectStore::new());
        let caps = Capabilities {
            cipher: Some(Box::new(MockCipherOps::new())),
            sentry: None,
            chronicle: None,
        };
        let engine = Arc::new(
            StashEngine::new(store, obj_store, caps, StashConfig::default())
                .await
                .expect("failed to create stash engine"),
        );

        // Build token validator from config.
        let token_validator = build_test_token_validator(&config.tokens);

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        let tcp_engine = engine;
        let tcp_handle = tokio::spawn(async move {
            crate::common::run_tcp(listener, tcp_engine, token_validator, shutdown_rx).await;
        });

        // Wait for server to accept connections.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            if tokio::time::Instant::now() > deadline {
                panic!("stash test server failed to start within 5s");
            }
            if let Ok(mut client) = shroudb_stash_client::StashClient::connect(&tcp_addr).await
                && client.health().await.is_ok()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        Self {
            tcp_addr,
            shutdown_tx,
            _tcp_handle: tcp_handle,
        }
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = self.shutdown_tx.send(true);
    }
}

/// Run TCP server (mirrors shroudb-stash-server/src/tcp.rs but usable from tests).
async fn run_tcp(
    listener: tokio::net::TcpListener,
    engine: Arc<StashEngine<shroudb_storage::EmbeddedStore>>,
    token_validator: Option<Arc<dyn shroudb_acl::TokenValidator>>,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    use shroudb_acl::{AclRequirement, AuthContext};
    use shroudb_protocol_wire::Resp3Frame;
    use shroudb_server_tcp::ServerProtocol;
    use shroudb_stash_protocol::commands::{StashCommand, parse_command};
    use shroudb_stash_protocol::dispatch::dispatch;
    use shroudb_stash_protocol::response::StashResponse;
    use std::future::Future;
    use std::pin::Pin;

    struct StashProtocol;

    impl ServerProtocol for StashProtocol {
        type Command = StashCommand;
        type Response = StashResponse;
        type Engine = StashEngine<shroudb_storage::EmbeddedStore>;

        fn engine_name(&self) -> &str {
            "stash"
        }

        fn parse_command(&self, args: &[&str]) -> Result<Self::Command, String> {
            parse_command(args)
        }

        fn auth_token(cmd: &Self::Command) -> Option<&str> {
            if let StashCommand::Auth { token } = cmd {
                Some(token)
            } else {
                None
            }
        }

        fn acl_requirement(cmd: &Self::Command) -> AclRequirement {
            cmd.acl_requirement()
        }

        fn dispatch<'a>(
            &'a self,
            engine: &'a Self::Engine,
            cmd: Self::Command,
            auth: Option<&'a AuthContext>,
        ) -> Pin<Box<dyn Future<Output = Self::Response> + Send + 'a>> {
            Box::pin(dispatch(engine, cmd, auth))
        }

        fn response_to_frame(&self, response: &Self::Response) -> Resp3Frame {
            match response {
                StashResponse::Ok(data) => {
                    let json = serde_json::to_string(data).unwrap_or_default();
                    Resp3Frame::BulkString(json.into_bytes())
                }
                StashResponse::Blob { metadata, data } => {
                    let meta_json = serde_json::to_string(metadata).unwrap_or_default();
                    Resp3Frame::Array(vec![
                        Resp3Frame::BulkString(meta_json.into_bytes()),
                        Resp3Frame::BulkString(data.clone()),
                    ])
                }
                StashResponse::Error(msg) => Resp3Frame::SimpleError(format!("ERR {msg}")),
            }
        }

        fn error_response(&self, msg: String) -> Self::Response {
            StashResponse::error(msg)
        }

        fn ok_response(&self) -> Self::Response {
            StashResponse::ok_simple()
        }
    }

    shroudb_server_tcp::run_tcp(
        listener,
        engine,
        Arc::new(StashProtocol),
        token_validator,
        shutdown_rx,
    )
    .await;
}

/// Build a StaticTokenValidator from test token configs.
fn build_test_token_validator(
    tokens: &[TestToken],
) -> Option<Arc<dyn shroudb_acl::TokenValidator>> {
    if tokens.is_empty() {
        return None;
    }

    let mut validator = shroudb_acl::StaticTokenValidator::new();

    for token in tokens {
        let grants: Vec<shroudb_acl::TokenGrant> = token
            .grants
            .iter()
            .map(|g| {
                let scopes: Vec<shroudb_acl::Scope> = g
                    .scopes
                    .iter()
                    .filter_map(|s| match s.to_lowercase().as_str() {
                        "read" => Some(shroudb_acl::Scope::Read),
                        "write" => Some(shroudb_acl::Scope::Write),
                        _ => None,
                    })
                    .collect();
                shroudb_acl::TokenGrant {
                    namespace: g.namespace.clone(),
                    scopes,
                }
            })
            .collect();

        let t = shroudb_acl::Token {
            tenant: token.tenant.clone(),
            actor: token.actor.clone(),
            is_platform: token.platform,
            grants,
            expires_at: None,
        };

        validator.register(token.raw.clone(), t);
    }

    Some(Arc::new(validator))
}
