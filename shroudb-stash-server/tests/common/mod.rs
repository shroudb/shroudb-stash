use std::net::TcpListener as StdTcpListener;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use shroudb_crypto::SensitiveBytes;
use shroudb_stash_engine::capabilities::{BoxFut, Capabilities, DataKeyPair, StashCipherOps};
use shroudb_stash_engine::engine::{StashConfig, StashEngine};
use shroudb_stash_engine::object_store::{InMemoryObjectStore, ObjectStore};
use shroudb_stash_engine::s3::S3ObjectStore;

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
    /// Use MinIO S3 backend instead of InMemoryObjectStore.
    pub use_minio: bool,
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

fn free_port() -> u16 {
    StdTcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .expect("ephemeral port addr")
        .port()
}

/// A running in-process test server. Shuts down on drop.
pub struct TestServer {
    pub tcp_addr: String,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    _tcp_handle: tokio::task::JoinHandle<()>,
    /// MinIO container ID, if started.
    minio_container: Option<String>,
    /// S3 endpoint, for direct verification.
    pub s3_endpoint: Option<String>,
    /// S3 bucket name.
    pub s3_bucket: Option<String>,
}

impl TestServer {
    /// Start a test server with default config (no auth, in-memory store).
    pub async fn start() -> Self {
        Self::start_with_config(TestServerConfig::default()).await
    }

    /// Start a test server with custom config.
    pub async fn start_with_config(config: TestServerConfig) -> Self {
        // Build object store (InMemory or MinIO-backed S3).
        let (object_store, minio_container, s3_endpoint, s3_bucket): (
            Arc<dyn ObjectStore>,
            Option<String>,
            Option<String>,
            Option<String>,
        ) = if config.use_minio {
            let (store, container_id, endpoint, bucket) = start_minio().await;
            (
                Arc::new(store),
                Some(container_id),
                Some(endpoint),
                Some(bucket),
            )
        } else {
            (Arc::new(InMemoryObjectStore::new()), None, None, None)
        };

        // Bind to an ephemeral port.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("failed to bind ephemeral port");
        let tcp_addr = listener.local_addr().expect("local addr").to_string();

        // Build the in-process engine.
        let store = shroudb_storage::test_util::create_test_store("stash-integ").await;
        let caps = Capabilities {
            cipher: Some(Box::new(MockCipherOps::new())),
            sentry: None,
            chronicle: None,
        };
        let engine = Arc::new(
            StashEngine::new(store, object_store, caps, StashConfig::default())
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
            minio_container,
            s3_endpoint,
            s3_bucket,
        }
    }

    /// Get a raw S3 client for direct verification (only available for MinIO tests).
    pub async fn s3_client(&self) -> Option<aws_sdk_s3::Client> {
        let endpoint = self.s3_endpoint.as_ref()?;
        let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_sdk_s3::config::Region::new("us-east-1"))
            .endpoint_url(endpoint)
            .load()
            .await;
        let s3_config = aws_sdk_s3::config::Builder::from(&sdk_config)
            .force_path_style(true)
            .build();
        Some(aws_sdk_s3::Client::from_conf(s3_config))
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = self.shutdown_tx.send(true);
        // Kill MinIO container if we started one.
        if let Some(ref container_id) = self.minio_container {
            let _ = Command::new("docker")
                .args(["rm", "-f", container_id])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }
}

/// Start a MinIO container and return an S3ObjectStore connected to it.
async fn start_minio() -> (S3ObjectStore, String, String, String) {
    let port = free_port();
    let endpoint = format!("http://127.0.0.1:{port}");
    let bucket = "stash-test";

    // Start MinIO container.
    let output = Command::new("docker")
        .args([
            "run",
            "-d",
            "--rm",
            "-p",
            &format!("{port}:9000"),
            "-e",
            "MINIO_ROOT_USER=minioadmin",
            "-e",
            "MINIO_ROOT_PASSWORD=minioadmin",
            "minio/minio",
            "server",
            "/data",
        ])
        .output()
        .expect("failed to start MinIO container — is Docker running?");

    assert!(
        output.status.success(),
        "MinIO container failed to start: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let container_id = String::from_utf8(output.stdout)
        .expect("container id")
        .trim()
        .to_string();

    // Set AWS credentials for the S3 client.
    // SAFETY: tests are single-threaded at this point (MinIO not yet connected),
    // and these env vars are only read by the AWS SDK during config loading.
    unsafe {
        std::env::set_var("AWS_ACCESS_KEY_ID", "minioadmin");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "minioadmin");
    }

    // Wait for MinIO to be ready.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        if tokio::time::Instant::now() > deadline {
            // Clean up container on failure.
            let _ = Command::new("docker")
                .args(["rm", "-f", &container_id])
                .status();
            panic!("MinIO failed to start within 15s");
        }
        if reqwest_health_check(&endpoint).await {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // Create the test bucket via the S3 API.
    let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_sdk_s3::config::Region::new("us-east-1"))
        .endpoint_url(&endpoint)
        .load()
        .await;
    let s3_config = aws_sdk_s3::config::Builder::from(&sdk_config)
        .force_path_style(true)
        .build();
    let raw_client = aws_sdk_s3::Client::from_conf(s3_config);

    raw_client
        .create_bucket()
        .bucket(bucket)
        .send()
        .await
        .expect("failed to create test bucket");

    // Build S3ObjectStore via with_client (skip the HEAD bucket in new()).
    let sdk_config2 = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_sdk_s3::config::Region::new("us-east-1"))
        .endpoint_url(&endpoint)
        .load()
        .await;
    let s3_config2 = aws_sdk_s3::config::Builder::from(&sdk_config2)
        .force_path_style(true)
        .build();
    let client = aws_sdk_s3::Client::from_conf(s3_config2);

    let store = S3ObjectStore::with_client(client, bucket.to_string());
    (store, container_id, endpoint, bucket.to_string())
}

/// Simple TCP health check for MinIO readiness.
async fn reqwest_health_check(endpoint: &str) -> bool {
    tokio::net::TcpStream::connect(endpoint.strip_prefix("http://").unwrap_or(endpoint))
        .await
        .is_ok()
}

/// Run TCP server (mirrors shroudb-stash-server/src/tcp.rs but usable from tests).
pub(crate) async fn run_tcp(
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
