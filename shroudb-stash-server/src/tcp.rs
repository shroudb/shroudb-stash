use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use shroudb_acl::{AclRequirement, AuthContext, TokenValidator};
use shroudb_protocol_wire::Resp3Frame;
use shroudb_server_tcp::ServerProtocol;
use shroudb_stash_engine::engine::StashEngine;
use shroudb_stash_protocol::commands::{StashCommand, parse_command};
use shroudb_stash_protocol::dispatch::dispatch;
use shroudb_stash_protocol::response::StashResponse;

pub struct StashProtocol;

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

pub async fn run_tcp(
    listener: tokio::net::TcpListener,
    engine: Arc<StashEngine<shroudb_storage::EmbeddedStore>>,
    token_validator: Option<Arc<dyn TokenValidator>>,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
    tls_acceptor: Option<tokio_rustls::TlsAcceptor>,
) {
    shroudb_server_tcp::run_tcp_tls(
        listener,
        engine,
        Arc::new(StashProtocol),
        token_validator,
        shutdown_rx,
        tls_acceptor,
    )
    .await;
}
