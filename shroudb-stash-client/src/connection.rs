use crate::error::ClientError;

/// TCP connection to a Stash server speaking RESP3.
///
/// Built directly on top of tokio TCP rather than wrapping `shroudb-client-common`,
/// because Stash's RETRIEVE command returns RESP3 arrays (metadata + blob bytes)
/// which the common connection does not support.
pub struct Connection {
    reader: tokio::io::BufReader<tokio::net::tcp::OwnedReadHalf>,
    writer: tokio::io::BufWriter<tokio::net::tcp::OwnedWriteHalf>,
    command_prefix: Option<String>,
}

impl Connection {
    /// Connect directly to a standalone Stash server.
    pub async fn connect(addr: &str) -> Result<Self, ClientError> {
        let stream = tokio::net::TcpStream::connect(addr).await?;
        let (r, w) = stream.into_split();
        Ok(Self {
            reader: tokio::io::BufReader::new(r),
            writer: tokio::io::BufWriter::new(w),
            command_prefix: None,
        })
    }

    /// Connect to a Stash engine through a Moat gateway.
    pub async fn connect_moat(addr: &str) -> Result<Self, ClientError> {
        let stream = tokio::net::TcpStream::connect(addr).await?;
        let (r, w) = stream.into_split();
        Ok(Self {
            reader: tokio::io::BufReader::new(r),
            writer: tokio::io::BufWriter::new(w),
            command_prefix: Some("STASH".to_string()),
        })
    }

    /// Send an engine command (prefixed in Moat mode).
    pub async fn send_command(&mut self, args: &[&str]) -> Result<serde_json::Value, ClientError> {
        if let Some(prefix) = self.command_prefix.clone() {
            let mut prefixed = Vec::with_capacity(args.len() + 1);
            prefixed.push(prefix.as_str());
            prefixed.extend_from_slice(args);
            self.write_command(&prefixed).await?;
        } else {
            self.write_command(args).await?;
        }
        self.read_value().await
    }

    /// Send a meta-command (AUTH, HEALTH, PING) without engine prefix.
    pub async fn send_meta_command(
        &mut self,
        args: &[&str],
    ) -> Result<serde_json::Value, ClientError> {
        self.write_command(args).await?;
        self.read_value().await
    }

    /// Send a command and return the raw RESP3 response.
    /// Alias for `send_command` — both handle all RESP3 types.
    pub async fn send_command_raw(
        &mut self,
        args: &[&str],
    ) -> Result<serde_json::Value, ClientError> {
        self.send_command(args).await
    }

    /// Write a RESP3 array command to the wire.
    async fn write_command(&mut self, args: &[&str]) -> Result<(), ClientError> {
        use tokio::io::AsyncWriteExt;

        let mut buf = Vec::new();
        buf.extend_from_slice(format!("*{}\r\n", args.len()).as_bytes());
        for arg in args {
            buf.extend_from_slice(format!("${}\r\n", arg.len()).as_bytes());
            buf.extend_from_slice(arg.as_bytes());
            buf.extend_from_slice(b"\r\n");
        }

        self.writer.write_all(&buf).await?;
        self.writer.flush().await?;
        Ok(())
    }

    /// Read a single RESP3 bulk string element from the stream.
    ///
    /// Expects the `$<len>\r\n<data>\r\n` format. Used when reading array elements.
    async fn read_bulk_string(&mut self) -> Result<serde_json::Value, ClientError> {
        use tokio::io::{AsyncBufReadExt, AsyncReadExt};

        let mut line = String::new();
        self.reader.read_line(&mut line).await?;
        let line = line.trim_end();

        if line.is_empty() || line.as_bytes()[0] != b'$' {
            return Err(ClientError::Protocol(format!(
                "expected bulk string in array, got: {}",
                line
            )));
        }

        let len: usize = line[1..]
            .parse()
            .map_err(|_| ClientError::Protocol("invalid bulk length".into()))?;
        let mut body = vec![0u8; len];
        self.reader.read_exact(&mut body).await?;
        let mut crlf = [0u8; 2];
        self.reader.read_exact(&mut crlf).await?;

        match serde_json::from_slice(&body) {
            Ok(json) => Ok(json),
            Err(_) => Ok(serde_json::Value::Array(
                body.iter()
                    .map(|&b| serde_json::Value::Number(b.into()))
                    .collect(),
            )),
        }
    }

    /// Read a single RESP3 value from the stream.
    async fn read_value(&mut self) -> Result<serde_json::Value, ClientError> {
        use tokio::io::{AsyncBufReadExt, AsyncReadExt};

        let mut line = String::new();
        self.reader.read_line(&mut line).await?;
        let line = line.trim_end();

        if line.is_empty() {
            return Err(ClientError::Protocol("empty response".into()));
        }

        match line.as_bytes()[0] {
            b'+' => {
                // Simple string
                let body = &line[1..];
                serde_json::from_str(body).or_else(|_| Ok(serde_json::json!(body)))
            }
            b'-' => {
                // Error
                let msg = &line[1..];
                let msg = msg.strip_prefix("ERR ").unwrap_or(msg);
                Err(ClientError::Server(msg.to_string()))
            }
            b'$' => {
                // Bulk string
                let len: usize = line[1..]
                    .parse()
                    .map_err(|_| ClientError::Protocol("invalid bulk length".into()))?;
                let mut body = vec![0u8; len];
                self.reader.read_exact(&mut body).await?;
                let mut crlf = [0u8; 2];
                self.reader.read_exact(&mut crlf).await?;

                // Try to parse as JSON; if that fails, return as base64-encoded string
                // (for raw binary data like blob bytes).
                match serde_json::from_slice(&body) {
                    Ok(json) => Ok(json),
                    Err(_) => {
                        // Raw bytes -- return as a JSON array of byte values
                        // so the caller can reconstruct the original bytes.
                        Ok(serde_json::Value::Array(
                            body.iter()
                                .map(|&b| serde_json::Value::Number(b.into()))
                                .collect(),
                        ))
                    }
                }
            }
            b'*' => {
                // Array -- Stash arrays contain only bulk strings (no nesting).
                let count: usize = line[1..]
                    .parse()
                    .map_err(|_| ClientError::Protocol("invalid array length".into()))?;
                let mut elements = Vec::with_capacity(count);
                for _ in 0..count {
                    elements.push(self.read_bulk_string().await?);
                }
                Ok(serde_json::Value::Array(elements))
            }
            _ => Err(ClientError::Protocol(format!(
                "unexpected response type: {}",
                line
            ))),
        }
    }
}
