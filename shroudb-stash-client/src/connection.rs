use crate::error::ClientError;

/// TCP connection to a Stash server speaking RESP3.
pub struct Connection(shroudb_client_common::Connection);

impl Connection {
    /// Connect to a Stash server.
    pub async fn connect(addr: &str) -> Result<Self, ClientError> {
        Ok(Self(
            shroudb_client_common::Connection::connect(addr).await?,
        ))
    }

    /// Send a command and read the JSON response.
    pub async fn send_command(&mut self, args: &[&str]) -> Result<serde_json::Value, ClientError> {
        Ok(self.0.send_command(args).await?)
    }

    /// Send a command and return the raw RESP3 response as JSON.
    /// Used by RETRIEVE which returns an array, not a single JSON object.
    pub async fn send_command_raw(
        &mut self,
        args: &[&str],
    ) -> Result<serde_json::Value, ClientError> {
        Ok(self.0.send_command(args).await?)
    }
}
