use anyhow::{anyhow, Result};
use std::sync::{Arc, Mutex};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader};

use super::handler::Handler;
use super::protocol::Command;
use crate::tunnel_manager::TunnelManager;

pub const PIPE_NAME: &str = r"\\.\pipe\tunnelbox-daemon";

pub struct IpcServer {
    handler: Arc<Handler>,
}

impl IpcServer {
    pub fn new(tunnel_manager: Arc<Mutex<TunnelManager>>) -> Self {
        Self {
            handler: Arc::new(Handler::new(tunnel_manager)),
        }
    }

    /// Starts the named pipe server — runs forever, accepting one client at a time.
    /// Each client connection is handled on its own tokio task.
    pub async fn run(&self) -> Result<()> {
        tracing::info!("IPC server listening on {}", PIPE_NAME);

        loop {
            // Create a new pipe instance for the next client
            let server = ServerOptions::new()
                .first_pipe_instance(false)
                .create(PIPE_NAME)
                .map_err(|e| anyhow!("Failed to create pipe: {e}"))?;

            // Wait for a client to connect
            server.connect().await
                .map_err(|e| anyhow!("Pipe connect failed: {e}"))?;

            tracing::debug!("IPC client connected");

            let handler = self.handler.clone();

            tokio::spawn(async move {
                if let Err(e) = Self::handle_client(server, handler).await {
                    tracing::warn!("IPC client error: {e}");
                }
                tracing::debug!("IPC client disconnected");
            });
        }
    }

    async fn handle_client(
        pipe: NamedPipeServer,
        handler: Arc<Handler>,
    ) -> Result<()> {
        let (reader, mut writer) = tokio::io::split(pipe);
        let mut lines = TokioBufReader::new(reader).lines();

        while let Some(line) = lines.next_line().await? {
            if line.trim().is_empty() {
                continue;
            }

            let handler = handler.clone();
            let line_clone = line.clone();
            
            // Run the blocking handler on a thread pool thread so it doesn't
            // block the tokio reactor while tunnel_connect is doing I/O
            let response = match tokio::task::spawn_blocking(move || {
                match serde_json::from_str::<Command>(&line_clone) {
                    Ok(command) => handler.handle(command),
                    Err(e) => super::protocol::Response::error(
                        "unknown", format!("Parse error: {e}")
                    ),
                }
            }).await {
                Ok(r) => r,
                Err(e) => super::protocol::Response::error(
                    "unknown", format!("Internal error: {e}")
                ),
            };

            let mut json = serde_json::to_string(&response)?;
            json.push('\n');
            writer.write_all(json.as_bytes()).await?;
        }

        Ok(())
    }
}