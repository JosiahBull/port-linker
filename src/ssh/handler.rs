use async_trait::async_trait;
use russh::client::Handler;
use russh::keys::key::PublicKey;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Debug)]
pub struct ClientHandler {
    server_public_key: Arc<Mutex<Option<PublicKey>>>,
}

impl ClientHandler {
    pub fn new() -> Self {
        Self {
            server_public_key: Arc::new(Mutex::new(None)),
        }
    }
}

impl Default for ClientHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(&mut self, server_public_key: &PublicKey) -> Result<bool, Self::Error> {
        let mut key = self.server_public_key.lock().await;
        *key = Some(server_public_key.clone());
        // In production, you'd verify against known_hosts
        // For now, accept all keys (like ssh -o StrictHostKeyChecking=no)
        Ok(true)
    }
}
