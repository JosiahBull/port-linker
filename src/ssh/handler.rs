use russh::client::Handler;
use russh::keys::PublicKey;
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

impl Handler for ClientHandler {
    type Error = russh::Error;

    fn check_server_key(
        &mut self,
        server_public_key: &PublicKey,
    ) -> impl std::future::Future<Output = Result<bool, Self::Error>> + Send {
        let key = self.server_public_key.clone();
        let server_public_key = server_public_key.clone();
        async move {
            let mut lock = key.lock().await;
            *lock = Some(server_public_key);
            // In production, you'd verify against known_hosts
            // For now, accept all keys (like ssh -o StrictHostKeyChecking=no)
            Ok(true)
        }
    }
}
