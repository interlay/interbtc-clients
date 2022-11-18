use std::sync::{Arc, RwLock};
use tokio::sync::broadcast::error::{RecvError, SendError};

/// A wrapper arround a tokio broadcast channel that makes sure that
/// listeners created after a shutdown signal has already been sent
/// also receive the shutdown signal.
#[derive(Clone)]
pub struct ShutdownSender {
    pub sent_shutdown: Arc<RwLock<bool>>,
    pub channel: tokio::sync::broadcast::Sender<()>,
}

impl ShutdownSender {
    pub fn new() -> Self {
        let (shutdown_tx, _) = tokio::sync::broadcast::channel(16);
        Self {
            sent_shutdown: Arc::new(RwLock::new(false)),
            channel: shutdown_tx,
        }
    }

    pub fn send(&self, value: ()) -> Result<usize, SendError<()>> {
        // Record that we sent the signal for listeners created in the future.
        // Note that unwrap is suitable here since the read only fails if a thread
        // holding the lock has panicked, in which case propagating the panic is
        // generally advised to prevent operating on unexpected state.
        *self.sent_shutdown.write().unwrap() = true;

        self.channel.send(value)
    }

    pub fn subscribe(&self) -> ShutdownReceiver {
        let subscription = self.channel.subscribe();
        // Check if signal was already sent before we started listening.
        // Note that unwrap is suitable here since the read only fails if a thread
        // holding the lock has panicked, in which case propagating the panic is
        // generally advised to prevent operating on unexpected state.
        let sent = *self.sent_shutdown.read().unwrap();
        ShutdownReceiver {
            received_shutdown: sent,
            inner: subscription,
        }
    }

    pub fn receiver_count(&self) -> usize {
        self.channel.receiver_count()
    }
}

impl Default for ShutdownSender {
    fn default() -> Self {
        Self::new()
    }
}

pub struct ShutdownReceiver {
    received_shutdown: bool,
    inner: tokio::sync::broadcast::Receiver<()>,
}

impl ShutdownReceiver {
    pub async fn recv(&mut self) -> Result<(), RecvError> {
        if self.received_shutdown {
            Ok(())
        } else {
            self.inner.recv().await
        }
    }
}
