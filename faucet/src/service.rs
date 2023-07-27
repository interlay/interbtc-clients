use futures::{future::Either, Future, FutureExt};
pub use runtime::ShutdownSender;

pub async fn on_shutdown(shutdown_tx: ShutdownSender, future2: impl Future) {
    let mut shutdown_rx = shutdown_tx.subscribe();
    let future1 = shutdown_rx.recv().fuse();

    let _ = future1.await;
    future2.await;
}

pub async fn wait_or_shutdown<F, E>(shutdown_tx: ShutdownSender, future2: F) -> Result<(), E>
where
    F: Future<Output = Result<(), E>>,
{
    match run_cancelable(shutdown_tx.subscribe(), future2).await {
        TerminationStatus::Cancelled => {
            tracing::trace!("Received shutdown signal");
            Ok(())
        }
        TerminationStatus::Completed(res) => {
            tracing::trace!("Sending shutdown signal");
            let _ = shutdown_tx.send(());
            res
        }
    }
}
