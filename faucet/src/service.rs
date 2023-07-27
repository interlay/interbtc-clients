use futures::{future::Either, Future, FutureExt};
pub use runtime::{ShutdownReceiver, ShutdownSender};

pub enum TerminationStatus<Res> {
    Cancelled,
    Completed(Res),
}

pub async fn on_shutdown(shutdown_tx: ShutdownSender, future2: impl Future) {
    let mut shutdown_rx = shutdown_tx.subscribe();
    let future1 = shutdown_rx.recv().fuse();

    let _ = future1.await;
    future2.await;
}

async fn run_cancelable<F, Res>(mut shutdown_rx: ShutdownReceiver, future2: F) -> TerminationStatus<Res>
where
    F: Future<Output = Res>,
{
    let future1 = shutdown_rx.recv().fuse();
    let future2 = future2.fuse();

    futures::pin_mut!(future1);
    futures::pin_mut!(future2);

    match futures::future::select(future1, future2).await {
        Either::Left((_, _)) => TerminationStatus::Cancelled,
        Either::Right((res, _)) => TerminationStatus::Completed(res),
    }
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
