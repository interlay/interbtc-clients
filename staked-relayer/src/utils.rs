use crate::Error;
use log::error;
use runtime::{StakedRelayerPallet, MINIMUM_STAKE};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::delay_for;

pub async fn check_every<F>(duration: Duration, check: impl Fn() -> F)
where
    F: Future<Output = Result<(), Error>>,
{
    loop {
        delay_for(duration).await;
        if let Err(e) = check().await {
            error!("Error: {}", e.to_string());
        }
    }
}

pub async fn is_registered<P: StakedRelayerPallet>(polka_rpc: &Arc<P>) -> bool {
    polka_rpc.get_stake().await.unwrap_or(0) >= MINIMUM_STAKE
}

pub async fn wait_until_registered<P: StakedRelayerPallet>(polka_rpc: &Arc<P>, delay: Duration) {
    loop {
        if is_registered(polka_rpc).await {
            return;
        }
        delay_for(delay).await;
    }
}
