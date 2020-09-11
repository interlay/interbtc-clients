use crate::rpc::Error;
use log::{error, info};
use std::future::Future;
use std::time::Duration;
use tokio::time::delay_for;

pub async fn check_status<F>(duration: Duration, verify: impl Fn() -> F)
where
    F: Future<Output = Result<bool, Error>>,
{
    loop {
        delay_for(duration).await;
        match verify().await {
            Ok(offline) => {
                if offline {
                    info!("Offline");
                } else {
                    info!("Online");
                }
            }
            Err(_) => {
                error!("Failed to check status");
            }
        };
    }
}
