use crate::rpc::Error;
use log::{error, info};
use std::future::Future;
use std::time::Duration;
use tokio::time::delay_for;

pub async fn check_every<F>(duration: Duration, check: impl Fn() -> F)
where
    F: Future<Output = ()>,
{
    loop {
        delay_for(duration).await;
        check().await;
    }
}
