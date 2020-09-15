use crate::rpc::Error;
use futures::stream::{FuturesUnordered, StreamExt};
use log::{error, info};
use std::future::Future;
use std::time::Duration;
use tokio::time::delay_for;

pub async fn check_until_true<F, R>(duration: Duration, check: impl Fn() -> F) -> R
where
    F: Future<Output = (bool, R)>,
{
    loop {
        info!("checking...");
        delay_for(duration).await;
        let result = check().await;
        if result.0 {
            return result.1;
        }
    }
}

pub async fn run_all<F1, F2, R>(mut workers: FuturesUnordered<F1>, report: impl Fn(R) -> F2)
where
    F1: Future<Output = R>,
    F2: Future<Output = ()>,
{
    loop {
        match workers.next().await {
            Some(result) => {
                report(result).await;
            }
            None => {
                println!("Done!");
                break;
            }
        }
    }
}
