use crate::Error;
use std::env::var;
use std::future::Future;
use std::time::Duration;
use tokio::time::delay_for;

pub fn read_env(s: &str) -> Result<String, Error> {
    var(s).map_err(|e| Error::ReadVar(s.to_string(), e))
}

pub async fn check_every<F>(duration: Duration, check: impl Fn() -> F)
where
    F: Future<Output = ()>,
{
    loop {
        delay_for(duration).await;
        check().await;
    }
}
