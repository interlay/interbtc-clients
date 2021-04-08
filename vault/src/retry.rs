use backoff::{backoff::Backoff, ExponentialBackoff};
use futures::Future;
use log::warn;
use runtime::Error as RuntimeError;
use std::time::Duration;

/// Gets the default retrying policy. This should be used for unexpected errors, not for operations
/// that are expected to take a while to succeed. That is, it is unsuitable for e.g. awaiting bitcoin
/// confirmation proof, due to potentially high retrying time.
/// Note: technically this is not a constant due to the use of `Default::default()`
fn get_exponential_backoff() -> ExponentialBackoff {
    ExponentialBackoff {
        max_elapsed_time: Some(Duration::from_secs(24 * 60 * 60)),
        max_interval: Duration::from_secs(60 * 60), // wait at most an hour before retrying
        initial_interval: Duration::from_secs(1),
        current_interval: Duration::from_secs(1),
        multiplier: 2.0,            // delay doubles every time
        randomization_factor: 0.25, // random value between 25% below and 25% above the ideal delay
        ..Default::default()
    }
}

pub enum RetryPolicy<E> {
    Skip(E),
    Throw(E),
}

pub async fn notify_retry_all<L, F, T>(call: L) -> Result<T, RuntimeError>
where
    L: Fn() -> F,
    F: Future<Output = Result<T, RuntimeError>>,
{
    notify_retry(call, |res| res.map_err(RetryPolicy::Skip)).await
}

pub async fn notify_retry<L, F, R, T>(call: L, verify: R) -> Result<T, RuntimeError>
where
    L: Fn() -> F,
    F: Future<Output = Result<T, RuntimeError>>,
    R: Fn(Result<T, RuntimeError>) -> Result<T, RetryPolicy<RuntimeError>>,
{
    let mut backoff = get_exponential_backoff();
    loop {
        let err = match verify(call().await) {
            Ok(ok) => return Ok(ok),
            Err(RetryPolicy::Skip(err)) => err,
            Err(RetryPolicy::Throw(err)) => return Err(err),
        };

        match backoff.next_backoff() {
            Some(wait) => {
                // error occurred, sleep before retrying
                warn!("{:?} - next retry in {:.3} s", err, wait.as_secs_f64());
                tokio::time::delay_for(wait).await;
            }
            None => break Err(RuntimeError::Timeout),
        }
    }
}
