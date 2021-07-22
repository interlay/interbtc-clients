use crate::Error;
use backoff::{backoff::Backoff, ExponentialBackoff};
use futures::Future;
use std::{fmt::Debug, time::Duration};

/// Gets the default retrying policy. This should be used for unexpected errors, not for operations
/// that are expected to take a while to succeed. That is, it is unsuitable for e.g. awaiting bitcoin
/// confirmation proof, due to potentially high retrying time.
/// Note: technically this is not a constant due to the use of `Default::default()`
fn get_exponential_backoff() -> ExponentialBackoff {
    ExponentialBackoff {
        max_elapsed_time: Some(Duration::from_secs(60 * 10)), // retry for at most 10 minutes
        max_interval: Duration::from_secs(60 * 2),            // only delay up to 2 minutes
        initial_interval: Duration::from_secs(1),             // first retry after 1 second
        current_interval: Duration::from_secs(1),             // increasing interval duration
        multiplier: 2.0,                                      // delay doubles every time
        randomization_factor: 0.25,                           // add random value within 25%
        ..Default::default()
    }
}

pub enum RetryPolicy<E> {
    Skip(E),
    Throw(E),
}

pub async fn notify_retry<E, L, FL, R, FR, T>(call: L, verify: R) -> Result<T, Error>
where
    E: Debug,
    L: Fn() -> FL,
    FL: Future<Output = Result<T, E>>,
    R: Fn(Result<T, E>) -> FR,
    FR: Future<Output = Result<T, RetryPolicy<Error>>>,
{
    let mut backoff = get_exponential_backoff();
    loop {
        let err = match verify(call().await).await {
            Ok(ok) => return Ok(ok),
            Err(RetryPolicy::Skip(err)) => err,
            Err(RetryPolicy::Throw(err)) => return Err(err),
        };

        match backoff.next_backoff() {
            Some(wait) => {
                // error occurred, sleep before retrying
                log::warn!("{:?} - next retry in {:.3} s", err, wait.as_secs_f64());
                tokio::time::sleep(wait).await;
            }
            None => break Err(Error::Timeout),
        }
    }
}
