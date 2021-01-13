use backoff::ExponentialBackoff;
use std::time::Duration;

/// Retry bitcoin ops for at most 24 hours
pub const BITCOIN_MAX_RETRYING_TIME: Duration = Duration::from_secs(24 * 60 * 60);

/// At startup we wait until a new block has arrived before we start event listeners.
/// This constant defines the rate at which we check whether the chain height has increased.
pub const CHAIN_HEIGHT_POLLING_INTERVAL: Duration = Duration::from_millis(500);

/// Gets the default retrying policy. This should be used for unexpected errors, not for operations
/// that are expected to take a while to succeed. That is, it is unsuitable for e.g. awaiting bitcoin
/// confirmation proof, due to potentially high retrying time.
/// Note: technically this is not a constant due to the use of `Default::default()`
pub fn get_retry_policy() -> ExponentialBackoff {
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
