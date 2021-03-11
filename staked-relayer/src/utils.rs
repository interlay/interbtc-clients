use crate::Error;
use runtime::{StakedRelayerPallet, UtilFuncs, MINIMUM_STAKE};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::delay_for;

pub async fn check_every<F>(duration: Duration, check: impl Fn() -> F) -> Result<(), Error>
where
    F: Future<Output = Result<(), Error>>,
{
    loop {
        delay_for(duration).await;
        check().await?;
    }
}

pub async fn is_registered<P: StakedRelayerPallet + UtilFuncs>(
    provider: &Arc<P>,
) -> Result<bool, Error> {
    let account_id = provider.get_account_id();
    // get stake returns 0 if not registered, so check that either active or inactive stake is non-zero
    let mut total_stake = provider.get_active_stake_by_id(account_id.clone()).await?;
    total_stake = total_stake.saturating_add(
        provider
            .get_inactive_stake_by_id(account_id.clone())
            .await?,
    );
    Ok(total_stake >= MINIMUM_STAKE)
}

pub async fn wait_until_registered<P: StakedRelayerPallet + UtilFuncs>(
    provider: &Arc<P>,
    delay: Duration,
) {
    // TODO: listen for register event
    loop {
        if is_registered(provider).await.unwrap_or(false) {
            return;
        }
        println!("not registered");
        delay_for(delay).await;
    }
}

pub async fn is_active<P: StakedRelayerPallet>(provider: &P) -> Result<bool, Error> {
    Ok(provider.get_active_stake().await? >= MINIMUM_STAKE)
}

pub async fn wait_until_active<P: StakedRelayerPallet>(provider: &P, delay: Duration) {
    // TODO: add bond event and listen
    loop {
        if is_active(provider).await.unwrap_or(false) {
            return;
        }
        delay_for(delay).await;
    }
}
