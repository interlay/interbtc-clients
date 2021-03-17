use crate::Error;
use futures::future;
use runtime::{StakedRelayerPallet, UtilFuncs, MINIMUM_STAKE};
use std::time::Duration;
use tokio::time::delay_for;

pub async fn is_registered<P: StakedRelayerPallet + UtilFuncs>(provider: &P) -> Result<bool, Error> {
    let account_id = provider.get_account_id();
    // get stake returns 0 if not registered, so check that either active or inactive stake is non-zero
    let (active_stake, inactive_stake) = future::try_join(
        provider.get_active_stake_by_id(account_id.clone()),
        provider.get_inactive_stake_by_id(account_id.clone()),
    )
    .await?;
    let total_stake = active_stake.saturating_add(inactive_stake);
    Ok(total_stake >= MINIMUM_STAKE)
}

pub async fn wait_until_registered<P: StakedRelayerPallet + UtilFuncs>(provider: &P, delay: Duration) {
    // TODO: listen for register event
    loop {
        if is_registered(provider).await.unwrap_or(false) {
            return;
        }
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
