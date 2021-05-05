use runtime::{Error as RuntimeError, StakedRelayerPallet, UtilFuncs, MINIMUM_STAKE};
use std::time::Duration;
use tokio::time::delay_for;

pub async fn is_registered<P: StakedRelayerPallet + UtilFuncs>(provider: &P) -> Result<bool, RuntimeError> {
    let stake = provider.get_stake_of(&provider.get_account_id()).await?;
    // get stake returns 0 if not registered, so check if the stake is above some threshold
    Ok(stake >= MINIMUM_STAKE)
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
