use crate::error::Error;
use log::*;
use runtime::{
    pallets::exchange_rate_oracle::SetExchangeRateEvent, DotBalancesPallet, PolkaBtcProvider,
    PolkaBtcRuntime, VaultRegistryPallet,
};
use sp_core::crypto::AccountId32;
use std::sync::Arc;

pub async fn maintain_collateralization_rate(
    provider: Arc<PolkaBtcProvider>,
    vault_id: AccountId32,
    maximum_collateral: u128,
) -> Result<(), runtime::Error> {
    let provider = &provider;
    let vault_id = &vault_id;
    provider
        .on_event::<SetExchangeRateEvent<PolkaBtcRuntime>, _, _, _>(
            |_| async move {
                info!("Received SetExchangeRateEvent");
                // todo: implement retrying
                if let Err(e) =
                    lock_required_collateral(provider.clone(), vault_id.clone(), maximum_collateral)
                        .await
                {
                    error!("Failed to maintain collateral level: {}", e);
                }
            },
            |error| error!("Error reading SetExchangeRate event: {}", error.to_string()),
        )
        .await
}

pub async fn lock_required_collateral(
    provider: Arc<PolkaBtcProvider>,
    vault_id: AccountId32,
    maximum_collateral: u128,
) -> Result<(), Error> {
    let required_collateral = provider
        .get_required_collateral_for_vault(vault_id.clone())
        .await?;
    let actual_collateral = provider.get_reserved_dot_balance().await?;

    // only increase upto `maximum_collataral`
    let target_collateral = if required_collateral <= maximum_collateral {
        required_collateral
    } else {
        info!("Unable to maintain collateralization rate due to set limit");
        maximum_collateral
    };

    trace!(
        "Current collateral = {}; required = {}; max = {}",
        actual_collateral,
        required_collateral,
        maximum_collateral
    );

    // if we should add more collateral
    if actual_collateral < target_collateral {
        let amount_to_increase = target_collateral - actual_collateral;
        info!("Locking additional collateral");
        provider
            .lock_additional_collateral(amount_to_increase)
            .await?;
    }

    Ok(())
}
