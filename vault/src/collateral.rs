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

/// Gets the required collateral for this vault, and if it is more than the actual
/// collateral (which can happen when the exchange rate changes), attempts to
/// increase up to maximum_collateral.
/// If actual_collateral < max_collateral < required_collateral, it will lock upto
/// max_collateral, but it will return InsufficientFunds afterwards.
///
/// # Arguments
///
/// * `provider` - the parachain RPC handle
/// * `vault_id` - the id of this vault
/// * `maximum_collateral` - the upperbound of total collateral that is allowed to be placed
pub async fn lock_required_collateral<P: VaultRegistryPallet + DotBalancesPallet>(
    provider: Arc<P>,
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

    // if we were unable to add the required amount, return error
    if required_collateral > maximum_collateral {
        Err(Error::InsufficientFunds)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use runtime::{
        pallets::Core, AccountId, Error as RuntimeError, H256Le, PolkaBtcRuntime, PolkaBtcVault,
    };
    use sp_core::{H160, H256};

    macro_rules! assert_ok {
        ( $x:expr $(,)? ) => {
            let is = $x;
            match is {
                Ok(_) => (),
                _ => assert!(false, "Expected Ok(_). Got {:#?}", is),
            }
        };
        ( $x:expr, $y:expr $(,)? ) => {
            assert_eq!($x, Ok($y));
        };
    }

    macro_rules! assert_err {
        ($result:expr, $err:pat) => {{
            match $result {
                Err($err) => (),
                Ok(v) => panic!("assertion failed: Ok({:?})", v),
                _ => panic!("expected: Err($err)"),
            }
        }};
    }

    mockall::mock! {
        Provider {}

        #[async_trait]
        pub trait VaultRegistryPallet {
            async fn get_vault(&self, vault_id: AccountId) -> Result<PolkaBtcVault, RuntimeError>;
            async fn get_all_vaults(&self) -> Result<Vec<PolkaBtcVault>, RuntimeError>;
            async fn register_vault(&self, collateral: u128, btc_address: H160) -> Result<(), RuntimeError>;
            async fn lock_additional_collateral(&self, amount: u128) -> Result<(), RuntimeError>;
            async fn withdraw_collateral(&self, amount: u128) -> Result<(), RuntimeError>;
            async fn update_btc_address(&self, address: H160) -> Result<(), RuntimeError>;
            async fn get_required_collateral_for_polkabtc(&self, amount_btc: u128) -> Result<u128, RuntimeError>;
            async fn get_required_collateral_for_vault(&self, vault_id: AccountId) -> Result<u128, RuntimeError>;
            async fn is_vault_below_auction_threshold(&self, vault_id: AccountId) -> Result<bool, RuntimeError>;
        }

        #[async_trait]
        pub trait DotBalancesPallet {
            async fn get_free_dot_balance(&self) -> Result<<PolkaBtcRuntime as Core>::Balance, RuntimeError>;
            async fn get_reserved_dot_balance(&self) -> Result<<PolkaBtcRuntime as Core>::Balance, RuntimeError>;
        }
    }

    #[tokio::test]
    async fn test_lock_required_collateral_with_high_max_succeeds() {
        // required = 100, actual = 25, max = 200: should add 75
        let mut provider = MockProvider::default();
        provider
            .expect_get_required_collateral_for_vault()
            .returning(|_| Ok(100));
        provider
            .expect_get_reserved_dot_balance()
            .returning(|| Ok(25));
        provider
            .expect_lock_additional_collateral()
            .withf(|&amount| amount == 75)
            .times(1)
            .returning(|_| Ok(()));

        let vault_id = AccountId32::default();
        assert_ok!(lock_required_collateral(Arc::new(provider), vault_id, 200).await);
    }

    #[tokio::test]
    async fn test_lock_required_collateral_with_low_max_fails() {
        // required = 100, actual = 25, max = 75: should add 50, but return err
        let mut provider = MockProvider::default();
        provider
            .expect_get_required_collateral_for_vault()
            .returning(|_| Ok(100));
        provider
            .expect_get_reserved_dot_balance()
            .returning(|| Ok(25));
        provider
            .expect_lock_additional_collateral()
            .withf(|&amount| amount == 50)
            .times(1)
            .returning(|_| Ok(()));

        let vault_id = AccountId32::default();
        assert_err!(
            lock_required_collateral(Arc::new(provider), vault_id, 75).await,
            Error::InsufficientFunds
        );
    }

    #[tokio::test]
    async fn test_lock_required_collateral_with_sufficient_collateral_succeeds() {
        // required = 100, actual = 100, max = 200:
        // check that lock_additional_collateral is not called
        let mut provider = MockProvider::default();
        provider
            .expect_get_required_collateral_for_vault()
            .returning(|_| Ok(100));
        provider
            .expect_get_reserved_dot_balance()
            .returning(|| Ok(100));

        let vault_id = AccountId32::default();
        assert_ok!(lock_required_collateral(Arc::new(provider), vault_id, 200).await);
    }

    #[tokio::test]
    async fn test_lock_required_collateral_at_max_fails() {
        // required = 100, actual = 25, max = 25:
        // check that lock_additional_collateral is not called
        let mut provider = MockProvider::default();
        provider
            .expect_get_required_collateral_for_vault()
            .returning(|_| Ok(100));
        provider
            .expect_get_reserved_dot_balance()
            .returning(|| Ok(25));

        let vault_id = AccountId32::default();
        assert_err!(
            lock_required_collateral(Arc::new(provider), vault_id, 25).await,
            Error::InsufficientFunds
        );
    }
}
