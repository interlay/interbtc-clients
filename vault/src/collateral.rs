use crate::error::Error;
use log::*;
use runtime::{
    pallets::exchange_rate_oracle::SetExchangeRateEvent, pallets::vault_registry::VaultStatus,
    AccountId, DotBalancesPallet, PolkaBtcProvider, PolkaBtcRuntime, VaultRegistryPallet,
};
use std::sync::Arc;

pub async fn maintain_collateralization_rate(
    provider: Arc<PolkaBtcProvider>,
    maximum_collateral: u128,
) -> Result<(), runtime::Error> {
    let provider = &provider;
    provider
        .on_event::<SetExchangeRateEvent<PolkaBtcRuntime>, _, _, _>(
            |_| async move {
                info!("Received SetExchangeRateEvent");
                // todo: implement retrying

                match lock_required_collateral(
                    provider.clone(),
                    provider.get_account_id().clone(),
                    maximum_collateral,
                )
                .await
                {
                    // vault not being registered is ok, no need to log it
                    Err(Error::RuntimeError(runtime::Error::VaultNotFound)) => {}
                    Err(e) => error!("Failed to maintain collateral level: {}", e),
                    _ => {} // success
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
/// If the vault is not registered and active, it does not attempt to increase the
/// collateral.
///
/// # Arguments
///
/// * `provider` - the parachain RPC handle
/// * `vault_id` - the id of this vault
/// * `maximum_collateral` - the upperbound of total collateral that is allowed to be placed
pub async fn lock_required_collateral<P: VaultRegistryPallet + DotBalancesPallet>(
    provider: Arc<P>,
    vault_id: AccountId,
    maximum_collateral: u128,
) -> Result<(), Error> {
    // check that the vault is registered and active
    let vault = provider.get_vault(vault_id.clone()).await?;
    if vault.status != VaultStatus::Active {
        return Err(Error::RuntimeError(runtime::Error::VaultNotFound));
    }

    let required_collateral = provider
        .get_required_collateral_for_vault(vault_id.clone())
        .await?;
    let actual_collateral = provider.get_reserved_dot_balance().await?;

    // we have 6 possible orderings of (required, actual, limit):
    // case 1: required <= actual <= limit // do nothing (already enough)
    // case 2: required <= limit <= actual // do nothing (already enough)
    // case 3: limit <= required <= actual // do nothing (already enough)
    // case 4: limit <= actual <= required // do nothing (return error)
    // case 5: actual <= limit <= required // increase to limit (return error)
    // case 6: actual <= required <= limit // increase to required (return ok)

    // cases 1-3: already have enough collateral
    if actual_collateral >= required_collateral {
        return Ok(());
    }

    trace!(
        "Current collateral = {}; required = {}; max = {}",
        actual_collateral,
        required_collateral,
        maximum_collateral
    );

    // only increase upto `maximum_collataral`
    let target_collateral = if required_collateral <= maximum_collateral {
        required_collateral
    } else {
        maximum_collateral
    };

    // if we can add more collateral
    if actual_collateral < target_collateral {
        // cases 5 & 6
        let amount_to_increase = target_collateral - actual_collateral;
        info!("Locking additional collateral");
        provider
            .lock_additional_collateral(amount_to_increase)
            .await?;
    }

    // if we were unable to add the required amount, return error
    if required_collateral > maximum_collateral {
        // cases 4 & 5
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
        pallets::Core, AccountId, BtcAddress, Error as RuntimeError, PolkaBtcRuntime, PolkaBtcVault,
    };

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
            async fn register_vault(&self, collateral: u128, btc_address: BtcAddress) -> Result<(), RuntimeError>;
            async fn lock_additional_collateral(&self, amount: u128) -> Result<(), RuntimeError>;
            async fn withdraw_collateral(&self, amount: u128) -> Result<(), RuntimeError>;
            async fn update_btc_address(&self, address: BtcAddress) -> Result<(), RuntimeError>;
            async fn get_required_collateral_for_polkabtc(&self, amount_btc: u128) -> Result<u128, RuntimeError>;
            async fn get_required_collateral_for_vault(&self, vault_id: AccountId) -> Result<u128, RuntimeError>;
            async fn is_vault_below_auction_threshold(&self, vault_id: AccountId) -> Result<bool, RuntimeError>;
        }

        #[async_trait]
        pub trait DotBalancesPallet {
            async fn get_free_dot_balance(&self) -> Result<<PolkaBtcRuntime as Core>::Balance, RuntimeError>;
            async fn get_reserved_dot_balance(&self) -> Result<<PolkaBtcRuntime as Core>::Balance, RuntimeError>;
            async fn transfer_to(&self, destination: AccountId, amount: u128) -> Result<(), RuntimeError>;
        }
    }

    #[tokio::test]
    async fn test_lock_required_collateral_case_1() {
        // case 1: required <= actual <= limit -- do nothing (already enough)
        // required = 50, actual = 75, max = 100:
        // check that lock_additional_collateral is not called
        let mut provider = MockProvider::default();
        provider.expect_get_vault().returning(|x| {
            Ok(PolkaBtcVault {
                id: x,
                status: VaultStatus::Active,
                ..Default::default()
            })
        });
        provider
            .expect_get_required_collateral_for_vault()
            .returning(|_| Ok(50));
        provider
            .expect_get_reserved_dot_balance()
            .returning(|| Ok(75));

        let vault_id = AccountId::default();
        assert_ok!(lock_required_collateral(Arc::new(provider), vault_id, 100).await);
    }

    #[tokio::test]
    async fn test_lock_required_collateral_case_2() {
        // case 2: required <= limit <= actual -- do nothing (already enough)
        // required = 100, actual = 200, max = 150:
        // check that lock_additional_collateral is not called
        let mut provider = MockProvider::default();
        provider.expect_get_vault().returning(|x| {
            Ok(PolkaBtcVault {
                id: x,
                status: VaultStatus::Active,
                ..Default::default()
            })
        });
        provider
            .expect_get_required_collateral_for_vault()
            .returning(|_| Ok(100));
        provider
            .expect_get_reserved_dot_balance()
            .returning(|| Ok(200));

        let vault_id = AccountId::default();
        assert_ok!(lock_required_collateral(Arc::new(provider), vault_id, 150).await);
    }

    #[tokio::test]
    async fn test_lock_required_collateral_case_3() {
        // case 3: limit <= required <= actual -- do nothing (already enough)
        // required = 100, actual = 150, max = 75:
        // check that lock_additional_collateral is not called
        let mut provider = MockProvider::default();
        provider.expect_get_vault().returning(|x| {
            Ok(PolkaBtcVault {
                id: x,
                status: VaultStatus::Active,
                ..Default::default()
            })
        });
        provider
            .expect_get_required_collateral_for_vault()
            .returning(|_| Ok(100));
        provider
            .expect_get_reserved_dot_balance()
            .returning(|| Ok(150));

        let vault_id = AccountId::default();
        assert_ok!(lock_required_collateral(Arc::new(provider), vault_id, 75).await);
    }

    #[tokio::test]
    async fn test_lock_required_collateral_case_4() {
        // case 4: limit <= actual <= required -- do nothing (return error)
        // required = 100, actual = 75, max = 50:
        // check that lock_additional_collateral is not called
        let mut provider = MockProvider::default();
        provider.expect_get_vault().returning(|x| {
            Ok(PolkaBtcVault {
                id: x,
                status: VaultStatus::Active,
                ..Default::default()
            })
        });
        provider
            .expect_get_required_collateral_for_vault()
            .returning(|_| Ok(100));
        provider
            .expect_get_reserved_dot_balance()
            .returning(|| Ok(75));

        let vault_id = AccountId::default();
        assert_err!(
            lock_required_collateral(Arc::new(provider), vault_id, 50).await,
            Error::InsufficientFunds
        );
    }

    #[tokio::test]
    async fn test_lock_required_collateral_case_5() {
        // case 5: actual <= limit <= required -- increase to limit (return error)
        // required = 100, actual = 25, max = 75: should add 50, but return err
        let mut provider = MockProvider::default();
        provider.expect_get_vault().returning(|x| {
            Ok(PolkaBtcVault {
                id: x,
                status: VaultStatus::Active,
                ..Default::default()
            })
        });
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

        let vault_id = AccountId::default();
        assert_err!(
            lock_required_collateral(Arc::new(provider), vault_id, 75).await,
            Error::InsufficientFunds
        );
    }
    #[tokio::test]
    async fn test_lock_required_collateral_case_6() {
        // case 6: actual <= required <= limit -- increase to required (return ok)
        // required = 100, actual = 25, max = 200: should add 75
        let mut provider = MockProvider::default();
        provider.expect_get_vault().returning(|x| {
            Ok(PolkaBtcVault {
                id: x,
                status: VaultStatus::Active,
                ..Default::default()
            })
        });
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

        let vault_id = AccountId::default();
        assert_ok!(lock_required_collateral(Arc::new(provider), vault_id, 200).await);
    }

    #[tokio::test]
    async fn test_lock_required_collateral_at_max_fails() {
        // required = 100, actual = 25, max = 25:
        // check that lock_additional_collateral is not called with amount 0
        let mut provider = MockProvider::default();
        provider.expect_get_vault().returning(|x| {
            Ok(PolkaBtcVault {
                id: x,
                status: VaultStatus::Active,
                ..Default::default()
            })
        });
        provider
            .expect_get_required_collateral_for_vault()
            .returning(|_| Ok(100));
        provider
            .expect_get_reserved_dot_balance()
            .returning(|| Ok(25));

        let vault_id = AccountId::default();
        assert_err!(
            lock_required_collateral(Arc::new(provider), vault_id, 25).await,
            Error::InsufficientFunds
        );
    }

    #[tokio::test]
    async fn test_lock_required_collateral_at_required_succeeds() {
        // required = 100, actual = 100, max = 200:
        // check that lock_additional_collateral is not called with amount 0
        let mut provider = MockProvider::default();
        provider.expect_get_vault().returning(|x| {
            Ok(PolkaBtcVault {
                id: x,
                status: VaultStatus::Active,
                ..Default::default()
            })
        });
        provider
            .expect_get_required_collateral_for_vault()
            .returning(|_| Ok(100));
        provider
            .expect_get_reserved_dot_balance()
            .returning(|| Ok(100));

        let vault_id = AccountId::default();
        assert_ok!(lock_required_collateral(Arc::new(provider), vault_id, 200).await);
    }

    #[tokio::test]
    async fn test_lock_required_collateral_with_unregistered_vault_fails() {
        let mut provider = MockProvider::default();
        provider.expect_get_vault().returning(|x| {
            Ok(PolkaBtcVault {
                id: x,
                status: VaultStatus::CommittedTheft,
                ..Default::default()
            })
        });

        let vault_id = AccountId::default();
        assert_err!(
            lock_required_collateral(Arc::new(provider), vault_id, 75).await,
            Error::RuntimeError(runtime::Error::VaultNotFound)
        );
    }
}
