use crate::{error::Error, system::VaultIdManager};
use bitcoin::BitcoinCoreApi;
use futures::future;
use runtime::{
    CollateralBalancesPallet, CurrencyIdExt, CurrencyInfo, FeedValuesEvent, InterBtcParachain, OracleKey, VaultId,
    VaultRegistryPallet, VaultStatus, H256,
};
use service::Error as ServiceError;

pub async fn maintain_collateralization_rate<B: BitcoinCoreApi + Clone + Send + Sync + 'static>(
    parachain_rpc: InterBtcParachain,
    vault_id_manager: VaultIdManager<B>,
) -> Result<(), ServiceError> {
    let parachain_rpc = &parachain_rpc;
    let vault_id_manager = &vault_id_manager;
    parachain_rpc
        .on_event::<FeedValuesEvent, _, _, _>(
            |event| async move {
                let updated_currencies = event.values.iter().filter_map(|(key, _value)| match key {
                    OracleKey::ExchangeRate(currency_id) => Some(currency_id),
                    _ => None,
                });
                let vault_ids = vault_id_manager.get_vault_ids().await;
                for currency_id in updated_currencies {
                    match vault_ids
                        .iter()
                        .find(|vault_id| &vault_id.collateral_currency() == currency_id)
                    {
                        None => tracing::debug!(
                            "Ignoring exchange rate update for {}",
                            currency_id.inner().map(|i| i.symbol().to_string()).unwrap_or_default()
                        ),
                        Some(vault_id) => {
                            tracing::info!(
                                "Received FeedValuesEvent for {}",
                                currency_id.inner().map(|i| i.symbol().to_string()).unwrap_or_default()
                            );

                            // TODO: implement retrying
                            if let Err(e) = lock_required_collateral(parachain_rpc.clone(), vault_id.clone()).await {
                                tracing::error!("Failed to maintain collateral level: {}", e);
                            }
                        }
                    }
                }
            },
            |error| tracing::error!("Error reading SetExchangeRate event: {}", error.to_string()),
        )
        .await?;
    Ok(())
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
/// * `parachain_rpc` - the parachain RPC handle
/// * `vault_id` - the id of this vault
/// * `maximum_collateral` - the upperbound of total collateral that is allowed to be placed
pub async fn lock_required_collateral<P: VaultRegistryPallet + CollateralBalancesPallet>(
    parachain_rpc: P,
    vault_id: VaultId,
) -> Result<(), Error> {
    // check that the vault is registered and active
    let vault = parachain_rpc.get_vault(&vault_id).await?;
    if !matches!(vault.status, VaultStatus::Active(..)) {
        return Err(Error::RuntimeError(runtime::Error::VaultNotFound));
    }

    let actual_collateral = parachain_rpc.get_vault_total_collateral(vault_id.clone()).await?;

    let (required_collateral, maximum_collateral) = future::try_join(
        async {
            Ok(parachain_rpc
                .get_required_collateral_for_vault(vault_id.clone())
                .await?)
        },
        async {
            // allow all balance to be used as collateral
            let free = parachain_rpc.get_free_balance(vault_id.collateral_currency()).await?;
            free.checked_add(actual_collateral).ok_or(Error::ArithmeticOverflow)
        },
    )
    .await?;

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

    tracing::info!(
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
        tracing::info!("Locking additional collateral");
        parachain_rpc.deposit_collateral(&vault_id, amount_to_increase).await?;
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
        AccountId, Balance, BtcAddress, BtcPublicKey, CurrencyId, Error as RuntimeError, InterBtcVault, Token, DOT,
        IBTC,
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
            async fn get_vault(&self, vault_id: &VaultId) -> Result<InterBtcVault, RuntimeError>;
            async fn get_vaults_by_account_id(&self, account_id: &AccountId) -> Result<Vec<VaultId>, RuntimeError>;
            async fn get_all_vaults(&self) -> Result<Vec<InterBtcVault>, RuntimeError>;
            async fn register_vault(&self, vault_id: &VaultId, collateral: u128) -> Result<(), RuntimeError>;
            async fn deposit_collateral(&self, vault_id: &VaultId, amount: u128) -> Result<(), RuntimeError>;
            async fn withdraw_collateral(&self, vault_id: &VaultId, amount: u128) -> Result<(), RuntimeError>;
            async fn get_public_key(&self) -> Result<Option<BtcPublicKey>, RuntimeError>;
            async fn register_public_key(&self, public_key: BtcPublicKey) -> Result<(), RuntimeError>;
            async fn get_required_collateral_for_wrapped(&self, amount_btc: u128, collateral_currency: CurrencyId) -> Result<u128, RuntimeError>;
            async fn get_required_collateral_for_vault(&self, vault_id: VaultId) -> Result<u128, RuntimeError>;
            async fn get_vault_total_collateral(&self, vault_id: VaultId) -> Result<u128, RuntimeError>;
            async fn get_collateralization_from_vault(&self, vault_id: VaultId, only_issued: bool) -> Result<u128, RuntimeError>;
            async fn set_current_client_release(&self, uri: &[u8], code_hash: &H256) -> Result<(), RuntimeError>;
            async fn set_pending_client_release(&self, uri: &[u8], code_hash: &H256) -> Result<(), RuntimeError>;
        }

        #[async_trait]
        pub trait CollateralBalancesPallet {
            async fn get_free_balance(&self, currency_id: CurrencyId) -> Result<Balance, RuntimeError>;
            async fn get_free_balance_for_id(&self, id: AccountId, currency_id: CurrencyId) -> Result<Balance, RuntimeError>;
            async fn get_reserved_balance(&self, currency_id: CurrencyId) -> Result<Balance, RuntimeError>;
            async fn get_reserved_balance_for_id(&self, id: AccountId, currency_id: CurrencyId) -> Result<Balance, RuntimeError>;
            async fn transfer_to(&self, recipient: &AccountId, amount: u128, currency_id: CurrencyId) -> Result<(), RuntimeError>;
        }
    }

    impl Clone for MockProvider {
        fn clone(&self) -> Self {
            // NOTE: expectations dropped
            Self::default()
        }
    }

    fn setup_mocks(required: u128, actual: u128, max: u128) -> MockProvider {
        let mut parachain_rpc = MockProvider::default();
        parachain_rpc
            .expect_get_required_collateral_for_vault()
            .returning(move |_| Ok(required));

        parachain_rpc.expect_get_vault().returning(move |x| {
            Ok(InterBtcVault {
                id: x.clone(),
                status: VaultStatus::Active(true),
                banned_until: None,
                secure_collateral_threshold: None,
                to_be_issued_tokens: 0,
                issued_tokens: 0,
                to_be_redeemed_tokens: 0,
                to_be_replaced_tokens: 0,
                replace_collateral: 0,
                liquidated_collateral: 0,
                active_replace_collateral: 0,
            })
        });

        parachain_rpc
            .expect_get_vault_total_collateral()
            .returning(move |_| Ok(actual));

        parachain_rpc
            .expect_get_free_balance()
            .returning(move |_| Ok(if max > actual { max - actual } else { 0 }));

        parachain_rpc
    }

    fn dummy_vault_id() -> VaultId {
        VaultId::new(AccountId::new([1u8; 32]), Token(DOT), Token(IBTC))
    }

    #[tokio::test]
    async fn test_lock_required_collateral_case_1() {
        // case 1: required <= actual <= limit -- do nothing (already enough)
        // required = 50, actual = 75, max = 100:
        // check that deposit_collateral is not called
        let parachain_rpc = setup_mocks(50, 75, 100);

        assert_ok!(lock_required_collateral(parachain_rpc, dummy_vault_id()).await);
    }

    #[tokio::test]
    async fn test_lock_required_collateral_case_2() {
        // case 2: required <= limit <= actual -- do nothing (already enough)
        // required = 100, actual = 200, max = 150:
        // check that deposit_collateral is not called
        let parachain_rpc = setup_mocks(100, 200, 150);

        assert_ok!(lock_required_collateral(parachain_rpc, dummy_vault_id()).await);
    }

    #[tokio::test]
    async fn test_lock_required_collateral_case_3() {
        // case 3: limit <= required <= actual -- do nothing (already enough)
        // required = 100, actual = 150, max = 75:
        // check that deposit_collateral is not called
        let parachain_rpc = setup_mocks(100, 150, 75);

        assert_ok!(lock_required_collateral(parachain_rpc, dummy_vault_id()).await);
    }

    #[tokio::test]
    async fn test_lock_required_collateral_case_4() {
        // case 4: limit <= actual <= required -- do nothing (return error)
        // required = 100, actual = 75, max = 50:
        // check that deposit_collateral is not called
        let parachain_rpc = setup_mocks(100, 75, 50);

        assert_err!(
            lock_required_collateral(parachain_rpc, dummy_vault_id()).await,
            Error::InsufficientFunds
        );
    }

    #[tokio::test]
    async fn test_lock_required_collateral_case_5() {
        // case 5: actual <= limit <= required -- increase to limit (return error)
        // required = 100, actual = 25, max = 75: should add 50, but return err
        let mut parachain_rpc = setup_mocks(100, 25, 75);
        parachain_rpc
            .expect_deposit_collateral()
            .withf(|_, &amount| amount == 50)
            .times(1)
            .returning(|_, _| Ok(()));

        assert_err!(
            lock_required_collateral(parachain_rpc, dummy_vault_id()).await,
            Error::InsufficientFunds
        );
    }
    #[tokio::test]
    async fn test_lock_required_collateral_case_6() {
        // case 6: actual <= required <= limit -- increase to required (return ok)
        // required = 100, actual = 25, max = 200: should add 75
        let mut parachain_rpc = setup_mocks(100, 25, 200);
        parachain_rpc
            .expect_deposit_collateral()
            .withf(|_, &amount| amount == 75)
            .times(1)
            .returning(|_, _| Ok(()));

        assert_ok!(lock_required_collateral(parachain_rpc, dummy_vault_id()).await);
    }

    #[tokio::test]
    async fn test_lock_required_collateral_at_max_fails() {
        // required = 100, actual = 25, max = 25:
        // check that deposit_collateral is not called with amount 0
        let parachain_rpc = setup_mocks(100, 25, 25);

        assert_err!(
            lock_required_collateral(parachain_rpc, dummy_vault_id()).await,
            Error::InsufficientFunds
        );
    }

    #[tokio::test]
    async fn test_lock_required_collateral_at_required_succeeds() {
        // required = 100, actual = 100, max = 200:
        // check that deposit_collateral is not called with amount 0
        let parachain_rpc = setup_mocks(100, 100, 200);

        assert_ok!(lock_required_collateral(parachain_rpc, dummy_vault_id()).await);
    }

    #[tokio::test]
    async fn test_lock_required_collateral_with_unregistered_vault_fails() {
        let mut parachain_rpc = MockProvider::default();
        parachain_rpc.expect_get_vault().returning(move |x| {
            Ok(InterBtcVault {
                id: x.clone(),
                status: VaultStatus::Liquidated,
                banned_until: None,
                secure_collateral_threshold: None,
                to_be_issued_tokens: 0,
                issued_tokens: 0,
                to_be_redeemed_tokens: 0,
                to_be_replaced_tokens: 0,
                replace_collateral: 0,
                liquidated_collateral: 0,
                active_replace_collateral: 0,
            })
        });

        assert_err!(
            lock_required_collateral(parachain_rpc, dummy_vault_id()).await,
            Error::RuntimeError(runtime::Error::VaultNotFound)
        );
    }
}
