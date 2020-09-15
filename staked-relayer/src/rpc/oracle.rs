use super::Error;

#[cfg(not(test))]
use super::Provider;

#[cfg(test)]
use super::mock::Provider;

use super::PolkaBTCVault;

#[derive(Clone)]
pub struct OracleChecker {
    pub(crate) rpc: Provider,
}

impl OracleChecker {
    /// Verify that the oracle is offline
    pub async fn is_oracle_offline(&self) -> Result<bool, Error> {
        let get_info = self.rpc.get_exchange_rate_info();
        let get_time = self.rpc.get_time_now();
        let result = tokio::try_join!(get_info, get_time);
        match result {
            Ok(((_rate, last, delay), now)) => Ok(last + delay < now),
            Err(_) => Err(Error::CheckOracleOffline),
        }
    }

    // pub async fn is_vault_undercollateralized(&self, vault: PolkaBTCVault) -> Result<(), Error> {
    //     // get the currently locked collateral for the vault
    //     let collateral_in_dot = self.rpc.get_account_data(vault.id).await?.reserved;
    //     // get the current threshold for the collateral
    //     // NOTE: The liquidation threshold expresses the percentage of minimum collateral
    //     // level required for the vault. If the vault is under this percentage,
    //     // the vault is flagged for liquidation.
    //     let liquidation_collateral_threshold = self.rpc.get_liquidation_threshold().await?;

    //     // calculate how much PolkaBTC the vault should maximally have considering
    //     // the liquidation threshold.
    //     // NOTE: if the division fails, return 0 as maximum amount
    //     let max_polka_btc_in_dot =
    //         match collateral_in_dot.checked_div(liquidation_collateral_threshold) {
    //             Some(v) => v,
    //             None => 0,
    //         };

    //     // get the currently issued tokens of the vault
    //     let amount_btc_in_dot = ext::oracle::btc_to_dots::<T>(vault.issued_tokens)?;

    //     // // Ensure that the current amount of PolkaBTC (in DOT) is greater than
    //     // // the allowed maximum of issued tokens to flag the vault for liquidation
    //     // ensure!(
    //     //     max_polka_btc_in_dot < raw_amount_btc_in_dot,
    //     //     Error::<T>::CollateralOk,
    //     // );

    //     Ok(())
    // }
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! aw {
        ($e:expr) => {
            tokio_test::block_on($e)
        };
    }

    #[test]
    fn test_check_oracle_offline() {
        let mut provider = Provider::default();
        provider
            .mock_get_exchange_rate_info()
            .returns(Ok((0, 0, 0)));
        provider.mock_get_time_now().returns(Ok(1));
        let verifier = OracleChecker { rpc: provider };

        assert_eq!(aw!(verifier.is_oracle_offline()).unwrap(), true);
    }
}
