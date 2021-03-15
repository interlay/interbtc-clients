use super::Error;
use crate::utils;
use log::info;
use runtime::{
    ErrorCode, ExchangeRateOraclePallet, SecurityPallet, StakedRelayerPallet, TimestampPallet,
};
use std::time::Duration;
use tokio::time::delay_for;

pub async fn report_offline_oracle<
    P: TimestampPallet + ExchangeRateOraclePallet + StakedRelayerPallet + SecurityPallet,
>(
    rpc: P,
    duration: Duration,
) -> Result<(), Error> {
    let monitor = OracleMonitor::new(rpc);
    loop {
        delay_for(duration).await;
        monitor.report_offline().await?;
    }
}

pub struct OracleMonitor<
    P: TimestampPallet + ExchangeRateOraclePallet + StakedRelayerPallet + SecurityPallet,
> {
    rpc: P,
}

impl<P: TimestampPallet + ExchangeRateOraclePallet + StakedRelayerPallet + SecurityPallet>
    OracleMonitor<P>
{
    pub fn new(rpc: P) -> Self {
        Self { rpc }
    }

    /// Verify that the oracle is offline
    pub async fn is_offline(&self) -> Result<bool, Error> {
        let get_info = self.rpc.get_exchange_rate_info();
        let get_time = self.rpc.get_time_now();
        let result = tokio::try_join!(get_info, get_time);
        match result {
            Ok(((_rate, last, delay), now)) => Ok(last + delay < now),
            Err(_) => Err(Error::CheckOracleOffline),
        }
    }

    pub async fn report_offline(&self) -> Result<(), Error> {
        if !utils::is_active(&self.rpc).await? {
            // not registered (active), ignore check
            return Ok(());
        }

        if self.is_offline().await? {
            if let Ok(error_codes) = self.rpc.get_error_codes().await {
                if error_codes.contains(&ErrorCode::OracleOffline) {
                    info!("Oracle already reported");
                    return Ok(());
                }
            }
            info!("Oracle is offline");
            self.rpc.report_oracle_offline().await?;
        };

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use runtime::PolkaBtcStatusUpdate;
    use runtime::{
        AccountId, BtcTxFeesPerByte, Error, ErrorCode, FixedPointNumber, FixedU128, H256Le,
        StatusCode, MINIMUM_STAKE,
    };
    use std::collections::BTreeSet;
    use std::iter::FromIterator;

    mockall::mock! {
        Provider {}

        #[async_trait]
        trait TimestampPallet {
            async fn get_time_now(&self) -> Result<u64, Error>;
        }

        #[async_trait]
        trait ExchangeRateOraclePallet {
            async fn get_exchange_rate_info(&self) -> Result<(FixedU128, u64, u64), Error>;

            async fn set_exchange_rate_info(&self, dot_per_btc: FixedU128) -> Result<(), Error>;

            async fn set_btc_tx_fees_per_byte(&self, fast: u32, half: u32, hour: u32) -> Result<(), Error>;

            async fn get_btc_tx_fees_per_byte(&self) -> Result<BtcTxFeesPerByte, Error>;

            async fn btc_to_dots(&self, amount: u128) -> Result<u128, Error>;

            async fn dots_to_btc(&self, amount: u128) -> Result<u128, Error>;
        }

        #[async_trait]
        trait StakedRelayerPallet {
            async fn get_active_stake(&self) -> Result<u128, Error>;
            async fn get_active_stake_by_id(&self, account_id: AccountId) -> Result<u128, Error>;
            async fn get_inactive_stake_by_id(&self, account_id: AccountId) -> Result<u128, Error>;
            async fn register_staked_relayer(&self, stake: u128) -> Result<(), Error>;
            async fn deregister_staked_relayer(&self) -> Result<(), Error>;
            async fn suggest_status_update(
                &self,
                deposit: u128,
                status_code: StatusCode,
                add_error: Option<ErrorCode>,
                remove_error: Option<ErrorCode>,
                block_hash: Option<H256Le>,
                message: String,
            ) -> Result<(), Error>;
            async fn vote_on_status_update(
                &self,
                status_update_id: u64,
                approve: bool,
            ) -> Result<(), Error>;
            async fn get_status_update(&self, id: u64) -> Result<PolkaBtcStatusUpdate, Error>;
            async fn report_oracle_offline(&self) -> Result<(), Error>;
            async fn report_vault_theft(
                &self,
                vault_id: AccountId,
                tx_id: H256Le,
                merkle_proof: Vec<u8>,
                raw_tx: Vec<u8>,
            ) -> Result<(), Error>;
            async fn is_transaction_invalid(
                &self,
                vault_id: AccountId,
                raw_tx: Vec<u8>,
            ) -> Result<bool, Error>;
            async fn set_maturity_period(&self, period: u32) -> Result<(), Error>;
            async fn evaluate_status_update(&self, status_update_id: u64) -> Result<(), Error>;
        }

        #[async_trait]
        trait SecurityPallet {
            async fn get_parachain_status(&self) -> Result<StatusCode, Error>;
            async fn get_error_codes(&self) -> Result<BTreeSet<ErrorCode>, Error>;
        }
    }

    impl Clone for MockProvider {
        fn clone(&self) -> Self {
            // NOTE: expectations dropped
            Self::default()
        }
    }

    #[tokio::test]
    async fn test_is_oracle_offline_true() {
        let mut parachain = MockProvider::default();
        parachain
            .expect_get_exchange_rate_info()
            .returning(|| Ok((FixedU128::one(), 0, 0)));
        parachain.expect_get_time_now().returning(|| Ok(1));

        assert_eq!(
            OracleMonitor::new(parachain).is_offline().await.unwrap(),
            true
        );
    }

    #[tokio::test]
    async fn test_is_oracle_offline_false() {
        let mut parachain = MockProvider::default();
        parachain
            .expect_get_exchange_rate_info()
            .returning(|| Ok((FixedU128::one(), 1, 3)));
        parachain.expect_get_time_now().returning(|| Ok(2));

        assert_eq!(
            OracleMonitor::new(parachain).is_offline().await.unwrap(),
            false
        );
    }

    #[tokio::test]
    async fn test_report_oracle_offline_not_reported() {
        let mut parachain = MockProvider::default();
        parachain
            .expect_get_active_stake()
            .once()
            .returning(|| Ok(MINIMUM_STAKE));

        // is_offline should return true
        parachain
            .expect_get_exchange_rate_info()
            .returning(|| Ok((FixedU128::one(), 0, 0)));
        parachain.expect_get_time_now().returning(|| Ok(1));

        // should report if error not known
        parachain
            .expect_get_error_codes()
            .once()
            .returning(|| Ok(BTreeSet::new()));
        parachain
            .expect_report_oracle_offline()
            .once()
            .returning(|| Ok(()));

        OracleMonitor::new(parachain)
            .report_offline()
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_report_oracle_offline_already_reported() {
        let mut parachain = MockProvider::default();
        parachain
            .expect_get_active_stake()
            .once()
            .returning(|| Ok(MINIMUM_STAKE));

        // is_offline should return true
        parachain
            .expect_get_exchange_rate_info()
            .returning(|| Ok((FixedU128::one(), 0, 0)));
        parachain.expect_get_time_now().returning(|| Ok(1));

        // should not report if error already known
        parachain
            .expect_get_error_codes()
            .once()
            .returning(|| Ok(BTreeSet::from_iter(vec![ErrorCode::OracleOffline])));
        parachain
            .expect_report_oracle_offline()
            .never()
            .returning(|| Ok(()));

        OracleMonitor::new(parachain)
            .report_offline()
            .await
            .unwrap();
    }
}
