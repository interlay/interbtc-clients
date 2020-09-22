use super::Error;
use log::{error, info};
use runtime::{
    ErrorCode, ExchangeRateOraclePallet, SecurityPallet, StakedRelayerPallet, TimestampPallet,
};
use std::sync::Arc;

pub struct Oracle<
    P: TimestampPallet + ExchangeRateOraclePallet + StakedRelayerPallet + SecurityPallet,
> {
    rpc: Arc<P>,
}

impl<P: TimestampPallet + ExchangeRateOraclePallet + StakedRelayerPallet + SecurityPallet>
    Oracle<P>
{
    pub fn new(rpc: Arc<P>) -> Self {
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

    pub async fn report_offline(&self) {
        match self.is_offline().await {
            Ok(true) => {
                if let Ok(error_codes) = self.rpc.get_error_codes().await {
                    if error_codes.contains(&ErrorCode::OracleOffline) {
                        info!("Oracle already reported");
                        return;
                    }
                    info!("Oracle is offline");
                    match self.rpc.report_oracle_offline().await {
                        Ok(_) => info!("Successfully reported oracle offline"),
                        Err(e) => error!("Failed to report oracle offline: {}", e.to_string()),
                    }
                };
            }
            // ignore if false
            Ok(false) => (),
            Err(e) => error!("Liveness check failed: {}", e.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use runtime::PolkaBtcStatusUpdate;
    use runtime::{Error, ErrorCode, H256Le, PolkaBtcRuntime, StatusCode};
    use std::collections::BTreeSet;
    use std::iter::FromIterator;
    use substrate_subxt::system::System;

    mockall::mock! {
        Provider {}

        #[async_trait]
        trait TimestampPallet {
            async fn get_time_now(&self) -> Result<u64, Error>;
        }

        #[async_trait]
        trait ExchangeRateOraclePallet {
            async fn get_exchange_rate_info(&self) -> Result<(u64, u64, u64), Error>;
        }

        #[async_trait]
        trait StakedRelayerPallet {
            async fn register_staked_relayer(&self, stake: u128) -> Result<(), Error>;
            async fn deregister_staked_relayer(&self) -> Result<(), Error>;
            async fn suggest_status_update(
                &self,
                deposit: u128,
                status_code: StatusCode,
                add_error: Option<ErrorCode>,
                remove_error: Option<ErrorCode>,
            ) -> Result<(), Error>;
            async fn get_status_update(&self, id: u64) -> Result<PolkaBtcStatusUpdate, Error>;
            async fn report_oracle_offline(&self) -> Result<(), Error>;
            async fn report_vault_theft(
                &self,
                vault_id: <PolkaBtcRuntime as System>::AccountId,
                tx_id: H256Le,
                tx_block_height: u32,
                merkle_proof: Vec<u8>,
                raw_tx: Vec<u8>,
            ) -> Result<(), Error>;
        }

        #[async_trait]
        trait SecurityPallet {
            async fn get_parachain_status(&self) -> Result<StatusCode, Error>;
            async fn get_error_codes(&self) -> Result<BTreeSet<ErrorCode>, Error>;
        }
    }

    #[tokio::test]
    async fn test_is_oracle_offline_true() {
        let mut prov = MockProvider::default();
        prov.expect_get_exchange_rate_info()
            .returning(|| Ok((0, 0, 0)));
        prov.expect_get_time_now().returning(|| Ok(1));

        assert_eq!(
            Oracle::new(Arc::new(prov)).is_offline().await.unwrap(),
            true
        );
    }

    #[tokio::test]
    async fn test_is_oracle_offline_false() {
        let mut prov = MockProvider::default();
        prov.expect_get_exchange_rate_info()
            .returning(|| Ok((0, 1, 3)));
        prov.expect_get_time_now().returning(|| Ok(2));

        assert_eq!(
            Oracle::new(Arc::new(prov)).is_offline().await.unwrap(),
            false
        );
    }

    #[tokio::test]
    async fn test_report_oracle_offline_not_reported() {
        let mut prov = MockProvider::default();

        // is_offline should return true
        prov.expect_get_exchange_rate_info()
            .returning(|| Ok((0, 0, 0)));
        prov.expect_get_time_now().returning(|| Ok(1));

        // should report if error not known
        prov.expect_get_error_codes()
            .once()
            .returning(|| Ok(BTreeSet::new()));
        prov.expect_report_oracle_offline()
            .once()
            .returning(|| Ok(()));

        Oracle::new(Arc::new(prov)).report_offline().await;
    }

    #[tokio::test]
    async fn test_report_oracle_offline_already_reported() {
        let mut prov = MockProvider::default();

        // is_offline should return true
        prov.expect_get_exchange_rate_info()
            .returning(|| Ok((0, 0, 0)));
        prov.expect_get_time_now().returning(|| Ok(1));

        // should not report if error already known
        prov.expect_get_error_codes()
            .once()
            .returning(|| Ok(BTreeSet::from_iter(vec![ErrorCode::OracleOffline])));
        prov.expect_report_oracle_offline()
            .never()
            .returning(|| Ok(()));

        Oracle::new(Arc::new(prov)).report_offline().await;
    }
}
