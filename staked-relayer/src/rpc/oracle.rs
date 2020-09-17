use super::Error;
use super::ErrorCode;
use log::{error, info};
use std::sync::Arc;

#[cfg(not(test))]
use super::Provider;

#[cfg(test)]
use super::MockProvider as Provider;

pub struct Oracle {
    rpc: Arc<Provider>,
}

impl Oracle {
    pub fn new(rpc: Arc<Provider>) -> Self {
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
    use std::collections::BTreeSet;
    use std::iter::FromIterator;

    #[test]
    fn test_is_oracle_offline_true() {
        let mut prov = Provider::default();
        prov.expect_get_exchange_rate_info()
            .returning(|| Ok((0, 0, 0)));
        prov.expect_get_time_now().returning(|| Ok(1));

        assert_eq!(
            tokio_test::block_on(Oracle::new(Arc::new(prov)).is_offline()).unwrap(),
            true
        );
    }

    #[test]
    fn test_is_oracle_offline_false() {
        let mut prov = Provider::default();
        prov.expect_get_exchange_rate_info()
            .returning(|| Ok((0, 1, 3)));
        prov.expect_get_time_now().returning(|| Ok(2));

        assert_eq!(
            tokio_test::block_on(Oracle::new(Arc::new(prov)).is_offline()).unwrap(),
            false
        );
    }

    #[test]
    fn test_report_oracle_offline_not_reported() {
        let mut prov = Provider::default();

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

        tokio_test::block_on(Oracle::new(Arc::new(prov)).report_offline());
    }

    #[test]
    fn test_report_oracle_offline_already_reported() {
        let mut prov = Provider::default();

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

        tokio_test::block_on(Oracle::new(Arc::new(prov)).report_offline());
    }
}
