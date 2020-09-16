use super::Error;
use std::sync::Arc;

#[cfg(not(test))]
use super::Provider;

#[cfg(test)]
use super::MockProvider as Provider;

#[derive(Clone)]
pub struct OracleChecker {
    rpc: Arc<Provider>,
}

impl OracleChecker {
    pub fn new(rpc: Arc<Provider>) -> Self {
        OracleChecker { rpc }
    }

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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_oracle_offline() {
        let mut mock = Provider::default();
        mock.expect_get_exchange_rate_info()
            .returning(|| Ok((0, 0, 0)));
        mock.expect_get_time_now().returning(|| Ok(1));

        let verifier = OracleChecker::new(Arc::new(mock));
        assert_eq!(
            tokio_test::block_on(verifier.is_oracle_offline()).unwrap(),
            true
        );
    }
}
