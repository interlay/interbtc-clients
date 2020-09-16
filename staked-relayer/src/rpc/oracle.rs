use super::Error;

#[cfg(not(test))]
use super::Provider;

#[cfg(test)]
use super::mock::Provider;

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
