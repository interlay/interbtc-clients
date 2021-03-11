use crate::execution::*;
use async_trait::async_trait;
use bitcoin::BitcoinCoreApi;
use log::{error, info};
use runtime::{
    pallets::redeem::RequestRedeemEvent, Error as RuntimeError, PolkaBtcProvider, PolkaBtcRuntime,
    Service, UtilFuncs,
};

#[derive(Clone)]
pub struct RedeemServiceConfig<B> {
    /// the bitcoin RPC handle
    pub bitcoin_core: B,
    /// the number of bitcoin confirmation to await
    pub num_confirmations: u32,
}

pub struct RedeemService<B> {
    btc_parachain: PolkaBtcProvider,
    bitcoin_core: B,
    num_confirmations: u32,
}

#[async_trait]
impl<B: BitcoinCoreApi + Clone + Send + Sync + 'static>
    Service<RedeemServiceConfig<B>, PolkaBtcProvider> for RedeemService<B>
{
    async fn connect(
        btc_parachain: PolkaBtcProvider,
        config: RedeemServiceConfig<B>,
    ) -> Result<(), RuntimeError> {
        RedeemService::new(btc_parachain, config)
            .run_service()
            .await
            .map_err(|_| RuntimeError::ChannelClosed)
    }
}

impl<B: BitcoinCoreApi + Clone + Send + Sync + 'static> RedeemService<B> {
    fn new(btc_parachain: PolkaBtcProvider, config: RedeemServiceConfig<B>) -> Self {
        Self {
            btc_parachain,
            bitcoin_core: config.bitcoin_core,
            num_confirmations: config.num_confirmations,
        }
    }

    /// Listen for RequestRedeemEvent directed at this vault; upon reception, transfer
    /// bitcoin and call execute_redeem
    async fn run_service(&self) -> Result<(), RuntimeError> {
        self.btc_parachain
            .on_event::<RequestRedeemEvent<PolkaBtcRuntime>, _, _, _>(
                |event| async {
                    if &event.vault_id != self.btc_parachain.get_account_id() {
                        return;
                    }
                    info!("Received redeem request: {:?}", event);

                    // within this event callback, we captured the arguments of listen_for_redeem_requests
                    // by reference. Since spawn requires static lifetimes, we will need to capture the
                    // arguments by value rather than by reference, so clone these:
                    let btc_parachain = self.btc_parachain.clone();
                    let bitcoin_core = self.bitcoin_core.clone();
                    let num_confirmations = self.num_confirmations;

                    // Spawn a new task so that we handle these events concurrently
                    tokio::spawn(async move {
                        // prepare the action that will be executed after the bitcoin transfer
                        let request = Request::from_redeem_request_event(&event);
                        let result = request
                            .pay_and_execute(&btc_parachain, &bitcoin_core, num_confirmations)
                            .await;

                        match result {
                            Ok(_) => info!(
                                "Completed redeem request #{} with amount {}",
                                event.redeem_id, event.amount_polka_btc
                            ),
                            Err(e) => error!(
                                "Failed to process redeem request #{}: {}",
                                event.redeem_id,
                                e.to_string()
                            ),
                        }
                    });
                },
                |error| error!("Error reading redeem event: {}", error.to_string()),
            )
            .await
    }
}
