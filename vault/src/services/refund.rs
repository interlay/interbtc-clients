use crate::execution::*;
use async_trait::async_trait;
use bitcoin::BitcoinCoreApi;
use log::{error, info};
use runtime::{
    pallets::refund::RequestRefundEvent, Error as RuntimeError, PolkaBtcProvider, PolkaBtcRuntime,
    Service, UtilFuncs,
};

#[derive(Clone)]
pub struct RefundServiceConfig<B> {
    /// the bitcoin RPC handle
    pub bitcoin_core: B,
    /// the number of bitcoin confirmation to await
    pub num_confirmations: u32,
}

pub struct RefundService<B> {
    btc_parachain: PolkaBtcProvider,
    bitcoin_core: B,
    num_confirmations: u32,
}

#[async_trait]
impl<B: BitcoinCoreApi + Clone + Send + Sync + 'static>
    Service<RefundServiceConfig<B>, PolkaBtcProvider> for RefundService<B>
{
    async fn connect(
        btc_parachain: PolkaBtcProvider,
        config: RefundServiceConfig<B>,
    ) -> Result<(), RuntimeError> {
        RefundService::new(btc_parachain, config)
            .run_service()
            .await
            .map_err(|_| RuntimeError::ChannelClosed)
    }
}

impl<B: BitcoinCoreApi + Clone + Send + Sync + 'static> RefundService<B> {
    fn new(btc_parachain: PolkaBtcProvider, config: RefundServiceConfig<B>) -> Self {
        Self {
            btc_parachain,
            bitcoin_core: config.bitcoin_core,
            num_confirmations: config.num_confirmations,
        }
    }

    /// Listen for RequestRefundEvent directed at this vault; upon reception, transfer
    /// bitcoin and call execute_refund
    async fn run_service(&self) -> Result<(), RuntimeError> {
        self.btc_parachain
            .on_event::<RequestRefundEvent<PolkaBtcRuntime>, _, _, _>(
                |event| async {
                    if &event.vault_id != self.btc_parachain.get_account_id() {
                        return;
                    }
                    info!("Received refund request: {:?}", event);

                    // within this event callback, we captured the arguments of listen_for_refund_requests
                    // by reference. Since spawn requires static lifetimes, we will need to capture the
                    // arguments by value rather than by reference, so clone these:
                    let btc_parachain = self.btc_parachain.clone();
                    let bitcoin_core = self.bitcoin_core.clone();
                    let num_confirmations = self.num_confirmations;

                    // Spawn a new task so that we handle these events concurrently
                    tokio::spawn(async move {
                        // prepare the action that will be executed after the bitcoin transfer
                        let request = Request::from_refund_request_event(&event);
                        let result = request
                            .pay_and_execute(&btc_parachain, &bitcoin_core, num_confirmations)
                            .await;

                        match result {
                            Ok(_) => info!(
                                "Completed refund request #{} with amount {}",
                                event.refund_id, event.amount_polka_btc
                            ),
                            Err(e) => error!(
                                "Failed to process refund request #{}: {}",
                                event.refund_id,
                                e.to_string()
                            ),
                        }
                    });
                },
                |error| error!("Error reading refund event: {}", error.to_string()),
            )
            .await
    }
}
