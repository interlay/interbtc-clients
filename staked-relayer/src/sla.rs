use async_trait::async_trait;
use log::{error, info};
use runtime::{
    conn::Service, pallets::sla::UpdateRelayerSLAEvent, Error as RuntimeError, PolkaBtcProvider,
    PolkaBtcRuntime, UtilFuncs,
};

pub struct SlaUpdateService {
    btc_parachain: PolkaBtcProvider,
}

#[async_trait]
impl Service<(), PolkaBtcProvider> for SlaUpdateService {
    async fn connect(btc_parachain: PolkaBtcProvider, config: ()) -> Result<(), RuntimeError> {
        SlaUpdateService::new(btc_parachain, config)
            .run_service()
            .await
            .map_err(|_| RuntimeError::ChannelClosed)
    }
}

impl SlaUpdateService {
    fn new(btc_parachain: PolkaBtcProvider, _config: ()) -> Self {
        Self { btc_parachain }
    }

    async fn run_service(&mut self) -> Result<(), RuntimeError> {
        let relayer_id = self.btc_parachain.get_account_id();
        self.btc_parachain
            .on_event::<UpdateRelayerSLAEvent<PolkaBtcRuntime>, _, _, _>(
                |event| async move {
                    if &event.relayer_id == relayer_id {
                        info!("Received event: new total SLA score = {:?}", event.new_sla);
                    }
                },
                |err| error!("Error (UpdateRelayerSLAEvent): {}", err.to_string()),
            )
            .await
    }
}
