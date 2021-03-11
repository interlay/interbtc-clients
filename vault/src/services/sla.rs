use async_trait::async_trait;
use log::{error, info};
use runtime::{
    pallets::sla::UpdateVaultSLAEvent, Error as RuntimeError, PolkaBtcProvider, PolkaBtcRuntime,
    Service, UtilFuncs,
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
        let vault_id = self.btc_parachain.get_account_id();
        self.btc_parachain
            .on_event::<UpdateVaultSLAEvent<PolkaBtcRuntime>, _, _, _>(
                |event| async move {
                    if &event.vault_id == vault_id {
                        info!("Received event: new total SLA score = {:?}", event.new_sla);
                    }
                },
                |err| error!("Error (UpdateVaultSLAEvent): {}", err.to_string()),
            )
            .await
    }
}
