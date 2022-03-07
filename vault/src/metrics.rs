use crate::system::VaultIdManager;
use bitcoin::BitcoinCoreApi;
use lazy_static::lazy_static;

use runtime::{
    prometheus::{gather, Encoder, GaugeVec, IntGauge, Opts as PrometheusOpts, Registry, TextEncoder},
    CurrencyIdExt, CurrencyInfo, Error, FeedValuesEvent, FixedPointNumber,
    FixedPointTraits::One,
    FixedU128, InterBtcParachain, OracleKey, VaultId, VaultRegistryPallet,
};
use service::{
    warp::{Rejection, Reply},
    Error as ServiceError,
};

lazy_static! {
    pub static ref REGISTRY: Registry = Registry::new();
    pub static ref LOCKED_BTC: IntGauge =
        IntGauge::new("connected_clients", "Connected Clients").expect("Failed to create prometheus metric");
    pub static ref LOCKED_COLLATERAL: GaugeVec = GaugeVec::new(
        PrometheusOpts::new("locked_collateral", "Locked Collateral"),
        &["vault_id"]
    )
    .expect("Failed to create prometheus metric");
    pub static ref COLLATERALIZATION: GaugeVec = GaugeVec::new(
        PrometheusOpts::new("collateralization", "Collateralization"),
        &["vault_id"]
    )
    .expect("Failed to create prometheus metric");
    pub static ref REQUIRED_COLLATERAL: GaugeVec = GaugeVec::new(
        PrometheusOpts::new("required_collateral", "Required Collateral"),
        &["vault_id"]
    )
    .expect("Failed to create prometheus metric");
}

pub fn register_custom_metrics() -> Result<(), Error> {
    REGISTRY.register(Box::new(LOCKED_BTC.clone()))?;
    REGISTRY.register(Box::new(LOCKED_COLLATERAL.clone()))?;
    REGISTRY.register(Box::new(COLLATERALIZATION.clone()))?;
    REGISTRY.register(Box::new(REQUIRED_COLLATERAL.clone()))?;

    Ok(())
}

pub async fn metrics_handler() -> Result<impl Reply, Rejection> {
    let encoder = TextEncoder::new();

    let mut buffer = Vec::new();
    if let Err(e) = encoder.encode(&REGISTRY.gather(), &mut buffer) {
        eprintln!("could not encode custom metrics: {}", e);
    };
    let mut res = match String::from_utf8(buffer.clone()) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("custom metrics could not be from_utf8'd: {}", e);
            String::default()
        }
    };
    buffer.clear();

    let mut buffer = Vec::new();
    if let Err(e) = encoder.encode(&gather(), &mut buffer) {
        eprintln!("could not encode prometheus metrics: {}", e);
    };
    let res_custom = match String::from_utf8(buffer.clone()) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("prometheus metrics could not be from_utf8'd: {}", e);
            String::default()
        }
    };
    buffer.clear();

    res.push_str(&res_custom);
    Ok(res)
}

pub async fn update_service_metrics(parachain_rpc: InterBtcParachain, vault_id: VaultId) -> Result<(), Error> {
    let decimals_offset = FixedU128::one()
        .into_inner()
        .checked_div(vault_id.collateral_currency().one())
        .unwrap_or_default() as f64;

    let actual_collateral = parachain_rpc.get_vault_total_collateral(vault_id.clone()).await?;
    let float_actual_collateral = FixedU128::from_inner(actual_collateral).to_float() * decimals_offset;

    LOCKED_COLLATERAL
        .with_label_values(&[format!("{:?}", vault_id).as_str()])
        .set(float_actual_collateral);

    let collateralization = parachain_rpc
        .get_collateralization_from_vault(vault_id.clone(), false)
        // if the collateralization is infinite, return 0 rather than logging an error, so
        // the metrics do change in case of a replacement
        .await
        .unwrap_or(0u128);
    let float_collateralization_percentage = FixedU128::from_inner(collateralization).to_float();
    COLLATERALIZATION
        .with_label_values(&[format!("{:?}", vault_id).as_str()])
        .set(float_collateralization_percentage);

    let required_collateral = parachain_rpc
        .get_required_collateral_for_vault(vault_id.clone())
        .await?;
    let truncated_required_collateral = FixedU128::from_inner(required_collateral).to_float() * decimals_offset;
    REQUIRED_COLLATERAL
        .with_label_values(&[format!("{:?}", vault_id).as_str()])
        .set(truncated_required_collateral);
    Ok(())
}

pub async fn monitor_bridge_metrics<B: BitcoinCoreApi + Clone + Send + Sync + 'static>(
    parachain_rpc: InterBtcParachain,
    vault_id_manager: VaultIdManager<B>,
) -> Result<(), ServiceError> {
    let parachain_rpc = &parachain_rpc;
    let vault_id_manager = &vault_id_manager;
    parachain_rpc
        .on_event::<FeedValuesEvent, _, _, _>(
            |event| async move {
                let updated_currencies = event.values.iter().filter_map(|(key, _value)| match key {
                    OracleKey::ExchangeRate(currency_id) => Some(currency_id),
                    _ => None,
                });
                let vault_ids = vault_id_manager.get_vault_ids().await;
                for currency_id in updated_currencies {
                    match vault_ids
                        .iter()
                        .find(|vault_id| &vault_id.collateral_currency() == currency_id)
                    {
                        None => tracing::debug!("Ignoring exchange rate update for {}", currency_id.inner().symbol()),
                        Some(vault_id) => {
                            tracing::info!("Received FeedValuesEvent for {}", currency_id.inner().symbol());
                            if let Err(err) = update_service_metrics(parachain_rpc.clone(), vault_id.clone()).await {
                                tracing::info!("{:?}", err);
                            }
                        }
                    }
                }
            },
            |error| tracing::error!("Error reading SetExchangeRate event: {}", error.to_string()),
        )
        .await?;
    Ok(())
}
