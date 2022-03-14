use crate::system::VaultIdManager;
use bitcoin::{BitcoinCoreApi, SignedAmount};
use lazy_static::lazy_static;

use runtime::{
    prometheus::{gather, proto::MetricFamily, Encoder, Gauge, Registry, TextEncoder},
    CurrencyIdExt, CurrencyInfo, Error, FeedValuesEvent, FixedPointNumber,
    FixedPointTraits::One,
    FixedU128, InterBtcParachain, OracleKey, VaultId, VaultRegistryPallet,
};
use service::{
    warp::{Rejection, Reply},
    Error as ServiceError,
};
use tokio::sync::RwLock;

// Metrics are stored under the `vault_id` key so that multiple vaults can be easily
// monitored at the same time.
lazy_static! {
    static ref BITCOIN_FEES: RwLock<Vec<f64>> = RwLock::new(vec![]);
    pub static ref REGISTRY: Registry = Registry::new();
    pub static ref LOCKED_BTC: Gauge =
        Gauge::new("locked_btc", "Locked Bitcoin").expect("Failed to create prometheus metric");
    pub static ref AVERAGE_BTC_FEE: Gauge =
        Gauge::new("avg_btc_fee", "Average Bitcoin Fee").expect("Failed to create prometheus metric");
    pub static ref LOCKED_COLLATERAL: Gauge =
        Gauge::new("locked_collateral", "Locked Collateral").expect("Failed to create prometheus metric");
    pub static ref COLLATERALIZATION: Gauge =
        Gauge::new("collateralization", "Collateralization").expect("Failed to create prometheus metric");
    pub static ref REQUIRED_COLLATERAL: Gauge =
        Gauge::new("required_collateral", "Required Collateral").expect("Failed to create prometheus metric");
}

pub fn register_custom_metrics() -> Result<(), Error> {
    REGISTRY.register(Box::new(LOCKED_BTC.clone()))?;
    REGISTRY.register(Box::new(AVERAGE_BTC_FEE.clone()))?;
    REGISTRY.register(Box::new(LOCKED_COLLATERAL.clone()))?;
    REGISTRY.register(Box::new(COLLATERALIZATION.clone()))?;
    REGISTRY.register(Box::new(REQUIRED_COLLATERAL.clone()))?;

    Ok(())
}

fn serialize(metrics: &[MetricFamily]) -> String {
    let encoder = TextEncoder::new();
    let mut buffer = Vec::new();
    if let Err(e) = encoder.encode(&metrics, &mut buffer) {
        eprintln!("could not encode metrics: {}", e);
    };
    let res = match String::from_utf8(buffer.clone()) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("metrics could not be parsed `from_utf8`: {}", e);
            String::default()
        }
    };
    buffer.clear();
    res
}

pub async fn metrics_handler() -> Result<impl Reply, Rejection> {
    let mut metrics = serialize(&REGISTRY.gather());
    let custom_metrics = serialize(&gather());
    metrics.push_str(&custom_metrics);
    Ok(metrics)
}

pub async fn update_bridge_metrics(parachain_rpc: InterBtcParachain, vault_id: VaultId) -> Result<(), Error> {
    let decimals_offset = FixedU128::one()
        .into_inner()
        .checked_div(vault_id.collateral_currency().one())
        .unwrap_or_default() as f64;

    let actual_collateral = parachain_rpc.get_vault_total_collateral(vault_id.clone()).await?;
    let float_actual_collateral = FixedU128::from_inner(actual_collateral).to_float() * decimals_offset;

    LOCKED_COLLATERAL.set(float_actual_collateral);

    let collateralization = parachain_rpc
        .get_collateralization_from_vault(vault_id.clone(), false)
        // if the collateralization is infinite, return 0 rather than logging an error, so
        // the metrics do change in case of a replacement
        .await
        .unwrap_or(0u128);
    let float_collateralization_percentage = FixedU128::from_inner(collateralization).to_float();
    COLLATERALIZATION.set(float_collateralization_percentage);

    let required_collateral = parachain_rpc
        .get_required_collateral_for_vault(vault_id.clone())
        .await?;
    let truncated_required_collateral = FixedU128::from_inner(required_collateral).to_float() * decimals_offset;
    REQUIRED_COLLATERAL.set(truncated_required_collateral);
    Ok(())
}

pub async fn update_bitcoin_metrics<B: BitcoinCoreApi + Clone + Send + Sync + 'static>(
    btc_rpc: B,
    btc_confirmations: u32,
) {
    match btc_rpc.get_balance(Some(btc_confirmations)).await {
        Ok(bitcoin_balance) => LOCKED_BTC.set(bitcoin_balance.as_btc()),
        Err(e) => {
            // failed to cancel; get up-to-date request list in next iteration
            tracing::error!("Failed to get Bitcoin balance: {}", e);
        }
    }
    update_bitcoin_fees(btc_rpc, None).await;
}

pub async fn update_bitcoin_fees<B: BitcoinCoreApi + Clone + Send + Sync + 'static>(
    btc_rpc: B,
    new_fee_entry: Option<SignedAmount>,
) {
    let mut bitcoin_fees_vec = BITCOIN_FEES.write().await;
    if bitcoin_fees_vec.len() == 0 && new_fee_entry.is_none() {
        // Initialize the `AVERAGE_BTC_FEE` by fetching all Bitcoin txs.
        match btc_rpc.list_transactions(None).await {
            Ok(tx_list) => {
                let mut fees: Vec<_> = tx_list
                    .iter()
                    .filter_map(|tx| tx.detail.fee.map(|amount| amount.as_btc()))
                    .collect();

                bitcoin_fees_vec.append(&mut fees);
            }
            Err(e) => {
                // failed to cancel; get up-to-date request list in next iteration
                tracing::error!("Failed to get Bitcoin transactions: {}", e);
            }
        }
    } else if let Some(fee) = new_fee_entry {
        bitcoin_fees_vec.push(fee.as_btc());
    }
    let average = bitcoin_fees_vec.iter().sum::<f64>() / bitcoin_fees_vec.len() as f64;
    // Fees are returned as negative numbers.
    AVERAGE_BTC_FEE.set(-average);
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
                            if let Err(err) = update_bridge_metrics(parachain_rpc.clone(), vault_id.clone()).await {
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
