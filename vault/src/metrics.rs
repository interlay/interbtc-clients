use std::{collections::HashMap, sync::Arc};

use crate::system::{VaultData, VaultIdManager};
use bitcoin::{BitcoinCoreApi, SignedAmount};
use lazy_static::lazy_static;

use runtime::{
    prometheus::{gather, proto::MetricFamily, Encoder, Gauge, GaugeVec, Opts, Registry, TextEncoder},
    CurrencyIdExt, CurrencyInfo, Error, FeedValuesEvent, FixedPointNumber,
    FixedPointTraits::One,
    FixedU128, InterBtcParachain, OracleKey, VaultId, VaultRegistryPallet,
};
use service::{
    warp::{Rejection, Reply},
    Error as ServiceError,
};
use tokio::sync::RwLock;

const CURRENCY_LABEL: &str = "currency";

// Metrics are stored under the [`CURRENCY_LABEL`] key so that multiple vaults can be easily
// monitored at the same time.
lazy_static! {
    pub static ref REGISTRY: Registry = Registry::new();
    pub static ref LOCKED_BTC: GaugeVec = GaugeVec::new(Opts::new("locked_btc", "Locked Bitcoin"), &[CURRENCY_LABEL])
        .expect("Failed to create prometheus metric");
    pub static ref AVERAGE_BTC_FEE: GaugeVec =
        GaugeVec::new(Opts::new("avg_btc_fee", "Average Bitcoin Fee"), &[CURRENCY_LABEL])
            .expect("Failed to create prometheus metric");
    pub static ref LOCKED_COLLATERAL: GaugeVec =
        GaugeVec::new(Opts::new("locked_collateral", "Locked Collateral"), &[CURRENCY_LABEL])
            .expect("Failed to create prometheus metric");
    pub static ref COLLATERALIZATION: GaugeVec =
        GaugeVec::new(Opts::new("collateralization", "Collateralization"), &[CURRENCY_LABEL])
            .expect("Failed to create prometheus metric");
    pub static ref REQUIRED_COLLATERAL: GaugeVec = GaugeVec::new(
        Opts::new("required_collateral", "Required Collateral"),
        &[CURRENCY_LABEL]
    )
    .expect("Failed to create prometheus metric");
}

#[derive(Clone, Debug)]
struct AverageTracker {
    total: u64,
    count: u64,
}

#[derive(Clone, Debug)]
pub struct PerCurrencyMetrics {
    locked_btc: Gauge,
    average_btc_fee: Gauge,
    locked_collateral: Gauge,
    collateralization: Gauge,
    required_collateral: Gauge,
    bitcoin_fee_data: Arc<RwLock<AverageTracker>>,
}

impl PerCurrencyMetrics {
    pub async fn new(vault_id: &VaultId) -> Self {
        let label = format!(
            "{}_{}",
            vault_id.collateral_currency().inner().symbol(),
            vault_id.wrapped_currency().inner().symbol()
        );
        let mut labels = HashMap::new();
        labels.insert(CURRENCY_LABEL, label.as_ref());

        Self {
            locked_btc: LOCKED_BTC.with(&labels),
            average_btc_fee: AVERAGE_BTC_FEE.with(&labels),
            locked_collateral: LOCKED_COLLATERAL.with(&labels),
            collateralization: COLLATERALIZATION.with(&labels),
            required_collateral: REQUIRED_COLLATERAL.with(&labels),
            bitcoin_fee_data: Arc::new(RwLock::new(AverageTracker { total: 0, count: 0 })),
        }
    }

    // construct a dummy metrics struct for testing purposes
    pub fn dummy() -> Self {
        let mut labels = HashMap::new();
        labels.insert(CURRENCY_LABEL, "dummy");

        Self {
            locked_btc: LOCKED_BTC.with(&labels),
            average_btc_fee: AVERAGE_BTC_FEE.with(&labels),
            locked_collateral: LOCKED_COLLATERAL.with(&labels),
            collateralization: COLLATERALIZATION.with(&labels),
            required_collateral: REQUIRED_COLLATERAL.with(&labels),
            bitcoin_fee_data: Arc::new(RwLock::new(AverageTracker { total: 0, count: 0 })),
        }
    }

    pub async fn initialize_values<B: BitcoinCoreApi + Clone + Send + Sync>(
        parachain_rpc: InterBtcParachain,
        vault_id: VaultId,
        vault: &VaultData<B>,
    ) {
        let (total, count) = vault
            .btc_rpc
            .list_transactions(None)
            .await
            .unwrap_or(vec![])
            .into_iter()
            .filter_map(|tx| tx.detail.fee.map(|amount| amount.as_sat().abs() as u64))
            .fold((0, 0), |(total, count), x| (total + x, count + 1));
        *vault.metrics.bitcoin_fee_data.write().await = AverageTracker { total, count };
        publish_average_bitcoin_fee(&vault).await;
        publish_bitcoin_balance(&vault).await;

        if let Err(err) = update_bridge_metrics(parachain_rpc, vault_id, vault.metrics.clone()).await {
            tracing::error!("Failed to initialize bridge metrics {:?}", err);
        }
    }
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

pub async fn update_bridge_metrics(
    parachain_rpc: InterBtcParachain,
    vault_id: VaultId,
    metrics: PerCurrencyMetrics,
) -> Result<(), Error> {
    let decimals_offset = FixedU128::one()
        .into_inner()
        .checked_div(vault_id.collateral_currency().one())
        .unwrap_or_default() as f64;

    let actual_collateral = parachain_rpc.get_vault_total_collateral(vault_id.clone()).await?;
    let float_actual_collateral = FixedU128::from_inner(actual_collateral).to_float() * decimals_offset;

    metrics.locked_collateral.set(float_actual_collateral);

    // if the collateralization is infinite, return 0 rather than logging an error, so
    // the metrics do change in case of a replacement
    let collateralization = parachain_rpc
        .get_collateralization_from_vault(vault_id.clone(), false)
        .await
        .unwrap_or(0u128);
    let float_collateralization_percentage = FixedU128::from_inner(collateralization).to_float();
    metrics.collateralization.set(float_collateralization_percentage);

    let required_collateral = parachain_rpc
        .get_required_collateral_for_vault(vault_id.clone())
        .await?;
    let truncated_required_collateral = FixedU128::from_inner(required_collateral).to_float() * decimals_offset;
    metrics.required_collateral.set(truncated_required_collateral);
    Ok(())
}

pub async fn update_bitcoin_metrics<B: BitcoinCoreApi + Clone + Send + Sync>(
    vault: VaultData<B>,
    new_fee_entry: Option<SignedAmount>,
) {
    // update the average fee
    if let Some(amount) = new_fee_entry {
        {
            let mut tmp = vault.metrics.bitcoin_fee_data.write().await;
            *tmp = AverageTracker {
                total: tmp.total.saturating_add(amount.as_sat().abs() as u64),
                count: tmp.count.saturating_add(1),
            };
            // guaranteed not to panic since we just incremented count
            tmp.total as f64 / tmp.count as f64
        };
        publish_average_bitcoin_fee(&vault).await;
    }

    publish_bitcoin_balance(&vault).await;
}

async fn publish_average_bitcoin_fee<B: BitcoinCoreApi + Clone + Send + Sync>(vault: &VaultData<B>) {
    let fees = vault.metrics.bitcoin_fee_data.read().await;
    if fees.count != 0 {
        vault.metrics.average_btc_fee.set(fees.total as f64 / fees.count as f64);
    }
}

async fn publish_bitcoin_balance<B: BitcoinCoreApi + Clone + Send + Sync>(vault: &VaultData<B>) {
    match vault.btc_rpc.get_balance(None).await {
        Ok(bitcoin_balance) => vault.metrics.locked_btc.set(bitcoin_balance.as_btc()),
        Err(e) => {
            // unexpected error, but not critical so just continue
            tracing::warn!("Failed to get Bitcoin balance: {}", e);
        }
    }
}

pub async fn monitor_bridge_metrics<B: BitcoinCoreApi + Clone + Send + Sync>(
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
                let vaults = vault_id_manager.get_entries().await;
                for currency_id in updated_currencies {
                    for (vault_id, data) in vaults
                        .iter()
                        .filter(|(vault_id, _)| &vault_id.collateral_currency() == currency_id)
                    {
                        if let Err(err) =
                            update_bridge_metrics(parachain_rpc.clone(), vault_id.clone(), data.metrics.clone()).await
                        {
                            tracing::info!("Failed to update prometheus bridge metrics: {}", err);
                        }
                    }
                }
            },
            |error| tracing::error!("Error reading SetExchangeRate event: {}", error.to_string()),
        )
        .await?;
    Ok(())
}
