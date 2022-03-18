use std::{collections::HashMap, convert::TryInto, sync::Arc};

use crate::system::{VaultData, VaultIdManager};
use bitcoin::{BitcoinCoreApi, GetTransactionResultDetailCategory, SignedAmount, TransactionExt};
use futures::{try_join, StreamExt};
use lazy_static::lazy_static;
use runtime::{
    prometheus::{gather, proto::MetricFamily, Encoder, Gauge, GaugeVec, Opts, Registry, TextEncoder},
    CurrencyIdExt, CurrencyInfo, Error, FeedValuesEvent, FixedPointNumber,
    FixedPointTraits::One,
    FixedU128, InterBtcParachain, OracleKey, RedeemPallet, RefundPallet, ReplacePallet, VaultId, VaultRegistryPallet,
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
    pub static ref BTC_BALANCE: GaugeVec =
        GaugeVec::new(Opts::new("btc_balance", "Bitcoin Balance"), &[CURRENCY_LABEL, "type"])
            .expect("Failed to create prometheus metric");
    pub static ref FEE_BUDGET_SURPLUS: GaugeVec =
        GaugeVec::new(Opts::new("fee_budget_surplus", "Fee Budget Surplus"), &[CURRENCY_LABEL])
            .expect("Failed to create prometheus metric");
}

#[derive(Clone, Debug)]
struct AverageTracker {
    total: u64,
    count: u64,
}

#[derive(Clone, Debug)]
struct StatefulGauge<T: Clone> {
    gauge: Gauge,
    data: Arc<RwLock<T>>,
}

#[derive(Clone, Debug)]
struct BtcBalance {
    upperbound: Gauge,
    lowerbound: Gauge,
    actual: Gauge,
}

#[derive(Clone, Debug)]
pub struct PerCurrencyMetrics {
    locked_collateral: Gauge,
    collateralization: Gauge,
    required_collateral: Gauge,
    btc_balance: BtcBalance,
    average_btc_fee: StatefulGauge<AverageTracker>,
    fee_budget_surplus: StatefulGauge<i64>,
}

impl PerCurrencyMetrics {
    pub fn new(vault_id: &VaultId) -> Self {
        let label = format!(
            "{}_{}",
            vault_id.collateral_currency().inner().symbol(),
            vault_id.wrapped_currency().inner().symbol()
        );
        Self::new_with_label(label.as_ref())
    }

    // construct a dummy metrics struct for testing purposes
    pub fn dummy() -> Self {
        Self::new_with_label("dummy")
    }

    fn new_with_label(label: &str) -> Self {
        let labels = HashMap::from([(CURRENCY_LABEL, label.as_ref())]);

        let btc_balance_gauge = |balance_type: &'static str| {
            let labels = HashMap::<&str, &str>::from([(CURRENCY_LABEL, label.as_ref()), ("type", balance_type)]);
            BTC_BALANCE.with(&labels)
        };

        Self {
            locked_collateral: LOCKED_COLLATERAL.with(&labels),
            collateralization: COLLATERALIZATION.with(&labels),
            required_collateral: REQUIRED_COLLATERAL.with(&labels),
            fee_budget_surplus: StatefulGauge {
                gauge: FEE_BUDGET_SURPLUS.with(&labels),
                data: Arc::new(RwLock::new(0)),
            },
            average_btc_fee: StatefulGauge {
                gauge: AVERAGE_BTC_FEE.with(&labels),
                data: Arc::new(RwLock::new(AverageTracker { total: 0, count: 0 })),
            },
            btc_balance: BtcBalance {
                upperbound: btc_balance_gauge("required_upperbound"),
                lowerbound: btc_balance_gauge("required_lowerbound"),
                actual: btc_balance_gauge("actual"),
            },
        }
    }

    pub async fn initialize_values<B: BitcoinCoreApi + Clone + Send + Sync>(
        parachain_rpc: InterBtcParachain,
        vault_id: VaultId,
        vault: &VaultData<B>,
    ) {
        let bitcoin_transactions = match vault.btc_rpc.list_transactions(None).await {
            Ok(x) => x
                .into_iter()
                .filter(|x| x.detail.category == GetTransactionResultDetailCategory::Send)
                .collect(),
            Err(_) => vec![],
        };

        // update average fee
        let (total, count) = bitcoin_transactions
            .iter()
            .filter_map(|tx| tx.detail.fee.map(|amount| amount.as_sat().abs() as u64))
            .fold((0, 0), |(total, count), x| (total + x, count + 1));
        *vault.metrics.average_btc_fee.data.write().await = AverageTracker { total, count };

        // update fee surplus
        if let Ok((redeem_requests, replace_requests, refund_requests)) = try_join!(
            parachain_rpc.get_vault_redeem_requests(vault_id.account_id.clone()),
            parachain_rpc.get_old_vault_replace_requests(vault_id.account_id.clone()),
            parachain_rpc.get_vault_refund_requests(vault_id.account_id.clone()),
        ) {
            let redeems = redeem_requests
                .iter()
                .map(|(id, redeem)| (id.clone(), redeem.transfer_fee_btc));
            let refunds = refund_requests
                .iter()
                .map(|(id, refund)| (id.clone(), refund.transfer_fee_btc));
            let replaces = replace_requests.iter().map(|(id, _)| (id.clone(), 0));
            let fee_budgets = redeems.chain(refunds).chain(replaces).collect::<HashMap<_, _>>();
            let fee_budgets = &fee_budgets;

            let fee_budget_surplus = futures::stream::iter(bitcoin_transactions.iter())
                .filter_map(|tx| async move {
                    let transaction = vault
                        .btc_rpc
                        .get_transaction(&tx.info.txid, tx.info.blockhash)
                        .await
                        .ok()?;
                    let op_return = transaction.get_op_return()?;
                    let budget: i64 = fee_budgets.get(&op_return)?.clone().try_into().ok()?;
                    let surplus = budget.checked_sub(tx.detail.fee?.as_sat().abs());
                    surplus
                })
                .fold(0i64, |acc, x| async move { acc.saturating_add(x) })
                .await;

            *vault.metrics.fee_budget_surplus.data.write().await = fee_budget_surplus;
            publish_fee_budget_surplus(&vault).await;
        }

        publish_average_bitcoin_fee(&vault).await;
        publish_bitcoin_balance(&vault).await;
        update_expected_bitcoin_balance(&vault, parachain_rpc.clone()).await;

        if let Err(err) = update_bridge_metrics(parachain_rpc, vault_id, vault.metrics.clone()).await {
            tracing::error!("Failed to initialize bridge metrics {:?}", err);
        }
    }
}

pub fn register_custom_metrics() -> Result<(), Error> {
    REGISTRY.register(Box::new(AVERAGE_BTC_FEE.clone()))?;
    REGISTRY.register(Box::new(LOCKED_COLLATERAL.clone()))?;
    REGISTRY.register(Box::new(COLLATERALIZATION.clone()))?;
    REGISTRY.register(Box::new(REQUIRED_COLLATERAL.clone()))?;
    REGISTRY.register(Box::new(FEE_BUDGET_SURPLUS.clone()))?;
    REGISTRY.register(Box::new(BTC_BALANCE.clone()))?;

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
    fee_budget: Option<u128>,
) {
    // update the average fee
    if let Some(amount) = new_fee_entry {
        {
            let mut tmp = vault.metrics.average_btc_fee.data.write().await;
            *tmp = AverageTracker {
                total: tmp.total.saturating_add(amount.as_sat().abs() as u64),
                count: tmp.count.saturating_add(1),
            };
        }
        publish_average_bitcoin_fee(&vault).await;

        if let Ok(budget) = TryInto::<i64>::try_into(fee_budget.unwrap_or(0)) {
            let surplus = budget.saturating_sub(amount.as_sat().abs());
            let mut tmp = vault.metrics.fee_budget_surplus.data.write().await;
            *tmp = tmp.saturating_add(surplus);
        }
        publish_fee_budget_surplus(&vault).await;
    }

    publish_bitcoin_balance(&vault).await;
}

async fn publish_fee_budget_surplus<B: BitcoinCoreApi + Clone + Send + Sync>(vault: &VaultData<B>) {
    let surplus = *vault.metrics.fee_budget_surplus.data.read().await;
    vault
        .metrics
        .fee_budget_surplus
        .gauge
        .set(surplus as f64 / vault.vault_id.wrapped_currency().one() as f64);
}

async fn publish_average_bitcoin_fee<B: BitcoinCoreApi + Clone + Send + Sync>(vault: &VaultData<B>) {
    let average = match vault.metrics.average_btc_fee.data.read().await {
        x if x.count > 0 => x.total as f64 / x.count as f64,
        _ => 0.0,
    };
    vault.metrics.average_btc_fee.gauge.set(average);
}

async fn publish_bitcoin_balance<B: BitcoinCoreApi + Clone + Send + Sync>(vault: &VaultData<B>) {
    match vault.btc_rpc.get_balance(None).await {
        Ok(bitcoin_balance) => vault.metrics.btc_balance.actual.set(bitcoin_balance.as_sat() as f64),
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

pub async fn update_expected_bitcoin_balance<B: BitcoinCoreApi + Clone + Send + Sync>(
    vault: &VaultData<B>,
    parachain_rpc: InterBtcParachain,
) {
    if let Ok(v) = parachain_rpc.get_vault(&vault.vault_id).await {
        let lowerbound = v.issued_tokens.saturating_sub(v.to_be_redeemed_tokens);
        let upperbound = v.issued_tokens.saturating_add(v.to_be_issued_tokens);
        vault.metrics.btc_balance.lowerbound.set(lowerbound as f64);
        vault.metrics.btc_balance.upperbound.set(upperbound as f64);
    }
}
