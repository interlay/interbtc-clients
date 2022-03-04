use lazy_static::lazy_static;
use runtime::{
    prometheus::{gather, Encoder, GaugeVec, IntGauge, Opts as PrometheusOpts, Registry, TextEncoder},
    Error, FixedU128, InterBtcParachain, VaultId, VaultRegistryPallet,
};
use service::warp::{Rejection, Reply};

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
    let actual_collateral = parachain_rpc.get_vault_total_collateral(vault_id.clone()).await?;
    let float_actual_collateral = FixedU128::from_inner(actual_collateral).to_float();
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
    let truncated_required_collateral = FixedU128::from_inner(required_collateral).to_float();
    REQUIRED_COLLATERAL
        .with_label_values(&[format!("{:?}", vault_id).as_str()])
        .set(truncated_required_collateral);
    Ok(())
}
