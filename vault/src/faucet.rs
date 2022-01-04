use crate::{deposit_collateral, error::Error};
use bitcoin::BitcoinCoreApi;
use hex::FromHex;
use jsonrpc_core::Value;
use jsonrpc_core_client::{transports::http as jsonrpc_http, TypedClient};
use parity_scale_codec::{Decode, Encode};
use runtime::{CurrencyId, CurrencyIdExt, InterBtcParachain, VaultId, VaultRegistryPallet, TX_FEES};
use serde::{Deserialize, Deserializer};

#[derive(Debug, Clone, Deserialize)]
struct RawBytes(#[serde(deserialize_with = "hex_to_buffer")] Vec<u8>);

pub fn hex_to_buffer<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    String::deserialize(deserializer)
        .and_then(|string| Vec::from_hex(&string[2..]).map_err(|err| Error::custom(err.to_string())))
}

#[derive(Encode, Decode, Debug, Clone, serde::Serialize)]
struct FundAccountJsonRpcRequest {
    pub vault_id: VaultId,
}

async fn get_faucet_allowance(faucet_connection: TypedClient, allowance_type: &str) -> Result<u128, Error> {
    let raw_allowance = faucet_connection
        .call_method::<(), RawBytes>(allowance_type, "", ())
        .await?;
    Ok(Decode::decode(&mut &raw_allowance.0[..])?)
}

async fn get_funding(faucet_connection: TypedClient, vault_id: VaultId) -> Result<(), Error> {
    let funding_request = FundAccountJsonRpcRequest { vault_id };
    let eq = format!("0x{}", hex::encode(funding_request.encode()));
    faucet_connection
        .call_method::<Vec<String>, Value>("fund_account", "", vec![eq.clone()])
        .await?;
    Ok(())
}

pub async fn fund_and_register<B: BitcoinCoreApi + Clone>(
    parachain_rpc: &InterBtcParachain,
    bitcoin_core: &B,
    faucet_url: &str,
    vault_id: &VaultId,
) -> Result<(), Error> {
    tracing::info!("Connecting to the faucet");
    let connection = jsonrpc_http::connect::<TypedClient>(faucet_url).await?;
    let currency_id: CurrencyId = vault_id.collateral_currency().into();

    // Receive user allowance from faucet
    if let Err(e) = get_funding(connection.clone(), vault_id.clone()).await {
        tracing::warn!("Failed to get funding from faucet: {}", e);
    }

    let user_allowance_in_dot: u128 = get_faucet_allowance(connection.clone(), "user_allowance").await?;
    let registration_collateral = user_allowance_in_dot
        .checked_mul(currency_id.inner().one())
        .ok_or(Error::ArithmeticOverflow)?
        .checked_sub(TX_FEES)
        .ok_or(Error::ArithmeticUnderflow)?;

    tracing::info!("Registering the vault");
    let public_key = bitcoin_core.get_new_public_key().await?;
    parachain_rpc
        .register_vault(vault_id, registration_collateral, public_key)
        .await?;

    // Receive vault allowance from faucet
    get_funding(connection.clone(), vault_id.clone()).await?;

    // TODO: faucet allowance should return planck
    let vault_allowance_in_dot: u128 = get_faucet_allowance(connection.clone(), "vault_allowance").await?;
    let vault_allowance_in_planck = vault_allowance_in_dot
        .checked_mul(currency_id.inner().one())
        .ok_or(Error::ArithmeticOverflow)?;
    let operational_collateral = vault_allowance_in_planck
        .checked_div(3)
        .unwrap_or_default()
        .checked_mul(2)
        .unwrap_or_default();

    deposit_collateral(parachain_rpc, vault_id, operational_collateral).await?;

    Ok(())
}
