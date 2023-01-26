use crate::{deposit_collateral, error::Error};
use faucet_rpc::Allowance;
use hex::FromHex;
use jsonrpc_core::Value;
use jsonrpc_core_client::{transports::http as jsonrpc_http, TypedClient};
use parity_scale_codec::{Decode, Encode};
use runtime::{AccountId, CurrencyId, InterBtcParachain, RuntimeCurrencyInfo, VaultId, VaultRegistryPallet, TX_FEES};
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
    pub vault_account_id: AccountId,
    pub collateral_currency: CurrencyId,
}

async fn get_faucet_allowance(
    faucet_connection: TypedClient,
    allowance_type: &str,
    vault_id: &VaultId,
) -> Result<u128, Error> {
    let raw_allowance = faucet_connection
        .call_method::<(), RawBytes>(allowance_type, "", ())
        .await?;
    let allowances: Allowance = Decode::decode(&mut &raw_allowance.0[..])?;
    let key = vault_id.collateral_currency().symbol()?;
    let value = allowances
        .iter()
        .find(|x| x.symbol == key)
        .map(|x| x.amount)
        .ok_or(Error::FaucetAllowanceNotSet(key))?;
    Ok(value)
}

async fn get_funding(faucet_connection: TypedClient, vault_id: VaultId) -> Result<(), Error> {
    let funding_request = FundAccountJsonRpcRequest {
        vault_account_id: vault_id.account_id.clone(),
        collateral_currency: vault_id.collateral_currency(),
    };
    let eq = format!("0x{}", hex::encode(funding_request.encode()));
    faucet_connection
        .call_method::<Vec<String>, Value>("fund_account", "", vec![eq.clone()])
        .await?;
    Ok(())
}

pub async fn fund_account(faucet_url: &str, vault_id: &VaultId) -> Result<TypedClient, Error> {
    tracing::info!("Connecting to the faucet");
    let connection = jsonrpc_http::connect::<TypedClient>(faucet_url).await?;

    // Receive user allowance from faucet
    if let Err(e) = get_funding(connection.clone(), vault_id.clone()).await {
        tracing::warn!("Failed to get funding from faucet: {}", e);
    }

    Ok(connection)
}

pub async fn fund_and_register(
    parachain_rpc: &InterBtcParachain,
    faucet_url: &str,
    vault_id: &VaultId,
) -> Result<(), Error> {
    let connection = fund_account(faucet_url, vault_id).await?;

    let user_allowance = get_faucet_allowance(connection.clone(), "user_allowance", vault_id).await?;
    tracing::error!("user_allowance = {user_allowance}");
    let registration_collateral = user_allowance.checked_sub(TX_FEES).ok_or(Error::ArithmeticUnderflow)?;

    tracing::info!("Registering the vault");
    parachain_rpc.register_vault(vault_id, registration_collateral).await?;

    // Receive vault allowance from faucet
    get_funding(connection.clone(), vault_id.clone()).await?;

    let vault_allowance_in_planck = get_faucet_allowance(connection.clone(), "vault_allowance", vault_id).await?;
    let operational_collateral = vault_allowance_in_planck
        .checked_div(3)
        .unwrap_or_default()
        .checked_mul(2)
        .unwrap_or_default();

    deposit_collateral(parachain_rpc, vault_id, operational_collateral).await?;

    Ok(())
}
