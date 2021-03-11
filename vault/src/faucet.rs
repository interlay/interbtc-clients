use crate::{error::Error, http, lock_additional_collateral};
use bitcoin::BitcoinCoreApi;
use jsonrpc_core::Value;
use jsonrpc_core_client::{transports::http as jsonrpc_http, TypedClient};
use parity_scale_codec::{Decode, Encode};
use runtime::{AccountId, PolkaBtcProvider, VaultRegistryPallet, PLANCK_PER_DOT, TX_FEES};

#[derive(Encode, Decode, Debug, Clone, serde::Serialize)]
struct FundAccountJsonRpcRequest {
    pub account_id: AccountId,
}

async fn get_faucet_allowance(
    faucet_connection: TypedClient,
    allowance_type: &str,
) -> Result<u128, Error> {
    let raw_allowance = faucet_connection
        .call_method::<(), http::RawBytes>(&allowance_type, "", ())
        .await?;
    Ok(Decode::decode(&mut &raw_allowance.0[..])?)
}

async fn get_funding(faucet_connection: TypedClient, vault_id: AccountId) -> Result<(), Error> {
    let funding_request = FundAccountJsonRpcRequest {
        account_id: vault_id,
    };
    let eq = format!("0x{}", hex::encode(funding_request.encode()));
    faucet_connection
        .call_method::<Vec<String>, Value>("fund_account", "", vec![eq.clone()])
        .await?;
    Ok(())
}

pub async fn fund_and_register<B: BitcoinCoreApi>(
    btc_parachain: &PolkaBtcProvider,
    bitcoin_core: &B,
    faucet_url: String,
    vault_id: AccountId,
) -> Result<(), Error> {
    let connection = jsonrpc_http::connect::<TypedClient>(&faucet_url).await?;

    // Receive user allowance from faucet
    get_funding(connection.clone(), vault_id.clone()).await?;

    let user_allowance_in_dot: u128 =
        get_faucet_allowance(connection.clone(), "user_allowance").await?;
    let registration_collateral = user_allowance_in_dot
        .checked_mul(PLANCK_PER_DOT)
        .ok_or(Error::ArithmeticOverflow)?
        .checked_sub(TX_FEES)
        .ok_or(Error::ArithmeticUnderflow)?;

    let public_key = bitcoin_core.get_new_public_key().await?;
    btc_parachain
        .register_vault(registration_collateral, public_key)
        .await?;

    // Receive vault allowance from faucet
    get_funding(connection.clone(), vault_id).await?;

    let vault_allowance_in_dot: u128 =
        get_faucet_allowance(connection.clone(), "vault_allowance").await?;
    let operational_collateral = vault_allowance_in_dot
        .checked_mul(PLANCK_PER_DOT)
        .ok_or(Error::ArithmeticOverflow)?
        .checked_sub(TX_FEES)
        .ok_or(Error::ArithmeticUnderflow)?;

    lock_additional_collateral(&btc_parachain, operational_collateral).await?;

    Ok(())
}
