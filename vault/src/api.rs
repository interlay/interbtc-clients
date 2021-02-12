use super::Error;
use bitcoin::BitcoinCoreApi;
use futures::executor::block_on;
use hex::FromHex;
use jsonrpc_http_server::{
    jsonrpc_core::{
        serde_json::Value, Error as JsonRpcError, ErrorCode as JsonRpcErrorCode, IoHandler, Params,
    },
    DomainsValidation, ServerBuilder,
};
use log::info;
use parity_scale_codec::{Decode, Encode};
use runtime::{
    BtcPublicKey, ExchangeRateOraclePallet, FeePallet, FixedPointNumber,
    FixedPointTraits::{CheckedAdd, CheckedMul},
    PolkaBtcProvider, ReplacePallet, UtilFuncs, VaultRegistryPallet,
};
use serde::{Deserialize, Deserializer};
use sp_arithmetic::FixedU128;
use sp_core::crypto::Ss58Codec;
use sp_core::H256;
use std::{net::SocketAddr, sync::Arc};

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct RawBytes(#[serde(deserialize_with = "hex_to_buffer")] pub(crate) Vec<u8>);

pub fn hex_to_buffer<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    String::deserialize(deserializer).and_then(|string| {
        Vec::from_hex(&string[2..]).map_err(|err| Error::custom(err.to_string()))
    })
}

fn parse_params<T: Decode>(params: Params) -> Result<T, Error> {
    let raw: [RawBytes; 1] = params.parse()?;
    let req = Decode::decode(&mut &raw[0].0[..]).map_err(Error::CodecError)?;
    Ok(req)
}

fn handle_resp<T: Encode>(resp: Result<T, Error>) -> Result<Value, JsonRpcError> {
    match resp {
        Ok(data) => Ok(format!("0x{}", hex::encode(data.encode())).into()),
        Err(err) => Err(JsonRpcError {
            code: JsonRpcErrorCode::InternalError,
            message: err.to_string(),
            data: None,
        }),
    }
}

#[derive(Encode, Decode, Debug)]
struct AccountIdJsonRpcResponse {
    account_id: String,
}

fn _account_id(provider: &Arc<PolkaBtcProvider>) -> Result<AccountIdJsonRpcResponse, Error> {
    Ok(AccountIdJsonRpcResponse {
        account_id: provider.get_account_id().to_ss58check(),
    })
}

#[derive(Encode, Decode, Debug)]
struct ReplaceRequestJsonRpcRequest {
    amount: u128,
}

async fn _request_replace(provider: &Arc<PolkaBtcProvider>, params: Params) -> Result<(), Error> {
    let req = parse_params::<ReplaceRequestJsonRpcRequest>(params)?;

    let amount_in_dot = provider.btc_to_dots(req.amount).await?;
    let griefing_collateral_percentage = provider.get_replace_griefing_collateral().await?;
    let griefing_collateral = calculate_for(amount_in_dot, griefing_collateral_percentage)?;
    let result = block_on(provider.request_replace(req.amount, griefing_collateral));
    info!(
        "Requesting replace for amount = {} with griefing_collateral = {}: {:?}",
        req.amount, griefing_collateral, result
    );
    Ok(result.map(|_| ())?)
}

/// Take the `percentage` of an `amount`
fn calculate_for(amount: u128, percentage: FixedU128) -> Result<u128, Error> {
    // we add 0.5 before we do the final integer division to round the result we return.
    // note that unwrapping is safe because we use a constant
    let rounding_addition = FixedU128::checked_from_rational(1, 2).unwrap();

    FixedU128::checked_from_integer(amount)
        .ok_or(Error::ArithmeticOverflow)?
        .checked_mul(&percentage)
        .ok_or(Error::ArithmeticOverflow)?
        .checked_add(&rounding_addition)
        .ok_or(Error::ArithmeticOverflow)?
        .into_inner()
        .checked_div(FixedU128::accuracy())
        .ok_or(Error::ArithmeticUnderflow)
}

#[derive(Encode, Decode, Debug)]
struct RegisterVaultJsonRpcRequest {
    collateral: u128,
}

#[derive(Encode, Decode, Debug)]
struct RegisterVaultJsonRpcResponse {
    public_key: BtcPublicKey,
}

fn _register_vault<B: BitcoinCoreApi>(
    provider: &Arc<PolkaBtcProvider>,
    btc: &Arc<B>,
    params: Params,
) -> Result<RegisterVaultJsonRpcResponse, Error> {
    let req = parse_params::<RegisterVaultJsonRpcRequest>(params)?;
    let public_key: BtcPublicKey = block_on(btc.get_new_public_key())?;
    let result = block_on(provider.register_vault(req.collateral, public_key.clone()));
    info!(
        "Registering vault with bitcoind public_key {:?} and collateral = {}: {:?}",
        public_key, req.collateral, result
    );
    Ok(result.map(|_| RegisterVaultJsonRpcResponse { public_key })?)
}

#[derive(Encode, Decode, Debug)]
struct ChangeCollateralJsonRpcRequest {
    amount: u128,
}

fn _lock_additional_collateral(
    provider: &Arc<PolkaBtcProvider>,
    params: Params,
) -> Result<(), Error> {
    let req = parse_params::<ChangeCollateralJsonRpcRequest>(params)?;
    let result = block_on(provider.lock_additional_collateral(req.amount));
    info!(
        "Locking additional collateral; amount {}: {:?}",
        req.amount, result
    );
    Ok(result?)
}

fn _withdraw_collateral(provider: &Arc<PolkaBtcProvider>, params: Params) -> Result<(), Error> {
    let req = parse_params::<ChangeCollateralJsonRpcRequest>(params)?;
    let result = block_on(provider.withdraw_collateral(req.amount));
    info!(
        "Withdrawing collateral with amount {}: {:?}",
        req.amount, result
    );
    Ok(result?)
}

#[derive(Encode, Decode, Debug)]
struct WithdrawReplaceJsonRpcRequest {
    replace_id: H256,
}

fn _withdraw_replace(provider: &Arc<PolkaBtcProvider>, params: Params) -> Result<(), Error> {
    let req = parse_params::<WithdrawReplaceJsonRpcRequest>(params)?;
    let result = block_on(provider.withdraw_replace(req.replace_id));
    info!(
        "Withdrawing replace request {}: {:?}",
        req.replace_id, result
    );
    Ok(result?)
}

pub async fn start<B: BitcoinCoreApi + Send + Sync + 'static>(
    provider: Arc<PolkaBtcProvider>,
    btc: Arc<B>,
    addr: SocketAddr,
    origin: String,
) {
    let mut io = IoHandler::default();
    {
        let provider = provider.clone();
        io.add_sync_method("account_id", move |_| handle_resp(_account_id(&provider)));
    }
    {
        let provider = provider.clone();
        io.add_method("request_replace", move |params| {
            let provider = provider.clone();
            async move { handle_resp(_request_replace(&provider, params).await) }
        });
    }
    {
        let provider = provider.clone();
        let btc = btc.clone();
        io.add_sync_method("register_vault", move |params| {
            handle_resp(_register_vault(&provider, &btc, params))
        });
    }
    {
        let provider = provider.clone();
        io.add_sync_method("lock_additional_collateral", move |params| {
            handle_resp(_lock_additional_collateral(&provider, params))
        });
    }
    {
        let provider = provider.clone();
        io.add_sync_method("withdraw_collateral", move |params| {
            handle_resp(_withdraw_collateral(&provider, params))
        });
    }
    {
        let provider = provider.clone();
        io.add_sync_method("withdraw_replace", move |params| {
            handle_resp(_withdraw_replace(&provider, params))
        });
    }

    let server = ServerBuilder::new(io)
        .rest_api(jsonrpc_http_server::RestApi::Unsecure)
        .cors(DomainsValidation::AllowOnly(vec![origin.into()]))
        .start_http(&addr)
        .expect("Unable to start RPC server");

    tokio::task::spawn_blocking(move || {
        server.wait();
    })
    .await
    .unwrap();
}
