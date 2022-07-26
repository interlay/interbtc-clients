use crate::{
    error::{Error, KeyLoadingError},
    rpc::ShutdownSender,
    InterBtcParachain, InterBtcSigner,
};
use clap::Parser;
use sp_keyring::AccountKeyring;
use std::{collections::HashMap, num::ParseIntError, str::FromStr, time::Duration};
use subxt::sp_core::{sr25519::Pair, Pair as _};

#[derive(Parser, Debug, Clone)]
pub struct ProviderUserOpts {
    /// Keyring to use, mutually exclusive with keyfile.
    #[clap(long, required_unless_present = "keyfile", parse(try_from_str = parse_account_keyring))]
    pub keyring: Option<AccountKeyring>,

    /// Path to the json file containing key pairs in a map.
    /// Valid content of this file is e.g.
    /// `{ "MyUser1": "<Polkadot Account Mnemonic>", "MyUser2": "<Polkadot Account Mnemonic>" }`.
    #[clap(long, conflicts_with = "keyring", requires = "keyname")]
    pub keyfile: Option<String>,

    /// The name of the account from the keyfile to use.
    #[clap(long, conflicts_with = "keyring", requires = "keyfile")]
    pub keyname: Option<String>,
}

impl ProviderUserOpts {
    /// Get the key pair and the username, the latter of which is used for wallet selection.
    pub fn get_key_pair(&self) -> Result<(Pair, String), Error> {
        // load parachain credentials
        let (pair, user_name) = match (self.keyfile.as_ref(), self.keyname.as_ref(), &self.keyring) {
            (Some(file_path), Some(keyname), None) => {
                (get_credentials_from_file(file_path, keyname)?, keyname.to_string())
            }
            (None, None, Some(keyring)) => (keyring.pair(), format!("{}", keyring)),
            _ => {
                // should never occur, due to clap constraints
                return Err(Error::KeyringArgumentError);
            }
        };
        Ok((pair, user_name))
    }
}

/// Loads the credentials for the given user from the keyfile
///
/// # Arguments
///
/// * `file_path` - path to the json file containing the credentials
/// * `keyname` - name of the key to get
fn get_credentials_from_file(file_path: &str, keyname: &str) -> Result<Pair, KeyLoadingError> {
    let file = std::fs::File::open(file_path)?;
    let reader = std::io::BufReader::new(file);
    let map: HashMap<String, String> = serde_json::from_reader(reader)?;
    let pair_str = map.get(keyname).ok_or(KeyLoadingError::KeyNotFound)?;
    let pair = Pair::from_string(pair_str, None).map_err(KeyLoadingError::SecretStringError)?;
    Ok(pair)
}

pub fn parse_account_keyring(src: &str) -> Result<AccountKeyring, Error> {
    AccountKeyring::from_str(src).map_err(|_| Error::KeyringAccountParsingError)
}

pub fn parse_duration_ms(src: &str) -> Result<Duration, ParseIntError> {
    Ok(Duration::from_millis(src.parse::<u64>()?))
}

pub fn parse_duration_minutes(src: &str) -> Result<Duration, ParseIntError> {
    Ok(Duration::from_secs(src.parse::<u64>()? * 60))
}

#[derive(Parser, Debug, Clone)]
pub struct ConnectionOpts {
    /// Parachain websocket URL.
    #[cfg_attr(feature = "standalone-metadata",clap(long, default_value = "ws://127.0.0.1:9944"))]
    #[cfg_attr(feature = "parachain-metadata-interlay-testnet",clap(long, default_value = "wss://staging.interlay-dev.interlay.io:443/parachain"))]
    #[cfg_attr(feature = "parachain-metadata-kintsugi-testnet",clap(long, default_value = "wss://api-dev-kintsugi.interlay.io:443/parachain"))]
    #[cfg_attr(feature = "parachain-metadata-kintsugi",clap(long, default_value = "wss://api-kusama.interlay.io:443/parachain"))]
    #[cfg_attr(feature = "parachain-metadata-interlay",clap(long, default_value = "wss://api.interlay.io:443/parachain"))]
    pub btc_parachain_url: String,

    /// Timeout in milliseconds to wait for connection to btc-parachain.
    #[clap(long, parse(try_from_str = parse_duration_ms), default_value = "60000")]
    pub btc_parachain_connection_timeout_ms: Duration,

    /// Maximum number of concurrent requests
    #[clap(long)]
    pub max_concurrent_requests: Option<usize>,

    /// Maximum notification capacity for each subscription
    #[clap(long)]
    pub max_notifs_per_subscription: Option<usize>,
}

impl ConnectionOpts {
    pub async fn try_connect(
        &self,
        signer: InterBtcSigner,
        shutdown_tx: ShutdownSender,
    ) -> Result<InterBtcParachain, Error> {
        InterBtcParachain::from_url_and_config_with_retry(
            &self.btc_parachain_url,
            signer,
            self.max_concurrent_requests,
            self.max_notifs_per_subscription,
            self.btc_parachain_connection_timeout_ms,
            shutdown_tx,
        )
        .await
    }
}
