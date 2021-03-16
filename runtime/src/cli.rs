use crate::error::{Error, KeyLoadingError};
use crate::{ConnectionManagerConfig, RestartPolicy};

use clap::Clap;
use sp_core::sr25519::Pair;
use sp_core::Pair as _;
use sp_keyring::AccountKeyring;
use std::collections::HashMap;
use std::time::Duration;

#[derive(Clap, Debug, Clone)]
pub struct ProviderUserOpts {
    /// Keyring to use, mutually exclusive with keyfile.
    #[clap(long)]
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
        let (pair, user_name) = match (self.keyfile.as_ref(), self.keyname.as_ref(), &self.keyring)
        {
            (Some(file_path), Some(keyname), None) => (
                get_credentials_from_file(&file_path, &keyname)?,
                keyname.to_string(),
            ),
            (None, None, Some(keyring)) => (keyring.pair(), format!("{}", keyring)),
            _ => panic!("Invalid arguments"), // should never occur, due to clap constraints
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
    let pair =
        Pair::from_string(pair_str, None).map_err(|e| KeyLoadingError::SecretStringError(e))?;
    Ok(pair)
}

#[derive(Clap, Debug, Clone)]
pub struct ConnectionOpts {
    /// Parachain websocket URL.
    #[clap(long, default_value = "ws://127.0.0.1:9944")]
    pub polka_btc_url: String,

    /// Timeout in milliseconds to wait for connection to btc-parachain.
    #[clap(long, default_value = "60000")]
    pub polka_btc_connection_timeout_ms: u64,

    /// What to do if the connection to the btc-parachain drops.
    #[clap(long, default_value = "always")]
    pub restart_policy: RestartPolicy,

    /// Maximum number of concurrent requests
    #[clap(long)]
    pub max_concurrent_requests: Option<usize>,

    /// Maximum notification capacity for each subscription
    #[clap(long)]
    pub max_notifs_per_subscription: Option<usize>,
}

impl Into<ConnectionManagerConfig> for ConnectionOpts {
    fn into(self) -> ConnectionManagerConfig {
        ConnectionManagerConfig {
            connection_timeout: Duration::from_millis(self.polka_btc_connection_timeout_ms),
            restart_policy: self.restart_policy,
            max_concurrent_requests: self.max_concurrent_requests,
            max_notifs_per_subscription: self.max_notifs_per_subscription,
        }
    }
}
