use crate::error::{Error, KeyLoadingError};
use clap::Clap;

use sp_core::sr25519::Pair;
use sp_core::Pair as _;
use sp_keyring::AccountKeyring;
use std::collections::HashMap;

#[derive(Clap, Debug, Clone)]
pub struct ProviderUserOpts {
    /// Keyring to use, mutually exclusive with keyfile.
    #[clap(long)]
    keyring: Option<AccountKeyring>,

    /// Path to the json file containing key pairs in a map.
    /// Valid content of this file is e.g.
    /// `{ "MyUser1": "<credentials>", "MyUser2": "<credentials>" }`.
    /// Credentials should be a `0x`-prefixed 64-digit hex string, or
    /// a BIP-39 key phrase of 12, 15, 18, 21 or 24 words. See
    /// `sp_core::from_string_with_seed` for more details.
    #[clap(long, conflicts_with = "keyring", requires = "keyname")]
    keyfile: Option<String>,

    /// The name of the account from the keyfile to use.
    #[clap(long, conflicts_with = "keyring", requires = "keyfile")]
    keyname: Option<String>,
}

impl ProviderUserOpts {
    /// Get the key pair and the username, the latter of which is used for wallet selection.
    pub fn get_key_pair(&self) -> Result<(Pair, String), Error> {
        // load parachain credentials
        let (pair, user_name) = match (
            self.keyfile.as_ref(),
            self.keyname.as_ref(),
            &self.keyring,
        ) {
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
