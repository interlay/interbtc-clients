use bitcoincore_rpc::bitcoin::secp256k1::Scalar;

use crate::{secp256k1::SecretKey, Error};

pub fn calculate_deposit_secret_key(vault_key: SecretKey, issue_key: SecretKey) -> Result<SecretKey, Error> {
    let mut deposit_key = vault_key;
    deposit_key.mul_assign(&Scalar::from(issue_key))?;
    Ok(deposit_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secp256k1;
    use rand::{thread_rng, Rng};
    use secp256k1::{constants::SECRET_KEY_SIZE, PublicKey, Secp256k1, SecretKey};
    use sp_core::H256;

    #[test]
    fn test_calculate_deposit_secret_key() {
        let secp = Secp256k1::new();

        // c
        let secure_id = H256::random();
        let secret_key = SecretKey::from_slice(secure_id.as_bytes()).unwrap();

        // v
        let raw_secret_key: [u8; SECRET_KEY_SIZE] = thread_rng().gen();
        let vault_secret_key = SecretKey::from_slice(&raw_secret_key).unwrap();
        // V
        let vault_public_key = PublicKey::from_secret_key(&secp, &vault_secret_key);

        // D = V * c
        let mut deposit_public_key = vault_public_key;
        deposit_public_key.mul_assign(&secp, &secret_key[..]).unwrap();

        // d = v * c
        let deposit_secret_key = calculate_deposit_secret_key(vault_secret_key, secret_key).unwrap();

        assert_eq!(
            deposit_public_key,
            PublicKey::from_secret_key(&secp, &deposit_secret_key)
        );
    }
}
