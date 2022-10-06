use crate::{BtcAddress, H160};
use bitcoin::{
    Address, ConversionError, Hash, Network, Payload, PubkeyHash, Script, ScriptHash, WPubkeyHash, WScriptHash,
};

pub trait PartialAddress: Sized + Eq + PartialOrd {
    /// Decode the `PartialAddress` from the `Payload` type.
    ///
    /// # Arguments
    /// * `payload` - Bitcoin payload (P2PKH, P2SH, P2WPKH)
    fn from_payload(payload: Payload) -> Result<Self, ConversionError>;

    /// Encode the `PartialAddress` into the `Payload` type.
    fn to_payload(&self) -> Result<Payload, ConversionError>;

    /// Decode the `PartialAddress` from the `Address` type.
    ///
    /// # Arguments
    /// * `address` - Bitcoin address
    fn from_address(address: Address) -> Result<Self, ConversionError>;

    /// Encode the `PartialAddress` as an address that the bitcoin rpc can use.
    ///
    /// # Arguments
    /// * `network` - network to prefix
    fn to_address(&self, network: Network) -> Result<Address, ConversionError>;
}

impl PartialAddress for BtcAddress {
    fn from_payload(payload: Payload) -> Result<Self, ConversionError> {
        match payload {
            Payload::PubkeyHash(hash) => Ok(Self::P2PKH(H160::from(hash.as_hash().into_inner()))),
            Payload::ScriptHash(hash) => Ok(Self::P2SH(H160::from(hash.as_hash().into_inner()))),
            Payload::WitnessProgram { version: _, program } => {
                if program.len() == 20 {
                    Ok(Self::P2WPKHv0(H160::from_slice(program.as_slice())))
                } else {
                    Err(ConversionError::InvalidPayload)
                }
            }
        }
    }

    fn to_payload(&self) -> Result<Payload, ConversionError> {
        let script = match self {
            Self::P2PKH(hash) => Script::new_p2pkh(&PubkeyHash::from_slice(hash.as_bytes())?),
            Self::P2SH(hash) => Script::new_p2sh(&ScriptHash::from_slice(hash.as_bytes())?),
            Self::P2WPKHv0(hash) => Script::new_v0_p2wpkh(&WPubkeyHash::from_slice(hash.as_bytes())?),
            Self::P2WSHv0(hash) => Script::new_v0_p2wsh(&WScriptHash::from_slice(hash.as_bytes())?),
        };

        Ok(Payload::from_script(&script)?)
    }

    fn from_address(address: Address) -> Result<Self, ConversionError> {
        Self::from_payload(address.payload)
    }

    fn to_address(&self, network: Network) -> Result<Address, ConversionError> {
        let payload = self.to_payload()?;
        Ok(Address { payload, network })
    }
}

impl PartialAddress for Payload {
    fn from_payload(payload: Payload) -> Result<Self, ConversionError> {
        Ok(payload)
    }

    fn to_payload(&self) -> Result<Payload, ConversionError> {
        Ok(self.clone())
    }

    fn from_address(address: Address) -> Result<Self, ConversionError> {
        Ok(address.payload)
    }

    fn to_address(&self, network: Network) -> Result<Address, ConversionError> {
        Ok(Address {
            network,
            payload: self.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_encode_and_decode_payload() {
        let addr = "bcrt1q6v2c7q7uv8vu6xle2k9ryfj3y3fuuy4rqnl50f";
        assert_eq!(
            addr,
            Payload::from_address(Address::from_str(addr).unwrap())
                .unwrap()
                .to_address(Network::Regtest)
                .unwrap()
                .to_string()
        );
    }
}
