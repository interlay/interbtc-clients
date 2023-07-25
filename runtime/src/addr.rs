use crate::{BtcAddress, H160};
use bitcoin::{
    json::bitcoin::ScriptBuf, Address, ConversionError, Hash, Network, Payload, PubkeyHash, ScriptHash, WPubkeyHash,
    WScriptHash,
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
            Payload::PubkeyHash(hash) => Ok(Self::P2PKH(H160::from(hash.to_byte_array()))),
            Payload::ScriptHash(hash) => Ok(Self::P2SH(H160::from(hash.to_byte_array()))),
            Payload::WitnessProgram(witness_program) => {
                let program = witness_program.program();

                if program.len() == 20 {
                    Ok(Self::P2WPKHv0(H160::from_slice(program.as_bytes())))
                } else {
                    Err(ConversionError::InvalidPayload)
                }
            }
            _ => {
                // catch-all required due to non_exhaustive annotation - at the time of writing
                // all cases are actually caught
                Err(ConversionError::InvalidFormat)
            }
        }
    }

    fn to_payload(&self) -> Result<Payload, ConversionError> {
        let script = match self {
            Self::P2PKH(hash) => ScriptBuf::new_p2pkh(&PubkeyHash::from_slice(hash.as_bytes())?),
            Self::P2SH(hash) => ScriptBuf::new_p2sh(&ScriptHash::from_slice(hash.as_bytes())?),
            Self::P2WPKHv0(hash) => ScriptBuf::new_v0_p2wpkh(&WPubkeyHash::from_slice(hash.as_bytes())?),
            Self::P2WSHv0(hash) => ScriptBuf::new_v0_p2wsh(&WScriptHash::from_slice(hash.as_bytes())?),
        };

        Ok(Payload::from_script(&script)?)
    }

    fn from_address(address: Address) -> Result<Self, ConversionError> {
        Self::from_payload(address.payload)
    }

    fn to_address(&self, network: Network) -> Result<Address, ConversionError> {
        let payload = self.to_payload()?;
        Ok(Address::new(network, payload))
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
        Ok(Address::new(network, self.clone()))
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
            Payload::from_address(
                Address::from_str(addr)
                    .unwrap()
                    .require_network(Network::Regtest)
                    .unwrap()
            )
            .unwrap()
            .to_address(Network::Regtest)
            .unwrap()
            .to_string()
        );
    }
}
