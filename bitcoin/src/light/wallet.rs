use super::{electrs::ElectrsClient, error::Error};
use crate::{
    hashes::Hash,
    json::bitcoin::SigHashType,
    opcodes, psbt,
    psbt::PartiallySignedTransaction,
    secp256k1::{All, Message, Secp256k1, SecretKey, Signature},
    util::bip143::SigHashCache,
    Address, Builder as ScriptBuilder, Network, PrivateKey, Script, Transaction, TxIn, TxOut, H256,
};
use std::{
    collections::BTreeMap,
    sync::{Arc, RwLock},
};

fn p2wpkh_script_code(script: &Script) -> Script {
    ScriptBuilder::new()
        .push_opcode(opcodes::OP_DUP)
        .push_opcode(opcodes::OP_HASH160)
        .push_slice(&script[2..])
        .push_opcode(opcodes::OP_EQUALVERIFY)
        .push_opcode(opcodes::OP_CHECKSIG)
        .into_script()
}

pub type KeyStore = Arc<RwLock<BTreeMap<Address, PrivateKey>>>;

#[derive(Clone)]
pub struct Wallet {
    secp: Secp256k1<All>,
    network: Network,
    electrs: ElectrsClient,
    pub(crate) key_store: KeyStore,
}

impl Wallet {
    pub fn new(network: Network, electrs: ElectrsClient) -> Self {
        Self {
            secp: Secp256k1::new(),
            network,
            electrs,
            key_store: Arc::new(RwLock::new(Default::default())),
        }
    }
}

impl Wallet {
    pub async fn fund_transaction(
        &self,
        tx: Transaction,
        change_address: Address,
        fee: u64,
    ) -> Result<PartiallySignedTransaction, Error> {
        // TODO: estimate tx fee
        let mut total_in = 0;
        let total_out = tx
            .output
            .iter()
            .map(|tx_out| tx_out.value)
            .sum::<u64>()
            .saturating_add(fee);

        let mut psbt = PartiallySignedTransaction::from_unsigned_tx(tx).unwrap();

        let addresses = self.key_store.read().unwrap().keys().cloned().collect::<Vec<_>>();
        for address in addresses {
            log::info!("Found address: {}", address);
            // get utxos for address
            let utxos = self.electrs.get_utxos_for_address(address).await?;
            for utxo in utxos {
                log::info!("Found utxo: {}", utxo.outpoint.txid);

                total_in += utxo.value;

                let script_pubkey = self.electrs.get_script_pubkey(utxo.outpoint).await?;

                psbt.global.unsigned_tx.input.push(TxIn {
                    previous_output: utxo.outpoint,
                    ..Default::default()
                });

                psbt.inputs.push(psbt::Input {
                    witness_utxo: Some(TxOut {
                        value: utxo.value,
                        script_pubkey,
                    }),
                    ..Default::default()
                });

                if total_in >= total_out {
                    // add change output
                    psbt.global.unsigned_tx.output.push(TxOut {
                        value: total_in.saturating_sub(total_out),
                        script_pubkey: change_address.script_pubkey(),
                    });

                    return Ok(psbt);
                }
            }
        }

        Err(Error::NotEnoughInputs)
    }

    pub fn put_p2wpkh_key(&self, secret_key: SecretKey) -> Result<(), Error> {
        let private_key = PrivateKey::new(secret_key, self.network);
        let public_key = private_key.public_key(&self.secp);
        let address = Address::p2wpkh(&public_key, self.network)?;
        log::info!("Added key for address {}", address);
        self.key_store.write().unwrap().insert(address, private_key);
        Ok(())
    }

    pub fn create_transaction(&self, recipient: Address, value: u64, maybe_op_return: Option<H256>) -> Transaction {
        let mut output = vec![TxOut {
            value,
            script_pubkey: recipient.script_pubkey(),
        }];
        if let Some(op_return) = maybe_op_return {
            output.push(TxOut {
                value: 0,
                script_pubkey: ScriptBuilder::new()
                    .push_opcode(opcodes::OP_RETURN)
                    .push_slice(op_return.as_bytes())
                    .into_script(),
            })
        }

        Transaction {
            version: 2,
            lock_time: Default::default(),
            input: Default::default(),
            output,
        }
    }

    pub fn sign_transaction(&self, psbt: &mut PartiallySignedTransaction) -> Result<(), Error> {
        for inp in 0..psbt.inputs.len() {
            let psbt_input = &psbt.inputs[inp];

            let prev_out = psbt_input.witness_utxo.clone().unwrap();

            let sighash_ty = psbt_input.sighash_type.unwrap_or_else(|| SigHashType::All.into());

            let script_code = if prev_out.script_pubkey.is_v0_p2wpkh() {
                Ok(p2wpkh_script_code(&prev_out.script_pubkey))
            } else {
                Err(Error::InvalidPrevOut)
            }?;

            let mut sig_hasher = SigHashCache::new(&psbt.global.unsigned_tx);
            let sig_hash = sig_hasher.signature_hash(inp, &script_code, prev_out.value, sighash_ty);

            let address = Address::from_script(&prev_out.script_pubkey, self.network).ok_or(Error::InvalidAddress)?;
            let key_store = self.key_store.read().unwrap();
            let private_key = key_store.get(&address).ok_or(Error::NoPrivateKey)?;

            let sig = self.secp.sign(
                &Message::from_slice(&sig_hash.into_inner()[..]).unwrap(),
                &private_key.key,
            );

            pub struct EcdsaSig {
                pub sig: Signature,
                pub hash_ty: SigHashType,
            }

            impl EcdsaSig {
                pub fn to_vec(&self) -> Vec<u8> {
                    // TODO: add support to serialize to a writer to SerializedSig
                    self.sig
                        .serialize_der()
                        .iter()
                        .map(|x| *x)
                        .chain(std::iter::once(self.hash_ty as u8))
                        .collect()
                }
            }

            let final_signature = EcdsaSig {
                sig,
                hash_ty: sighash_ty,
            };

            psbt.inputs[inp]
                .partial_sigs
                .insert(private_key.public_key(&self.secp), final_signature.to_vec());

            // psbt_input.final_script_witness = Some(Witness::from_vec(vec![
            //     final_signature.to_vec(),
            //     private_key.public_key(&self.secp).to_bytes(),
            // ]));
        }

        for psbt_input in psbt.inputs.iter_mut() {
            let (key, sig) = psbt_input.partial_sigs.iter().next().unwrap();

            psbt_input.final_script_witness = Some(vec![sig.clone().to_vec(), key.to_bytes()]);
        }

        Ok(())
    }
}
