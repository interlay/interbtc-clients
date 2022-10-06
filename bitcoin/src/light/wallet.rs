use bitcoincore_rpc::bitcoin::{
    blockdata::{constants::WITNESS_SCALE_FACTOR, transaction::NonStandardSighashType},
    PackedLockTime, PublicKey, Witness,
};

use super::{electrs::ElectrsClient, error::Error};
use crate::{
    hashes::Hash,
    json::bitcoin::SigHashType,
    opcodes, psbt,
    psbt::PartiallySignedTransaction,
    secp256k1::{All, Message, Secp256k1, SecretKey, Signature},
    util::bip143::SigHashCache,
    Address, Builder as ScriptBuilder, Network, OutPoint, PrivateKey, Script, Transaction, TxIn, TxOut, VarInt, H256,
};
use std::{
    collections::BTreeMap,
    sync::{Arc, RwLock},
};

trait GetSerializeSize {
    fn get_serialize_size(&self) -> u64;
}

impl GetSerializeSize for TxOut {
    // https://github.com/bitcoin/bitcoin/blob/2ab4a80480b6d538ec2a642f7f96c635c725317b/src/primitives/transaction.h#L161
    fn get_serialize_size(&self) -> u64 {
        (8 + VarInt(self.script_pubkey.len() as u64).len() + self.script_pubkey.len()) as u64
    }
}

impl GetSerializeSize for TxIn {
    // https://github.com/bitcoin/bitcoin/blob/2ab4a80480b6d538ec2a642f7f96c635c725317b/src/primitives/transaction.h#L128
    fn get_serialize_size(&self) -> u64 {
        (32 + 4 + 4 + VarInt(self.script_sig.len() as u64).len() + self.script_sig.len()) as u64
    }
}

impl GetSerializeSize for Vec<Vec<u8>> {
    fn get_serialize_size(&self) -> u64 {
        let mut input_weight = 0;
        input_weight += VarInt(self.len() as u64).len();
        for elem in self {
            input_weight += VarInt(elem.len() as u64).len() + elem.len();
        }
        input_weight as u64
    }
}

impl GetSerializeSize for Witness {
    fn get_serialize_size(&self) -> u64 {
        self.to_vec().get_serialize_size()
    }
}

// https://github.com/bitcoin/bitcoin/blob/607d5a46aa0f5053d8643a3e2c31a69bfdeb6e9f/src/script/sign.cpp#L611
fn dummy_sign_input(txin: &mut TxIn, public_key: PublicKey) {
    // create a dummy signature that is a valid DER-encoding
    let dummy_signature = {
        let m_r_len = 32;
        let m_s_len = 32;

        let mut vch_sig = vec![0; m_r_len + m_s_len + 7];
        vch_sig[0] = 0x30;
        vch_sig[1] = (m_r_len + m_s_len + 4) as u8;
        vch_sig[2] = 0x02;
        vch_sig[3] = m_r_len as u8;
        vch_sig[4] = 0x01;
        vch_sig[4 + m_r_len] = 0x02;
        vch_sig[5 + m_r_len] = m_s_len as u8;
        vch_sig[6 + m_r_len] = 0x01;
        vch_sig[6 + m_r_len + m_s_len] = SigHashType::All as u8;
        vch_sig
    };

    // update input (only works with segwit for now)
    txin.witness = Witness::from_vec(vec![dummy_signature.to_vec(), public_key.to_bytes()]);
}

// https://github.com/bitcoin/bitcoin/blob/e9035f867a36a430998e3811385958229ac79cf5/src/consensus/validation.h#L156
fn get_transaction_input_weight(txin: TxIn) -> u64 {
    txin.get_serialize_size() * (WITNESS_SCALE_FACTOR as u64 - 1)
        + txin.get_serialize_size()
        + txin.witness.get_serialize_size()
}

// https://github.com/bitcoin/bitcoin/blob/f6fdedf850d10d877316871aacfd5b6656178e70/src/policy/policy.cpp#L295
fn get_virtual_transaction_size(n_weight: u64) -> u64 {
    (n_weight + WITNESS_SCALE_FACTOR as u64 - 1) / WITNESS_SCALE_FACTOR as u64
}

// https://github.com/bitcoin/bitcoin/blob/01e1627e25bc5477c40f51da03c3c31b609a85c9/src/wallet/spend.cpp#L30
fn calculate_maximum_signed_input_size(outpoint: OutPoint, public_key: PublicKey) -> u64 {
    let mut txin = TxIn {
        previous_output: outpoint,
        ..Default::default()
    };
    dummy_sign_input(&mut txin, public_key);

    // GetVirtualTransactionInputSize = GetVirtualTransactionSize(GetTransactionInputWeight(txin));
    get_virtual_transaction_size(get_transaction_input_weight(txin))
}

// https://github.com/bitcoin/bitcoin/blob/01e1627e25bc5477c40f51da03c3c31b609a85c9/src/wallet/spend.cpp#L47
fn calculate_maximum_signed_tx_size(psbt: &PartiallySignedTransaction, wallet: &Wallet) -> u64 {
    let mut tx = psbt.clone().extract_tx();

    // https://github.com/bitcoin/bitcoin/blob/5291933fedceb9df16eb9e4627b1d7386b53ba07/src/wallet/wallet.cpp#L1608
    for (i, txin) in tx.input.iter_mut().enumerate() {
        let tx_out = psbt.inputs[i].witness_utxo.as_ref().expect("psbt has witness utxo");
        let public_key = wallet.get_pub_key(&tx_out.script_pubkey).expect("wallet has key");
        dummy_sign_input(txin, public_key)
    }

    // GetVirtualTransactionSize = GetVirtualTransactionSize(GetTransactionWeight(tx))
    get_virtual_transaction_size(tx.get_weight() as u64)
}

struct FeeRate {
    // Fee rate in sat/kvB (satoshis per 1000 virtualbytes)
    n_satoshis_per_k: u64,
}

impl FeeRate {
    // https://github.com/bitcoin/bitcoin/blob/2ab4a80480b6d538ec2a642f7f96c635c725317b/src/policy/feerate.cpp#L23
    fn get_fee(&self, num_bytes: u64) -> u64 {
        self.n_satoshis_per_k.saturating_mul(num_bytes).div_ceil(1000)
    }
}

struct CoinOutput {
    value: u64,
    fee: u64,
}

impl CoinOutput {
    // output's value minus fees required to spend it
    fn get_effective_value(&self) -> u64 {
        self.value.saturating_sub(self.fee)
    }
}

struct SelectCoins {
    preset_inputs: Vec<CoinOutput>,
    target_value: u64,
}

impl SelectCoins {
    fn new(target_value: u64) -> Self {
        Self {
            preset_inputs: vec![],
            target_value,
        }
    }

    fn add(&mut self, coin_output: CoinOutput) {
        self.preset_inputs.push(coin_output);
    }

    // https://github.com/bitcoin/bitcoin/blob/2bd9aa5a44b88c866c4d98f8a7bf7154049cba31/src/wallet/coinselection.cpp#L425
    fn get_selected_value(&self) -> u64 {
        self.preset_inputs.iter().map(|input| input.value).sum()
    }

    // https://github.com/bitcoin/bitcoin/blob/2bd9aa5a44b88c866c4d98f8a7bf7154049cba31/src/wallet/coinselection.cpp#L430
    fn get_selected_effective_value(&self) -> u64 {
        self.preset_inputs.iter().map(|input| input.get_effective_value()).sum()
    }

    // https://github.com/bitcoin/bitcoin/blob/2bd9aa5a44b88c866c4d98f8a7bf7154049cba31/src/wallet/coinselection.cpp#L495
    fn get_change(&self, min_viable_change: u64, change_fee: u64) -> u64 {
        // change = SUM(inputs) - SUM(outputs) - fees
        let change = self
            .get_selected_effective_value()
            .saturating_sub(self.target_value)
            .saturating_sub(change_fee);

        if change < min_viable_change {
            0
        } else {
            change
        }
    }
}

// https://github.com/bitcoindevkit/bdk/blob/061f15af004ce16ea107cfcbe86e0120be22eaa8/src/wallet/signer.rs#L818
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

    pub fn get_priv_key(&self, script_pubkey: &Script) -> Result<PrivateKey, Error> {
        let address = Address::from_script(script_pubkey, self.network)?;
        let key_store = self.key_store.read()?;
        let private_key = key_store.get(&address).ok_or(Error::NoPrivateKey)?;
        Ok(*private_key)
    }

    pub fn get_pub_key(&self, script_pubkey: &Script) -> Result<PublicKey, Error> {
        Ok(self.get_priv_key(script_pubkey)?.public_key(&self.secp))
    }

    pub async fn fund_transaction(
        &self,
        tx: Transaction,
        change_address: Address,
        n_satoshis_per_k: u64,
    ) -> Result<PartiallySignedTransaction, Error> {
        let recipients_sum = tx.output.iter().map(|tx_out| tx_out.value).sum::<u64>();

        let m_effective_feerate = FeeRate { n_satoshis_per_k };

        // TODO: calculate actual minimum
        let min_viable_change = 0;
        let change_output_size = TxOut {
            value: 0,
            script_pubkey: change_address.script_pubkey(),
        }
        .get_serialize_size();
        let change_fee = m_effective_feerate.get_fee(change_output_size);

        let tx_noinputs_size = 10
            + VarInt(tx.output.len() as u64).len() as u64
            + tx.output.iter().map(|tx_out| tx_out.get_serialize_size()).sum::<u64>();
        let not_input_fees = m_effective_feerate.get_fee(tx_noinputs_size);

        // https://github.com/bitcoin/bitcoin/blob/01e1627e25bc5477c40f51da03c3c31b609a85c9/src/wallet/spend.cpp#L896
        let selection_target = recipients_sum + not_input_fees;
        let mut value_to_select = selection_target;

        let mut psbt = PartiallySignedTransaction::from_unsigned_tx(tx)?;
        let mut select_coins = SelectCoins::new(selection_target);

        // get available coins
        let addresses = self.key_store.read()?.keys().cloned().collect::<Vec<_>>();
        for address in addresses {
            log::info!("Found address: {}", address);
            // get utxos for address
            let utxos = self.electrs.get_utxos_for_address(address).await?;
            // TODO: stream this, no need to fetch
            for utxo in utxos {
                log::info!("Found utxo: {}", utxo.outpoint.txid);

                let script_pubkey = self.electrs.get_script_pubkey(utxo.outpoint).await?;
                let public_key = self.get_pub_key(&script_pubkey).expect("wallet has key");
                let input_bytes = calculate_maximum_signed_input_size(utxo.outpoint, public_key);
                let coin_output = CoinOutput {
                    value: utxo.value,
                    fee: m_effective_feerate.get_fee(input_bytes),
                };

                let effective_value = coin_output.get_effective_value();
                select_coins.add(coin_output);
                value_to_select = value_to_select.saturating_sub(effective_value);

                psbt.unsigned_tx.input.push(TxIn {
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

                if value_to_select == 0 {
                    // add change output before computing maximum size
                    let change_amount = select_coins.get_change(min_viable_change, change_fee);
                    let mut n_change_pos_in_out = None;
                    if change_amount > 0 {
                        n_change_pos_in_out = Some(psbt.unsigned_tx.output.len());
                        // add change output
                        psbt.unsigned_tx.output.push(TxOut {
                            value: change_amount,
                            script_pubkey: change_address.script_pubkey(),
                        });
                    }

                    // https://github.com/bitcoin/bitcoin/blob/01e1627e25bc5477c40f51da03c3c31b609a85c9/src/wallet/spend.cpp#L945
                    let n_bytes = calculate_maximum_signed_tx_size(&psbt, self);
                    let fee_needed = m_effective_feerate.get_fee(n_bytes);
                    let n_fee_ret = select_coins.get_selected_value() - recipients_sum - change_amount;

                    if let Some(change_pos) = n_change_pos_in_out {
                        if fee_needed < n_fee_ret {
                            log::info!("Fee needed is less than expected");
                            let mut change_output = &mut psbt.unsigned_tx.output[change_pos];
                            change_output.value += n_fee_ret - fee_needed;
                        }
                    }

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
        self.key_store.write()?.insert(address, private_key);
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
            lock_time: PackedLockTime::ZERO,
            input: Default::default(),
            output,
        }
    }

    pub fn sign_transaction(&self, psbt: &mut PartiallySignedTransaction) -> Result<(), Error> {
        for inp in 0..psbt.inputs.len() {
            let psbt_input = &psbt.inputs[inp];

            let prev_out = psbt_input
                .witness_utxo
                .clone()
                .expect("utxo is always set in fund_transaction; qed");

            // Note: we don't support SchnorrSighashType
            let sighash_ty = match psbt_input.sighash_type {
                Some(x) => x
                    .ecdsa_hash_ty()
                    .map_err(|NonStandardSighashType(ty)| Error::PsbtError(psbt::Error::NonStandardSighashType(ty)))?,
                _ => SigHashType::All,
            };

            // TODO: support signing p2sh, p2pkh, p2wsh
            let script_code = if prev_out.script_pubkey.is_v0_p2wpkh() {
                Ok(p2wpkh_script_code(&prev_out.script_pubkey))
            } else {
                Err(Error::InvalidPrevOut)
            }?;

            let mut sig_hasher = SigHashCache::new(&psbt.unsigned_tx);
            let sig_hash = sig_hasher.signature_hash(inp, &script_code, prev_out.value, sighash_ty);

            let private_key = self.get_priv_key(&prev_out.script_pubkey)?;

            let sig = self
                .secp
                .sign(&Message::from_slice(&sig_hash.into_inner()[..])?, &private_key.key);

            pub struct EcdsaSig {
                pub sig: Signature,
                pub hash_ty: SigHashType,
            }

            impl EcdsaSig {
                // https://github.com/rust-bitcoin/rust-bitcoin/blob/deb867e33d30873c44c1d0c9917630ed52388d59/src/util/ecdsa.rs#L50
                pub fn to_vec(&self) -> Vec<u8> {
                    self.sig
                        .serialize_der()
                        .iter()
                        .copied()
                        .chain(std::iter::once(self.hash_ty as u8))
                        .collect()
                }
            }

            let final_signature = EcdsaSig {
                sig,
                hash_ty: sighash_ty,
            };

            // TODO: can we write directly to final_script_witness here?
            psbt.inputs[inp]
                .partial_sigs
                .insert(private_key.public_key(&self.secp), final_signature.to_vec());
        }

        for psbt_input in psbt.inputs.iter_mut() {
            let (key, sig) = psbt_input.partial_sigs.iter().next().expect("signature set above; qed");
            // https://github.com/bitcoin/bitcoin/blob/607d5a46aa0f5053d8643a3e2c31a69bfdeb6e9f/src/script/sign.cpp#L125
            psbt_input.final_script_witness = Some(Witness::from_vec(vec![sig.clone().to_vec(), key.to_bytes()]));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{deserialize, serialize};
    use bitcoincore_rpc::bitcoin::{
        consensus::Encodable,
        hashes::hex::{FromHex, ToHex},
        Txid,
    };
    use std::str::FromStr;

    #[test]
    fn should_select_coins() -> Result<(), Box<dyn std::error::Error>> {
        let mut select_coins = SelectCoins::new(50);
        let coin_output = CoinOutput { value: 100, fee: 10 };
        assert_eq!(coin_output.get_effective_value(), 90);

        select_coins.add(coin_output);
        assert_eq!(select_coins.get_selected_value(), 100);
        assert_eq!(select_coins.get_selected_effective_value(), 90);
        assert_eq!(select_coins.get_change(0, 5), 35);

        select_coins.add(CoinOutput { value: 10, fee: 1 });
        assert_eq!(select_coins.get_selected_value(), 110);
        assert_eq!(select_coins.get_selected_effective_value(), 99);
        assert_eq!(select_coins.get_change(0, 5), 44);

        Ok(())
    }

    #[test]
    fn should_get_serialize_size_segwit() -> Result<(), Box<dyn std::error::Error>> {
        // 8bbe885f5e49d31b0a3b17fb5f8677aa6a8e94fb45b572a2e21903c6376df204
        let tx_bytes = Vec::from_hex(
            "02000000000101fade6bd2ce8ab9c73f5d571e7c4b8cc0a5fa0952ada94be35748542a53d1435902000000\
            00ffffffff032085010000000000160014ff9da567e62f30ea8654fa1d5fbd47bef8e3be130000000000000\
            000226a2058c36f0b41bf0e50461bb4986c89e3ab1cddbae663a1d6560348bc82b698109762081600000000\
            001600149878a28b9c7418b0b4970054f176cb828ba87ddd02483045022100f68d61e62f522f825cc15a66d\
            231e4079b32c0e20ada460466254c998d5bffe6022017f8c4bc15aa0c632f14d7f5201dc26c80682cddb2e8\
            540a9208597416bbe005012103def3a3e3049f78321f577324c8e9d89f59745d9840c563ff73bf737822804\
            04f00000000",
        )
        .unwrap();
        let tx: Transaction = deserialize(&tx_bytes)?;

        fn assert_serialize_size<T>(data: &T)
        where
            T: GetSerializeSize + Encodable + ?Sized,
        {
            assert_eq!(data.get_serialize_size(), serialize(data).len() as u64);
        }

        assert_serialize_size(&tx.input[0]);
        assert_serialize_size(&tx.output[0]); // recipient
        assert_serialize_size(&tx.output[1]); // OP_RETURN
        assert_serialize_size(&tx.output[2]); // change

        assert_eq!(get_virtual_transaction_size(tx.get_weight() as u64), 184);

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_calculate_fees() -> Result<(), Box<dyn std::error::Error>> {
        let tx = Transaction {
            version: 2,
            lock_time: Default::default(),
            input: vec![TxIn {
                // value: 100000
                previous_output: OutPoint {
                    txid: Txid::from_str("0243dee566c0bf1b887416caa0e625b447c793786f1e6a5fc9c24f0d583f4c07")?,
                    vout: 0,
                },
                script_sig: Script::new(),
                sequence: 4294967293,
                witness: vec![
                    hex::decode("3044022025f214b6b3f1a0b9e1110367e260ca2ff8c614272b284839be77e06607d5f8f9022056404808a029bc0fee409ca4de812e0289b092d32299340fdaa13232f367d0f801")?,
                    hex::decode("0251bc49a18fc5af7662d04faa1929d44b7155ec723cc7f590efbf4e0fe18b14c6")?,
                ],
            }],
            output: vec![
                TxOut {
                   value: 0,
                   script_pubkey: Script::from_str("6a20f66966cde9d87d08cc58e6378cde0a57b21dd21a9688f2723aad4b184c56005b")?
                },
                TxOut {
                    value: 700,
                    script_pubkey: Script::from_str("0014810b092d165f424556b1c33fd343871a0cf4d36b")?
                },
                TxOut {
                    value: 99116,
                    script_pubkey: Script::from_str("00146b980ce352f5389938fae6ecd905d4c8af25b8d6")?
                }
            ],
        };

        assert_eq!(tx.get_size(), 265);
        assert_eq!(tx.get_weight(), 733);
        // vsize [vB] = weight [wu] / 4
        assert_eq!(tx.get_weight().div_ceil(WITNESS_SCALE_FACTOR), 184);
        assert_eq!(get_virtual_transaction_size(tx.get_weight() as u64), 184);

        let fee_rate = FeeRate { n_satoshis_per_k: 1000 };
        assert_eq!(
            fee_rate.get_fee(tx.get_weight().div_ceil(WITNESS_SCALE_FACTOR) as u64),
            184
        );

        let actual_fee = 100000 - tx.output.iter().map(|tx_out| tx_out.value).sum::<u64>();
        assert_eq!(actual_fee, 184);

        let input_bytes = calculate_maximum_signed_input_size(
            OutPoint {
                txid: Txid::from_str("0243dee566c0bf1b887416caa0e625b447c793786f1e6a5fc9c24f0d583f4c07")?,
                vout: 0,
            },
            PublicKey::from_str("0251bc49a18fc5af7662d04faa1929d44b7155ec723cc7f590efbf4e0fe18b14c6")?,
        );

        let outputs_no_change = vec![
            TxOut {
                value: 0,
                script_pubkey: Script::from_str(
                    "6a20f66966cde9d87d08cc58e6378cde0a57b21dd21a9688f2723aad4b184c56005b",
                )?,
            },
            TxOut {
                value: 99116,
                script_pubkey: Script::from_str("00146b980ce352f5389938fae6ecd905d4c8af25b8d6")?,
            },
        ];

        let tx_noinputs_size = 10
            + VarInt(outputs_no_change.len() as u64).len() as u64
            + outputs_no_change
                .iter()
                .map(|tx_out| tx_out.get_serialize_size())
                .sum::<u64>();
        let change_output_size = TxOut {
            value: 0,
            script_pubkey: Script::from_str("0014810b092d165f424556b1c33fd343871a0cf4d36b")?,
        }
        .get_serialize_size();

        assert_eq!(input_bytes + tx_noinputs_size + change_output_size, 184);

        Ok(())
    }

    macro_rules! map_btree {
        ($($k:expr => $v:expr),* $(,)?) => {{
            core::convert::From::from([$(($k, $v),)*])
        }};
    }

    #[test]
    fn should_sign_transaction() -> Result<(), Box<dyn std::error::Error>> {
        let secp = Secp256k1::new();

        let key_store: BTreeMap<_, _> = map_btree! {
            Address::from_str("bcrt1qxu0en0v9dsywqchvpr6g9aa5vh9wyeupys2ka8").unwrap() =>
            PrivateKey::from_wif("cNbq2Es45c5E8hYt6MT2Phk84A4tN3KSWxPzi8JpH61eW6Ttpusf").unwrap()
        };
        let wallet = Wallet {
            secp,
            network: Network::Regtest,
            electrs: ElectrsClient::new(None, Network::Regtest).unwrap(),
            key_store: Arc::new(RwLock::new(key_store)),
        };

        // 020000000001018971609cf35253baa5164e95f79effd9ed466a2a58e6a723b38327b81e5cd2dc0000000000fdffffff02a086010000000000160014998fced992b90c49c2295c5724edf0daf4748dca5c60042a01000000160014709467f945841c6bb638f9e107de2933e214f1c502473044022057aeb22db1f8656513b7f44df3a30d8405ba040cb250d731379307f1799f9cad02201582f355d461fd0c8ced789eb02053995663c66fc63a80341da9354ce3b23e580121028d16c10d62693f938deb171ad0a8323e389e79685da23795bb6e6503cb5db1c000000000
        let mut psbt = PartiallySignedTransaction {
            unsigned_tx: Transaction {
                version: 2,
                lock_time: 0,
                input: vec![TxIn {
                    previous_output: OutPoint {
                        txid: Txid::from_str("dcd25c1eb82783b323a7e6582a6a46edd9ff9ef7954e16a5ba5352f39c607189")?,
                        vout: 0,
                    },
                    script_sig: Default::default(),
                    sequence: 4294967293,
                    witness: Default::default(),
                }],
                output: vec![
                    TxOut {
                        value: 100000,
                        // bcrt1qnx8uakvjhyxyns3ft3tjfm0smt68frw2c9adgx
                        script_pubkey: Script::from_str("0014998fced992b90c49c2295c5724edf0daf4748dca")?,
                    },
                    TxOut {
                        value: 4999897180,
                        // bcrt1qwz2x0729sswxhd3cl8ss0h3fx03pfuw9anc7ww
                        script_pubkey: Script::from_str("0014709467f945841c6bb638f9e107de2933e214f1c5")?,
                    },
                ],
                xpub: Default::default(),
                version: 0,
                proprietary: Default::default(),
                unknown: Default::default(),
            },
            inputs: vec![psbt::Input {
                witness_utxo: Some(TxOut {
                    value: 5000000000,
                    script_pubkey: Address::from_str("bcrt1qxu0en0v9dsywqchvpr6g9aa5vh9wyeupys2ka8")?.script_pubkey(),
                }),
                ..Default::default()
            }],
            outputs: vec![Default::default(); 2],
        };

        wallet.sign_transaction(&mut psbt)?;
        let signed_tx = psbt.extract_tx();

        assert_eq!(
            "3044022057aeb22db1f8656513b7f44df3a30d8405ba040cb250d731379307f1799f9cad02201582f355d461fd0c8ced789eb02053995663c66fc63a80341da9354ce3b23e5801",
            signed_tx.input[0].witness[0].to_hex()
        );

        Ok(())
    }
}
