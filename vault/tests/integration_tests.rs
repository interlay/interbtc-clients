#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]

use bitcoin::{
    secp256k1::{PublicKey, SecretKey, Secp256k1, rand::rngs::OsRng}, key, Network, Address,
    serialize, BitcoinCore, BitcoinCoreApi, Block, BlockHash, BlockHeader, Error as BitcoinError,
    GetBlockResult, Hash, LockedTransaction, OutPoint, PartialAddress, Script, Transaction,
    TransactionMetadata, TxIn, TxMerkleNode, TxOut, Txid, Uint256, PUBLIC_KEY_SIZE,
    PartialMerkleTree, 
};
use runtime::pallets::btc_relay::{TransactionBuilder, TransactionInputBuilder, TransactionOutput};
use runtime::UtilFuncs;
use runtime::BtcAddress::P2PKH;
use runtime::{
    pallets::issue::*,
    pallets::redeem::*,
    substrate_subxt::{Event, PairSigner},
    BlockBuilder, BtcAddress, BtcPublicKey, BtcRelayPallet, ExchangeRateOraclePallet,
    FixedPointNumber, FixedU128, Formattable, H256Le, IssuePallet, PolkaBtcProvider,
    PolkaBtcRuntime, RawBlockHeader, RedeemPallet, ReplacePallet, VaultRegistryPallet,
};
use sp_core::H160;
use sp_core::H256;
use sp_core::U256;
use sp_keyring::AccountKeyring;
// use staked_relayer;
use async_trait::async_trait;
use futures::future::Either;
use futures::pin_mut;
use futures::FutureExt;
use futures::SinkExt;
use futures::StreamExt;
use jsonrpsee::Client as JsonRpseeClient;
use log::*;
use rand::distributions::Uniform;
use rand::{thread_rng, Rng};
use std::convert::TryInto;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use substrate_subxt_client::{
    DatabaseConfig, KeystoreConfig, Role, SubxtClient, SubxtClientConfig,
};
use tempdir::TempDir;
use tokio::sync::{RwLock, Mutex, OwnedMutexGuard};
use tokio::time::delay_for;
use vault;

fn default_vault_args() -> vault::Opts {
    vault::Opts {
        polka_btc_url: "".to_string(), // only used by bin
        http_addr: "".to_string(),     // only used by bin
        rpc_cors_domain: "*".to_string(),
        auto_register_with_collateral: Some(50000000),
        no_auto_auction: false,
        no_auto_replace: false,
        no_startup_collateral_increase: false,
        max_collateral: 50000000,
        collateral_timeout_ms: 1000,
        no_api: true,
        account_info: runtime::cli::ProviderUserOpts {
            keyname: None,
            keyfile: None,
            keyring: Some(AccountKeyring::Bob),
        },
        btc_confirmations: None,
        no_issue_execution: false,
        bitcoin: bitcoin::cli::BitcoinOpts {
            bitcoin_rpc_url: "http://localhost:18443".to_string(),
            bitcoin_rpc_user: "rpcuser".to_string(),
            bitcoin_rpc_pass: "rpcpassword".to_string(),
        },
        network: vault::BitcoinNetwork::from_str("regtest").unwrap(),
    }
}

async fn default_provider_client(key: AccountKeyring) -> (JsonRpseeClient, TempDir) {
    let tmp = TempDir::new("btc-parachain-").expect("failed to create tempdir");
    let config = SubxtClientConfig {
        impl_name: "btc-parachain-full-client",
        impl_version: "0.0.1",
        author: "Interlay Ltd",
        copyright_start_year: 2020,
        db: DatabaseConfig::ParityDb {
            path: tmp.path().join("db"),
        },
        keystore: KeystoreConfig::Path {
            path: tmp.path().join("keystore"),
            password: None,
        },
        chain_spec: btc_parachain::chain_spec::development_config(true).unwrap(),
        role: Role::Authority(key.clone()),
        telemetry: None,
    };

    let client = SubxtClient::from_config(config, btc_parachain::service::new_full)
        .expect("Error creating subxt client")
        .into();
    return (client, tmp);
}

async fn setup_provider(client: JsonRpseeClient, key: AccountKeyring) -> PolkaBtcProvider {
    let signer = PairSigner::<PolkaBtcRuntime, _>::new(key.pair());
    PolkaBtcProvider::new(client, signer)
        .await
        .expect("Error creating provider")
}

async fn send_transaction(provider: &PolkaBtcProvider) {
    let address = BtcAddress::P2PKH(H160::zero());
    // place the transaction into the mempool
    let block = BlockBuilder::new()
        .with_version(2)
        .with_coinbase(&address, 50, 3)
        .with_timestamp(1588813835)
        .mine(U256::from(2).pow(254.into()));
    let output_address = BtcAddress::P2PKH(H160::zero());

    let transaction = TransactionBuilder::new()
        .with_version(2)
        .add_input(
            TransactionInputBuilder::new()
                .with_coinbase(false)
                .with_previous_hash(block.transactions[0].hash())
                .with_script(&[
                    0, 71, 48, 68, 2, 32, 91, 128, 41, 150, 96, 53, 187, 63, 230, 129, 53, 234,
                    210, 186, 21, 187, 98, 38, 255, 112, 30, 27, 228, 29, 132, 140, 155, 62, 123,
                    216, 232, 168, 2, 32, 72, 126, 179, 207, 142, 8, 99, 8, 32, 78, 244, 166, 106,
                    160, 207, 227, 61, 210, 172, 234, 234, 93, 59, 159, 79, 12, 194, 240, 212, 3,
                    120, 50, 1, 71, 81, 33, 3, 113, 209, 131, 177, 9, 29, 242, 229, 15, 217, 247,
                    165, 78, 111, 80, 79, 50, 200, 117, 80, 30, 233, 210, 167, 133, 175, 62, 253,
                    134, 127, 212, 51, 33, 2, 128, 200, 184, 235, 148, 25, 43, 34, 28, 173, 55, 54,
                    189, 164, 187, 243, 243, 152, 7, 84, 210, 85, 156, 238, 77, 97, 188, 240, 162,
                    197, 105, 62, 82, 174,
                ])
                .build(),
        )
        .add_output(TransactionOutput::payment(10000.into(), &output_address))
        .add_output(TransactionOutput::op_return(0, H256::zero().as_bytes()))
        .build();

    let block = BlockBuilder::new()
        .with_previous_hash(block.header.hash())
        .with_version(2)
        .with_coinbase(&address, 50, 3)
        .with_timestamp(1588813835)
        .add_transaction(transaction)
        .mine(U256::from(2).pow(254.into()));

    let block_header = RawBlockHeader::from_bytes(&block.header.format()).unwrap();
    provider.store_block_header(block_header).await.unwrap();
}

async fn initialize_btc_relay(provider: &PolkaBtcProvider) {
    let height = 0;
    let address = BtcAddress::P2PKH(H160::zero());
    let block = BlockBuilder::new()
        .with_version(2)
        .with_coinbase(&address, 50, 3)
        .with_timestamp(1588813835)
        .mine(U256::from(2).pow(254.into()));

    let block_header = RawBlockHeader::from_bytes(&block.header.format())
        .expect("could not serialize block header");

    provider
        .initialize_btc_relay(block_header, height)
        .await
        .unwrap();
}

struct MockBitcoinCore {
    provider: Arc<PolkaBtcProvider>,
    blocks: RwLock<Vec<Block>>,
    transaction_creation_lock: Arc<Mutex<()>>,
}

pub fn merkle_proof(block: &Block) -> Vec<u8> {
    let mut ret = Vec::new();

    // header
    ret.append(&mut serialize(&block.header));

    let txids = block.txdata.iter().map(|x| x.txid()).collect::<Vec<_>>();
    let partial_merkle_tree = PartialMerkleTree::from_txids(&txids, &[false, true]);
    ret.append(&mut serialize(&partial_merkle_tree));
// 
// 
//     // number of transcations:
//     ret.append(&mut serialize(&(block.txdata.len() as u32)));
// 
//     // number of hashes:
//     ret.push(block.txdata.len() as u8);
// 
// 
//     // hashes
//     for tx in block.txdata.iter() {
//         ret.append(&mut tx.txid().as_ref().to_vec());
//     }
// 
//     // number of bytes of flag bits:
//     ret.push(1);
// 
//     // flag bits:
//     ret.push(3);

    ret
}

impl MockBitcoinCore {
    fn new(provider: Arc<PolkaBtcProvider>) -> Self {
        Self {
            provider,
            blocks: RwLock::new(vec![]),
            transaction_creation_lock: Arc::new(Mutex::new(()))
        }
    }
    async fn send_block(&self, address: BtcAddress, amount: u64) -> Block {
        let block = self.generate_block(address, amount).await;

        let raw_block_header = serialize(&block.header);
        self.provider
            .store_block_header(raw_block_header.try_into().unwrap())
            .await
            .unwrap();

        block
    }
    async fn generate_block_with_transaction(&self, transaction: &Transaction) -> Block {
        let target = U256::from(2).pow(254.into());
        let mut bytes = [0u8; 32];
        target.to_big_endian(&mut bytes);
        let target = Uint256::from_be_bytes(bytes);

        let mut blocks = self.blocks.write().await;

        let prev_blockhash = if blocks.is_empty() {
            Default::default()
        } else {
            blocks[blocks.len() - 1].header.block_hash()
        };

        let mut block = Block {
            txdata: vec![
                Self::generate_coinbase_transaction(
                    &BtcAddress::P2PKH(H160::from([1; 20])),
                    10000,
                    blocks.len() as u32,
                ), 
                transaction.clone()
            ],
            header: BlockHeader {
                version: 2,
                merkle_root: Default::default(),
                bits: BlockHeader::compact_target_from_u256(&target),
                nonce: 0,
                prev_blockhash,
                time: 1,
            },
        };
        block.header.merkle_root = block.merkle_root();

        loop {
            if let Ok(_) = block.header.validate_pow(&target) {
                break;
            }
            block.header.nonce += 1;
        }


        blocks.push(block.clone());
            
        block
    }
    async fn generate_block(&self, address: BtcAddress, amount: u64) -> Block {
        self.generate_block_with_transaction(&Self::generate_normal_transaction(
                &address,
                amount,
            )).await
    }

    fn generate_normal_transaction<A: PartialAddress + Send + 'static> (
        address: &A,
        reward: u64,
    ) -> Transaction {
        let address:BtcAddress = BtcAddress::decode_str(&address.encode_str(Network::Regtest).unwrap()).unwrap();
        let address = Script::from(address.to_script().as_bytes().to_vec());

        Transaction {
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_slice(&[1;32]).unwrap(),
                    vout: 0,
                }, // coinbase
                witness: vec![],
                script_sig: Script::from(vec![0, 71, 48, 68, 2, 32, 91, 128, 41, 150, 96, 53, 187, 63, 230, 129, 53, 234,
                    210, 186, 21, 187, 98, 38, 255, 112, 30, 27, 228, 29, 132, 140, 155, 62, 123,
                    216, 232, 168, 2, 32, 72, 126, 179, 207, 142, 8, 99, 8, 32, 78, 244, 166, 106,
                    160, 207, 227, 61, 210, 172, 234, 234, 93, 59, 159, 79, 12, 194, 240, 212, 3,
                    120, 50, 1, 71, 81, 33, 3, 113, 209, 131, 177, 9, 29, 242, 229, 15, 217, 247,
                    165, 78, 111, 80, 79, 50, 200, 117, 80, 30, 233, 210, 167, 133, 175, 62, 253,
                    134, 127, 212, 51, 33, 2, 128, 200, 184, 235, 148, 25, 43, 34, 28, 173, 55, 54,
                    189, 164, 187, 243, 243, 152, 7, 84, 210, 85, 156, 238, 77, 97, 188, 240, 162,
                    197, 105, 62, 82, 174]),
                sequence: u32::max_value(),
            }],
            output: vec![TxOut {
                script_pubkey: address,
                value: reward,
            }],
            lock_time: 0,
            version: 2,
        }
    }

    fn generate_coinbase_transaction(
        address: &BtcAddress,
        reward: u64,
        height: u32,
    ) -> Transaction {
        let address = Script::from(address.to_script().as_bytes().to_vec());

        Transaction {
            input: vec![TxIn {
                previous_output: OutPoint::null(), // coinbase
                witness: vec![],
                script_sig: Default::default(),
                sequence: u32::max_value(),
            }],
            output: vec![TxOut {
                script_pubkey: address,
                value: reward,
            }],
            lock_time: height,
            version: 1,
        }
    }

    async fn init(self) -> Self {
        let address = BtcAddress::P2PKH(H160::from([0; 20]));

        let block = self.generate_block(address, 10000).await;

        let raw_block_header = serialize(&block.header);
        self.provider
            .initialize_btc_relay(raw_block_header.try_into().unwrap(), 0)
            .await
            .unwrap();

        self
    }
}

#[async_trait]
impl BitcoinCoreApi for MockBitcoinCore {
    async fn wait_for_block(
        &self,
        height: u32,
        delay: Duration,
        num_confirmations: u32,
    ) -> Result<BlockHash, BitcoinError> {
        loop {
            {
                let blocks = self.blocks.read().await;
                if let Some(block) = blocks.get(height as usize) {
                    return Ok(block.header.block_hash());
                }
            }
            delay_for(Duration::from_secs(1)).await;
        }
    }
    async fn get_block_count(&self) -> Result<u64, BitcoinError> {
        Ok(self.blocks.read().await.len().try_into().unwrap())
    }
    async fn get_raw_tx_for(
        &self,
        txid: &Txid,
        block_hash: &BlockHash,
    ) -> Result<Vec<u8>, BitcoinError> {
        let blocks = self.blocks.read().await;

        let transaction = blocks.iter().find_map(|x| {
            x.txdata.iter().find(|y| &y.txid() == txid) 
        }).ok_or(BitcoinError::InvalidBitcoinHeight)?;
        
        Ok(serialize(transaction))
    }
    async fn get_proof_for(
        &self,
        txid: Txid,
        block_hash: &BlockHash,
    ) -> Result<Vec<u8>, BitcoinError> {
        let blocks = self.blocks.read().await;

        // we assume the txid is at index 1
        let block = blocks.iter().find(|x| x.txdata[1].txid() == txid) 
            .ok_or(BitcoinError::InvalidBitcoinHeight)?;

        Ok(merkle_proof(&block))
    }
    async fn get_block_hash_for(&self, height: u32) -> Result<BlockHash, BitcoinError> {
        let blocks = self.blocks.read().await;
        let block = blocks.get(height as usize)
            .ok_or(BitcoinError::InvalidBitcoinHeight)?;
        Ok(block.header.block_hash())
    }
    async fn is_block_known(&self, block_hash: BlockHash) -> Result<bool, BitcoinError> {
        Ok(self.blocks.read().await.iter().any(|x| x.block_hash() == block_hash))
    }
    async fn get_new_address<A: PartialAddress + Send + 'static>(&self) -> Result<A, BitcoinError> {
        let bytes: [u8; 20] = (0..20).map(|_| thread_rng().gen::<u8>()).collect::<Vec<_>>().as_slice().try_into().unwrap();
        let address = BtcAddress::P2PKH(H160::from(bytes));
        Ok(A::decode_str(&address.to_string())?)
    }
    async fn get_new_public_key<P: From<[u8; PUBLIC_KEY_SIZE]> + 'static>(
        &self,
    ) -> Result<P, BitcoinError> {
        let secp = Secp256k1::new();
        let mut rng = OsRng::new().unwrap();
        let secret_key = SecretKey::new(&mut rng);
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        Ok(P::from(public_key.serialize()))
    }
    async fn add_new_deposit_key<P: Into<[u8; PUBLIC_KEY_SIZE]> + Send + Sync + 'static>(
        &self,
        public_key: P,
        secret_key: Vec<u8>,
    ) -> Result<(), BitcoinError> {
        Ok(())
    }
    async fn get_best_block_hash(&self) -> Result<BlockHash, BitcoinError> {
        let blocks = self.blocks.read().await;
        Ok(blocks[blocks.len() - 1].block_hash())
    }
    async fn get_block(&self, hash: &BlockHash) -> Result<Block, BitcoinError> {
        let blocks = self.blocks.read().await;
        let block = blocks.iter().find(|x| &x.block_hash() == hash)
            .ok_or(BitcoinError::InvalidBitcoinHeight)?;
        Ok(block.clone())
    }
    async fn get_block_info(&self, hash: &BlockHash) -> Result<GetBlockResult, BitcoinError> {
        let blocks = self.blocks.read().await;

        let (block_height, block) = blocks
            .iter()
            .enumerate()
            .find(|x| &x.1.block_hash() == hash) 
            .ok_or(BitcoinError::InvalidBitcoinHeight)?;
        Ok(GetBlockResult {
            height: block_height,
            hash: block.block_hash(),
            confirmations: Default::default(),
            size: Default::default(),
            strippedsize: Default::default(),
            weight: Default::default(),
            version: Default::default(),
            version_hex: Default::default(),
            merkleroot: Default::default(),
            tx: Default::default(),
            time: Default::default(),
            mediantime: Default::default(),
            nonce: Default::default(),
            bits: Default::default(),
            difficulty: Default::default(),
            chainwork: Default::default(),
            n_tx: Default::default(),
            previousblockhash: Default::default(),
            nextblockhash: Default::default(),
        })
    }
    async fn get_mempool_transactions<'a>(
        self: Arc<Self>,
    ) -> Result<Box<dyn Iterator<Item = Result<Transaction, BitcoinError>> + Send + 'a>, BitcoinError>
    {
        Ok(Box::new(std::iter::empty()))
    }
    async fn wait_for_transaction_metadata(
        &self,
        txid: Txid,
        op_timeout: Duration,
        num_confirmations: u32,
    ) -> Result<TransactionMetadata, BitcoinError> {
        let blocks = self.blocks.read().await;
        let (block_height, block) = blocks
            .iter()
            .enumerate()
            .find(|x| x.1.txdata[1].txid() == txid) 
            .ok_or(BitcoinError::InvalidBitcoinHeight)?;
        let block_hash = block.block_hash();
        let proof = self.get_proof_for(txid, &block_hash).await.unwrap();
        let raw_tx = self.get_raw_tx_for(&txid, &block_hash).await.unwrap();

        Ok(TransactionMetadata {
            block_hash,
            proof,
            raw_tx,
            txid,
            block_height: block_height as u32
        })
    }
    async fn create_transaction<A: PartialAddress + Send + 'static>(
        &self,
        address: A,
        sat: u64,
        request_id: &[u8; 32],
    ) -> Result<LockedTransaction, BitcoinError> {

        let mut op_return_script = vec![0x6a, 32];
        op_return_script.append(&mut request_id.to_vec());
        
        let op_return = TxOut {
            value: 0,
            script_pubkey: Script::from(op_return_script),
        };
        let mut transaction = MockBitcoinCore::generate_normal_transaction(&address, sat);
        transaction.output.push(op_return);

        Ok(LockedTransaction::new(transaction, self.transaction_creation_lock.clone().lock_owned().await))
    }
    async fn send_transaction(&self, transaction: LockedTransaction) -> Result<Txid, BitcoinError> {
        let block = self.generate_block_with_transaction(&transaction.transaction).await;
        Ok(block.txdata[1].txid())
    }
    async fn create_and_send_transaction<A: PartialAddress + Send + 'static>(
        &self,
        address: A,
        sat: u64,
        request_id: &[u8; 32],
    ) -> Result<Txid, BitcoinError> {
        let tx = self.create_transaction(address, sat, request_id).await?;
        let txid = self.send_transaction(tx).await?;
        Ok(txid)
    }
    async fn send_to_address<A: PartialAddress + Send + 'static>(
        &self,
        address: A,
        sat: u64,
        request_id: &[u8; 32],
        op_timeout: Duration,
        num_confirmations: u32,
    ) -> Result<TransactionMetadata, BitcoinError> {
        let txid = self
            .create_and_send_transaction(address, sat, request_id)
            .await.unwrap();
        let metadata = self
            .wait_for_transaction_metadata(txid, op_timeout, num_confirmations)
            .await
            .unwrap();
        Ok(metadata)
    }
    async fn create_wallet(&self, wallet: &str) -> Result<(), BitcoinError> {
        Ok(())
    }
    async fn wallet_has_public_key<P>(&self, public_key: P) -> Result<bool, BitcoinError>
    where
        P: Into<[u8; PUBLIC_KEY_SIZE]>
            + From<[u8; PUBLIC_KEY_SIZE]>
            + Clone
            + PartialEq
            + Send
            + Sync
            + 'static,
    {
        Ok(true)
    }
}


trait Translate {
    type Associated;
    fn translate(&self) -> Self::Associated;
}

impl Translate for Txid {
    type Associated = H256Le;
    fn translate(&self) -> Self::Associated {
        H256Le::from_bytes_le(&self.to_vec())
    }
}



#[tokio::test]
async fn test_issue_succeeds() {
    let (client, _tmp_dir) = default_provider_client(AccountKeyring::Alice).await;
    let alice_provider = setup_provider(client.clone(), AccountKeyring::Alice).await;
    initialize_btc_relay(&alice_provider).await;
    send_transaction(&alice_provider).await;
}

#[tokio::test]
async fn test_start_vault_succeeds() {
    let _ = env_logger::try_init();

    let (client, _tmp_dir) = default_provider_client(AccountKeyring::Alice).await;
    let relayer_provider = setup_provider(client.clone(), AccountKeyring::Bob).await;

    let btc_rpc = MockBitcoinCore::new(Arc::new(relayer_provider))
        .init()
        .await;

    let address = BtcAddress::P2PKH(H160::from([0; 20]));

    let relayer_provider = setup_provider(client.clone(), AccountKeyring::Bob).await;
    btc_rpc.send_block(address, 10000).await;
    btc_rpc.send_block(address, 10000).await;

    relayer_provider.set_exchange_rate_info(FixedU128::saturating_from_rational(1u128, 100)).await.unwrap();

    let vault_provider = setup_provider(client.clone(), AccountKeyring::Charlie).await;
    let key = btc_rpc.get_new_public_key().await.unwrap();

    vault_provider.register_vault(100000000000, key).await.unwrap();

    let user_provider = setup_provider(client.clone(), AccountKeyring::Dave).await;


    let issue = user_provider.request_issue(100000, vault_provider.get_account_id().clone(), 10000).await.unwrap();

    let address = BtcAddress::P2PKH(H160::from_slice(&[2;20]));

    let block = btc_rpc.send_block(issue.btc_address, issue.amount as u64).await;

    let proof = btc_rpc.get_proof_for(block.txdata[1].txid(), &block.header.block_hash()).await.unwrap();
    let raw_tx = btc_rpc.get_raw_tx_for(&block.txdata[1].txid(), &block.header.block_hash()).await.unwrap();
    user_provider.execute_issue(issue.issue_id, block.txdata[1].txid().translate(), proof, raw_tx).await.unwrap();


    //     vault_provider
    //     .set_exchange_rate_info(FixedU128::checked_from_rational(10000u128, 100_000).unwrap())
    //     .await
    //     .unwrap();
    // 
    //     let opts = default_vault_args();
    //     let btc_rpc = Arc::new(MockBitcoinCore::new(Arc::new(relayer_provider)).init().await);

    //     // let mut btc_rpc = MockBitcoin::default();
    //
    //
    //     // block.consensus_encode(writer)
    //
    //
    //
    //     let fut_issue = || async {
    //         delay_for(Duration::from_secs(10)).await;
    //     };
    //
    //     let fut_vault = vault::start(opts, Arc::new(vault_provider), btc_rpc);
}
