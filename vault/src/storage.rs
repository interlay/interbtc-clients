use crate::Error;
use bitcoin::{deserialize, serialize, Error as BitcoinError, Transaction};
use rocksdb::DB as RocksDb;
use runtime::H256;
use std::{collections::HashMap, sync::Mutex};

pub trait TransactionStore {
    /// Fetch the transaction by ID.
    fn get_tx(&self, id: &H256) -> Result<Transaction, Error>;

    /// Insert the transaction.
    fn put_tx(&self, id: H256, tx: Transaction) -> Result<(), Error>;
}

impl TransactionStore for Mutex<HashMap<H256, Transaction>> {
    fn get_tx(&self, id: &H256) -> Result<Transaction, Error> {
        self.lock()
            .unwrap()
            .get(id)
            .map(ToOwned::to_owned)
            .ok_or(Error::TransactionNotFound)
    }

    fn put_tx(&self, id: H256, tx: Transaction) -> Result<(), Error> {
        let mut tx_store = self.lock().unwrap();
        tx_store.insert(id, tx);
        Ok(())
    }
}

impl TransactionStore for RocksDb {
    fn get_tx(&self, id: &H256) -> Result<Transaction, Error> {
        let raw_tx = self.get(id)?.ok_or(Error::TransactionNotFound)?;
        Ok(deserialize(&raw_tx).map_err(Into::<BitcoinError>::into)?)
    }

    fn put_tx(&self, id: H256, tx: Transaction) -> Result<(), Error> {
        self.put(id, serialize(&tx))?;
        Ok(())
    }
}
