use runtime::BtcAddress;
use sp_core::H256;
use std::{borrow::Borrow, collections::HashMap, hash::Hash};
use tokio::sync::{Mutex, MutexGuard};

#[derive(Debug, Default)]
pub struct ReversibleHashMap<K, V>((HashMap<K, V>, HashMap<V, K>));

impl<K, V> ReversibleHashMap<K, V>
where
    K: Hash + Eq + Copy + Default,
    V: Hash + Eq + Copy + Default,
{
    pub fn new() -> ReversibleHashMap<K, V> {
        Default::default()
    }

    /// Inserts a reversible key-value pair into the map.
    ///
    /// If the map did not have a key present, None is returned.
    pub fn insert(&mut self, k: K, v: V) -> (Option<K>, Option<V>) {
        let k1 = self.0 .0.insert(k, v);
        let k2 = self.0 .1.insert(v, k);
        (k2, k1)
    }

    /// Remove the from the reversible map by the key.
    pub fn remove_key<Q: ?Sized>(&mut self, k: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq,
    {
        if let Some(v) = self.0 .0.remove(k) {
            self.0 .1.remove(&v);
            Some(v)
        } else {
            None
        }
    }

    /// Remove the from the reversible map by the value.
    pub fn remove_value<Q: ?Sized>(&mut self, v: &Q) -> Option<K>
    where
        V: Borrow<Q>,
        Q: Hash + Eq,
    {
        if let Some(k) = self.0 .1.remove(v) {
            self.0 .0.remove(&k);
            Some(k)
        } else {
            None
        }
    }

    /// Get the key associated with the value
    pub fn get_key_for_value<Q: ?Sized>(&mut self, v: &Q) -> Option<&K>
    where
        V: Borrow<Q>,
        Q: Hash + Eq,
    {
        self.0 .1.get(v)
    }
}

pub struct IssueRequests(Mutex<ReversibleHashMap<H256, BtcAddress>>);

impl IssueRequests {
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) async fn lock(&self) -> MutexGuard<'_, ReversibleHashMap<H256, BtcAddress>> {
        self.0.lock().await
    }

    pub(crate) async fn insert(&self, issue_id: H256, address: BtcAddress) -> (Option<H256>, Option<BtcAddress>) {
        self.0.lock().await.insert(issue_id, address)
    }

    pub(crate) async fn remove(&self, issue_id: &H256) -> Option<BtcAddress> {
        self.0.lock().await.remove_key(issue_id)
    }
}

impl Default for IssueRequests {
    fn default() -> Self {
        Self(Mutex::new(ReversibleHashMap::new()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_add_key_value_pair() {
        let mut rev_hash_map = ReversibleHashMap::<u32, u32>::new();
        assert_eq!(rev_hash_map.insert(13, 37), (None, None));
        assert_eq!(rev_hash_map.insert(13, 37), (Some(13), Some(37)));
        assert_eq!(rev_hash_map.get_key_for_value(&37), Some(&13));
        assert_eq!(rev_hash_map.remove_key(&13), Some(37));
        assert_eq!(rev_hash_map.remove_key(&37), None);
    }
}
