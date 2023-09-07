use std::{sync::Arc, time::Duration};
use tokio::time::sleep;
mod backing;
mod error;
mod issuing;

pub use backing::Backing;
pub use error::Error;
pub use issuing::{Issuing, RandomDelay};

// 10 minutes = 600 seconds
const SLEEP_TIME: Duration = Duration::from_secs(600);

/// Retrieves `batch` blocks starting at block `height` from the backing blockchain
async fn collect_headers<T>(height: u32, batch: u32, cli: &impl Backing) -> Result<Vec<Vec<u8>>, Error<T>> {
    let mut headers = Vec::new();
    for h in height..height + batch {
        headers.push(
            cli.get_block_header(h)
                .await
                .map(|header| header.ok_or(Error::BlockHeaderNotFound))??,
        );
    }
    Ok(headers)
}

/// Computes the height at which the relayer should start to submit blocks.
/// In most cases it should be from the next block after the highest block
/// stored by the issuing blockchain
async fn compute_start_height<T: Issuing>(backing: &impl Backing, issuing: &T) -> Result<u32, Error<T::Error>> {
    let mut start_height = issuing.get_best_height().await.map_err(Error::RuntimeError)?;

    // check backing for discrepancy
    let mut relay_hash = issuing
        .get_block_hash(start_height)
        .await
        .map_err(Error::RuntimeError)?;
    let mut btc_hash = backing.get_block_hash(start_height).await?;

    // backwards pass
    while relay_hash != btc_hash {
        start_height = start_height.checked_sub(1).ok_or(Error::NotInitialized)?;
        relay_hash = issuing
            .get_block_hash(start_height)
            .await
            .map_err(Error::RuntimeError)?;
        btc_hash = backing.get_block_hash(start_height).await?;
    }

    // forward pass (possible forks)
    loop {
        match backing.get_block_hash(start_height).await {
            Ok(h) if issuing.is_block_stored(h.clone()).await.map_err(Error::RuntimeError)? => {
                start_height = start_height.saturating_add(1);
            }
            _ => break,
        }
    }

    // found matching parent start on next
    Ok(start_height)
}

#[derive(Default)]
pub struct Config {
    /// Initialization height, if unset will use `get_block_count`
    pub start_height: Option<u32>,
    /// Maximum number of headers to collect on catchup
    pub max_batch_size: u32,
    /// Thread sleep duration
    pub interval: Option<Duration>,
    /// Number of confirmations a block needs to have before it is submitted.
    pub btc_confirmations: u32,
}

/// Runner implements the main loop for the relayer
pub struct Runner<B: Backing, I: Issuing> {
    backing: B,
    issuing: I,
    start_height: Option<u32>,
    max_batch_size: u32,
    interval: Duration,
    btc_confirmations: u32,
    random_delay: Arc<Box<dyn RandomDelay<Error = I::Error> + Send + Sync>>,
}

impl<B: Backing, I: Issuing> Runner<B, I> {
    pub fn new(
        backing: B,
        issuing: I,
        conf: Config,
        random_delay: Arc<Box<dyn RandomDelay<Error = I::Error> + Send + Sync>>,
    ) -> Runner<B, I> {
        Runner {
            backing,
            issuing,
            random_delay,
            start_height: conf.start_height,
            max_batch_size: conf.max_batch_size,
            interval: conf.interval.unwrap_or(SLEEP_TIME),
            btc_confirmations: conf.btc_confirmations,
        }
    }

    /// Returns the block header at `height`
    async fn get_block_header(&self, height: u32) -> Result<Vec<u8>, Error<I::Error>> {
        loop {
            match self.backing.get_block_header(height).await? {
                Some(header) => return Ok(header),
                None => {
                    log::trace!("No block found at height {}, sleeping for {:?}", height, self.interval);
                    sleep(self.interval).await
                }
            };
        }
    }

    async fn get_num_confirmed_blocks(&self) -> Result<u32, Error<I::Error>> {
        Ok(self
            .backing
            .get_block_count()
            .await?
            .saturating_sub(self.btc_confirmations))
    }

    /// Submit the next block(s) or initialize the relay,
    /// may submit up to `max_batch_size` blocks at a time
    pub async fn submit_next(&self) -> Result<(), Error<I::Error>> {
        if !self.issuing.is_initialized().await.map_err(Error::RuntimeError)? {
            let start_height = self.start_height.unwrap_or(self.get_num_confirmed_blocks().await?);
            log::info!("Initializing at height {}", start_height);
            self.issuing
                .initialize(
                    self.backing.get_block_header(start_height).await?.unwrap(),
                    start_height,
                )
                .await
                .map_err(Error::RuntimeError)?;
        }

        let max_height = self.get_num_confirmed_blocks().await?;
        log::trace!("Backing height: {}", max_height);
        let current_height = compute_start_height(&self.backing, &self.issuing).await?;
        log::trace!("Issuing height: {}", current_height);

        let batch_size = if current_height.saturating_add(self.max_batch_size) > max_height {
            max_height.saturating_add(1).saturating_sub(current_height)
        } else {
            self.max_batch_size
        };

        match batch_size {
            0 => {
                // nothing to submit right now. Wait a little while
                log::trace!("Waiting for the next Bitcoin block...");
                sleep(self.interval).await;
            }
            1 => {
                // submit a single block header
                log::info!("Processing block at height {}", current_height);
                let header = self.get_block_header(current_height).await?;
                // TODO: check if block already stored
                self.issuing
                    .submit_block_header(header, self.random_delay.clone())
                    .await
                    .map_err(Error::RuntimeError)?;
                log::info!("Submitted block at height {}", current_height);
            }
            _ => {
                log::info!(
                    "Processing blocks {} -> {} [{}]",
                    current_height,
                    current_height + batch_size,
                    batch_size
                );
                let headers = collect_headers(current_height, batch_size, &self.backing).await?;
                self.issuing
                    .submit_block_header_batch(headers)
                    .await
                    .map_err(Error::RuntimeError)?;
                log::info!(
                    "Submitted blocks {} -> {} [{}]",
                    current_height,
                    current_height + batch_size,
                    batch_size
                );
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::relay::RandomDelay;

    use super::*;

    use async_trait::async_trait;
    use std::{
        cell::{Ref, RefCell, RefMut},
        collections::HashMap,
        rc::Rc,
    };

    #[derive(Clone, Debug)]
    pub struct ZeroDelay;

    #[async_trait]
    impl RandomDelay for ZeroDelay {
        type Error = DummyError;
        async fn delay(&self, _seed_data: &[u8; 32]) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    struct DummyIssuing {
        headers: Rc<RefCell<HashMap<u32, Vec<u8>>>>,
    }

    unsafe impl Sync for DummyIssuing {}

    impl DummyIssuing {
        fn new(headers: HashMap<u32, Vec<u8>>) -> DummyIssuing {
            DummyIssuing {
                headers: Rc::new(RefCell::new(headers)),
            }
        }

        fn get_headers(&self) -> Ref<HashMap<u32, Vec<u8>>> {
            self.headers.borrow()
        }

        fn get_headers_mut(&self) -> RefMut<HashMap<u32, Vec<u8>>> {
            self.headers.borrow_mut()
        }
    }

    #[derive(Debug, PartialEq)]
    pub enum DummyError {
        AlreadyInitialized,
        CannotFetchBestHeight,
        BlockExists,
        BlockHashNotFound,
    }
    #[async_trait]
    impl Issuing for DummyIssuing {
        type Error = DummyError;

        async fn is_initialized(&self) -> Result<bool, Self::Error> {
            Ok(!self.get_headers().is_empty())
        }

        async fn initialize(&self, header: Vec<u8>, height: u32) -> Result<(), Self::Error> {
            if self.get_headers().is_empty() {
                self.get_headers_mut().insert(height, header);
                Ok(())
            } else {
                Err(DummyError::AlreadyInitialized)
            }
        }

        async fn submit_block_header(
            &self,
            header: Vec<u8>,
            _random_delay: Arc<Box<dyn RandomDelay<Error = DummyError> + Send + Sync>>,
        ) -> Result<(), Self::Error> {
            let is_stored = self.is_block_stored(header.clone()).await?;
            if is_stored {
                Err(DummyError::BlockExists)
            } else {
                let height = self.get_best_height().await? + 1;
                // NOTE: assume hash(header) == header
                self.get_headers_mut().insert(height, header);
                Ok(())
            }
        }

        async fn submit_block_header_batch(&self, headers: Vec<Vec<u8>>) -> Result<(), Self::Error> {
            for header in headers {
                self.submit_block_header(header.to_vec(), Arc::new(Box::new(ZeroDelay)))
                    .await?;
            }
            Ok(())
        }

        async fn get_best_height(&self) -> Result<u32, Self::Error> {
            self.get_headers()
                .keys()
                .max()
                .copied()
                .ok_or(DummyError::CannotFetchBestHeight)
        }

        async fn get_block_hash(&self, height: u32) -> Result<Vec<u8>, Self::Error> {
            self.get_headers()
                .get(&height)
                .cloned()
                .ok_or(DummyError::BlockHashNotFound)
        }

        async fn is_block_stored(&self, hash: Vec<u8>) -> Result<bool, Self::Error> {
            Ok(self.get_headers().iter().any(|(_, h)| &h[..] == &hash[..]))
        }
    }

    struct DummyBacking {
        hashes: HashMap<u32, Vec<u8>>,
    }

    impl DummyBacking {
        fn new(hashes: HashMap<u32, Vec<u8>>) -> DummyBacking {
            DummyBacking { hashes }
        }
    }

    #[async_trait]
    impl Backing for DummyBacking {
        async fn get_block_count(&self) -> Result<u32, crate::Error> {
            self.hashes.keys().max().copied().ok_or(crate::Error::ConnectionRefused) // arbitrary error
        }

        async fn get_block_header(&self, height: u32) -> Result<Option<Vec<u8>>, crate::Error> {
            Ok(self.hashes.get(&height).cloned())
        }

        async fn get_block_hash(&self, height: u32) -> Result<Vec<u8>, crate::Error> {
            self.hashes.get(&height).cloned().ok_or(crate::Error::ConnectionRefused) // arbitrary error
        }
    }

    fn make_hash(hash_hex: &str) -> Vec<u8> {
        hash_hex.as_bytes().to_vec()
    }

    fn make_hashes(hashes: Vec<(u32, &str)>) -> HashMap<u32, Vec<u8>> {
        hashes.iter().map(|(k, v)| (*k, make_hash(v))).collect()
    }

    #[tokio::test]
    async fn test_dummy_issuing() {
        let hashes = make_hashes(vec![(2, "a"), (3, "b"), (4, "c")]);
        let issuing = DummyIssuing::new(hashes);

        assert_eq!(
            issuing.initialize(make_hash("x"), 1).await,
            Err(DummyError::AlreadyInitialized)
        );
        assert_eq!(issuing.get_best_height().await, Ok(4));
        assert_eq!(issuing.get_block_hash(2).await, Ok(make_hash("a")));
        assert_eq!(issuing.get_block_hash(5).await, Err(DummyError::BlockHashNotFound));
        assert_eq!(issuing.is_block_stored(make_hash("a")).await, Ok(true));
        assert_eq!(issuing.is_block_stored(make_hash("x")).await, Ok(false));
        assert_eq!(
            issuing
                .submit_block_header(make_hash("a"), Arc::new(Box::new(ZeroDelay)))
                .await,
            Err(DummyError::BlockExists)
        );
        assert_eq!(
            issuing
                .submit_block_header(make_hash("d"), Arc::new(Box::new(ZeroDelay)))
                .await,
            Ok(())
        );
        assert_eq!(issuing.get_best_height().await, Ok(5));
    }

    #[tokio::test]
    async fn compute_start_height_simple() {
        let hashes = make_hashes(vec![(2, "a"), (3, "b"), (4, "c")]);
        let backing = DummyBacking::new(hashes.clone());
        let issuing = DummyIssuing::new(hashes);
        assert_eq!(5, compute_start_height(&backing, &issuing).await.unwrap());
    }

    #[tokio::test]
    async fn compute_start_height_missing_blocks() {
        let backing_hashes = make_hashes(vec![(2, "a"), (3, "b"), (4, "c")]);
        let issuing_hashes = make_hashes(vec![(2, "a"), (3, "b")]);
        let backing = DummyBacking::new(backing_hashes);
        let issuing = DummyIssuing::new(issuing_hashes);
        assert_eq!(4, compute_start_height(&backing, &issuing).await.unwrap());
    }

    #[tokio::test]
    async fn compute_start_height_with_fork() {
        // height of c should also be 4 but we cannot model fork with this dummy implementation
        let backing_hashes = make_hashes(vec![(2, "a"), (3, "b"), (4, "c")]);
        let issuing_hashes = make_hashes(vec![(2, "a"), (3, "b"), (4, "d"), (0, "c")]);
        let backing = DummyBacking::new(backing_hashes);
        let issuing = DummyIssuing::new(issuing_hashes);
        assert_eq!(5, compute_start_height(&backing, &issuing).await.unwrap());
    }

    #[tokio::test]
    async fn new_runner_with_best() {
        let hashes = make_hashes(vec![(2, "a"), (3, "b"), (4, "c")]);
        let backing = DummyBacking::new(hashes.clone());
        let issuing = DummyIssuing::new(hashes);
        let runner = Runner::new(
            backing,
            issuing,
            Config {
                start_height: None,
                max_batch_size: 1,
                interval: None,
                btc_confirmations: 0,
            },
            Arc::new(Box::new(ZeroDelay)),
        );

        assert_eq!(runner.issuing.get_best_height().await.unwrap(), 4);
    }

    #[tokio::test]
    async fn catchup_when_out_of_sync() {
        let backing_hashes = make_hashes(vec![(2, "a"), (3, "b"), (4, "c"), (5, "d"), (6, "e")]);
        let issuing_hashes = make_hashes(vec![(2, "a"), (3, "b")]);
        let backing = DummyBacking::new(backing_hashes);
        let issuing = DummyIssuing::new(issuing_hashes);
        let runner = Runner::new(
            backing,
            issuing,
            Config {
                start_height: Some(0),
                max_batch_size: 16,
                interval: None,
                btc_confirmations: 0,
            },
            Arc::new(Box::new(ZeroDelay)),
        );

        let height_before = runner.issuing.get_best_height().await.unwrap();
        assert_eq!(height_before, 3);

        runner.submit_next().await.unwrap();
        let height_after = runner.issuing.get_best_height().await.unwrap();
        assert_eq!(height_after, 6);

        let best_height = runner.backing.get_block_count().await.unwrap();
        assert_eq!(height_after, best_height);

        assert!(runner.issuing.is_block_stored(make_hash("c")).await.unwrap());
        assert!(runner.issuing.is_block_stored(make_hash("d")).await.unwrap());
        assert!(runner.issuing.is_block_stored(make_hash("e")).await.unwrap());
    }

    #[tokio::test]
    async fn submit_next_success() {
        let backing_hashes = make_hashes(vec![(2, "a"), (3, "b"), (4, "c"), (5, "d")]);
        let issuing_hashes = make_hashes(vec![(2, "a"), (3, "b")]);
        let backing = DummyBacking::new(backing_hashes);
        let issuing = DummyIssuing::new(issuing_hashes);
        let runner = Runner::new(
            backing,
            issuing,
            Config {
                start_height: None,
                max_batch_size: 1,
                interval: None,
                btc_confirmations: 0,
            },
            Arc::new(Box::new(ZeroDelay)),
        );

        let height_before = runner.issuing.get_best_height().await.unwrap();
        assert_eq!(height_before, 3);

        runner.submit_next().await.unwrap();
        let height_after = runner.issuing.get_best_height().await.unwrap();
        assert_eq!(height_after, 4);

        assert!(runner.issuing.is_block_stored(make_hash("c")).await.unwrap());
        assert!(!runner.issuing.is_block_stored(make_hash("d")).await.unwrap());
    }

    #[tokio::test]
    async fn submit_next_with_1_confirmation_batch_submission_succeeds() {
        let backing_hashes = make_hashes(vec![(2, "a"), (3, "b"), (4, "c"), (5, "d")]);
        let issuing_hashes = make_hashes(vec![(2, "a")]);
        let backing = DummyBacking::new(backing_hashes);
        let issuing = DummyIssuing::new(issuing_hashes);
        let runner = Runner::new(
            backing,
            issuing,
            Config {
                start_height: None,
                interval: Some(Duration::from_secs(0)),
                max_batch_size: 16,
                btc_confirmations: 1,
            },
            Arc::new(Box::new(ZeroDelay)),
        );

        let height_before = runner.issuing.get_best_height().await.unwrap();
        assert_eq!(height_before, 2);

        runner.submit_next().await.unwrap();
        runner.submit_next().await.unwrap();

        let height_after = runner.issuing.get_best_height().await.unwrap();
        assert_eq!(height_after, 4);

        assert!(runner.issuing.is_block_stored(make_hash("c")).await.unwrap());
        // this block has not been confirmed yet, so we should not have submitted it
        assert!(!runner.issuing.is_block_stored(make_hash("d")).await.unwrap());
    }

    #[tokio::test]
    async fn submit_next_with_1_confirmation_single_submission_succeeds() {
        let backing_hashes = make_hashes(vec![(2, "a"), (3, "b"), (4, "c"), (5, "d")]);
        let issuing_hashes = make_hashes(vec![(2, "a")]);
        let backing = DummyBacking::new(backing_hashes);
        let issuing = DummyIssuing::new(issuing_hashes);
        let runner = Runner::new(
            backing,
            issuing,
            Config {
                start_height: None,
                max_batch_size: 1,
                interval: Some(Duration::from_secs(0)),
                btc_confirmations: 1,
            },
            Arc::new(Box::new(ZeroDelay)),
        );

        let height_before = runner.issuing.get_best_height().await.unwrap();
        assert_eq!(height_before, 2);

        for _ in 0..10 {
            runner.submit_next().await.unwrap();
        }

        let height_after = runner.issuing.get_best_height().await.unwrap();
        assert_eq!(height_after, 4);

        assert!(runner.issuing.is_block_stored(make_hash("c")).await.unwrap());
        // this block has not been confirmed yet, so we should not have submitted it
        assert!(!runner.issuing.is_block_stored(make_hash("d")).await.unwrap());
    }

    #[tokio::test]
    async fn submit_next_with_2_confirmation_succeeds() {
        let backing_hashes = make_hashes(vec![(2, "a"), (3, "b"), (4, "c"), (5, "d")]);
        let issuing_hashes = make_hashes(vec![(2, "a")]);
        let backing = DummyBacking::new(backing_hashes);
        let issuing = DummyIssuing::new(issuing_hashes);
        let runner = Runner::new(
            backing,
            issuing,
            Config {
                start_height: None,
                max_batch_size: 1,
                interval: Some(Duration::from_secs(0)),
                btc_confirmations: 2,
            },
            Arc::new(Box::new(ZeroDelay)),
        );

        let height_before = runner.issuing.get_best_height().await.unwrap();
        assert_eq!(height_before, 2);

        for _ in 0..10 {
            runner.submit_next().await.unwrap();
        }

        let height_after = runner.issuing.get_best_height().await.unwrap();
        assert_eq!(height_after, 3);

        assert!(runner.issuing.is_block_stored(make_hash("b")).await.unwrap());

        // these blocks have not been confirmed yet, so we should not have submitted it
        assert!(!runner.issuing.is_block_stored(make_hash("c")).await.unwrap());
        assert!(!runner.issuing.is_block_stored(make_hash("d")).await.unwrap());
    }
}