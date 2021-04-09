use std::{error::Error as StdError, marker::PhantomData, time::Duration};
use tokio::time::delay_for;

mod error;
mod types;

pub use error::Error;
pub use types::{Backing, Issuing};

// 10 minutes = 600 seconds
const SLEEP_TIME: u64 = 600;

/// Retrieves `batch` blocks starting at block `height` from the backing blockchain
async fn collect_headers<E: StdError>(
    height: u32,
    batch: u32,
    cli: &impl Backing<E>,
) -> Result<Vec<Vec<u8>>, Error<E>> {
    let mut headers = Vec::new();
    for h in height..height + batch {
        headers.push(cli.get_block_header(h).await.map(|header| header.unwrap())?);
    }
    Ok(headers)
}

/// Computes the height at which the relayer should start to submit blocks.
/// In most cases it should be from the next block after the highest block
/// stored by the issuing blockchain
async fn compute_start_height<E: StdError>(
    backing: &impl Backing<E>,
    issuing: &impl Issuing<E>,
) -> Result<u32, Error<E>> {
    let mut start_height = issuing.get_best_height().await?;

    // check backing for discrepancy
    let mut relay_hash = issuing.get_block_hash(start_height).await?;
    let mut btc_hash = backing.get_block_hash(start_height).await?;

    // backwards pass
    while relay_hash != btc_hash {
        start_height = start_height.checked_sub(1).ok_or(Error::NotInitialized)?;
        relay_hash = issuing.get_block_hash(start_height).await?;
        btc_hash = backing.get_block_hash(start_height).await?;
    }

    // forward pass (possible forks)
    loop {
        match backing.get_block_hash(start_height).await {
            Ok(h) if issuing.is_block_stored(h.clone()).await? => {
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
    // initialization height, if unset will use `get_block_count`
    pub start_height: Option<u32>,
    // maximum number of headers to collect on catchup
    pub max_batch_size: u32,
    // thread sleep duration
    pub timeout: Option<Duration>,
    ///Number of confirmations a block needs to have before it is submitted.
    pub required_btc_confirmations: u32,
}

/// Runner implements the main loop for the relayer
pub struct Runner<E: StdError, B: Backing<E>, I: Issuing<E>> {
    _marker: PhantomData<E>,
    backing: B,
    issuing: I,
    start_height: Option<u32>,
    max_batch_size: u32,
    timeout: Duration,
    required_btc_confirmations: u32,
}

impl<E: StdError, B: Backing<E>, I: Issuing<E>> Runner<E, B, I> {
    pub fn new(backing: B, issuing: I, conf: Config) -> Runner<E, B, I> {
        Runner {
            _marker: PhantomData {},
            backing,
            issuing,
            start_height: conf.start_height,
            max_batch_size: conf.max_batch_size,
            timeout: conf.timeout.unwrap_or_else(|| Duration::from_secs(SLEEP_TIME)),
            required_btc_confirmations: conf.required_btc_confirmations,
        }
    }

    /// Returns the block header at `height`
    async fn get_block_header(&self, height: u32) -> Result<Vec<u8>, Error<E>> {
        loop {
            match self.backing.get_block_header(height).await? {
                Some(header) => return Ok(header),
                None => {
                    tracing::trace!("No block found at height {}, sleeping for {:?}", height, self.timeout);
                    delay_for(self.timeout).await
                }
            };
        }
    }

    async fn get_num_confirmed_blocks(&self) -> Result<u32, Error<E>> {
        Ok(self
            .backing
            .get_block_count()
            .await?
            .saturating_sub(self.required_btc_confirmations))
    }

    /// Submit the next block(s) or initialize the relay,
    /// may submit up to `max_batch_size` blocks at a time
    pub async fn submit_next(&self) -> Result<(), Error<E>> {
        if !self.issuing.is_initialized().await? {
            let start_height = self.start_height.unwrap_or(self.get_num_confirmed_blocks().await?);
            tracing::info!("Initializing at height {}", start_height);
            self.issuing
                .initialize(
                    self.backing.get_block_header(start_height).await?.unwrap(),
                    start_height,
                )
                .await?;
        }

        let max_height = self.get_num_confirmed_blocks().await?;
        tracing::trace!("Backing height: {}", max_height);
        let current_height = compute_start_height(&self.backing, &self.issuing).await?;
        tracing::trace!("Issuing height: {}", current_height);

        let batch_size = if current_height.saturating_add(self.max_batch_size) > max_height {
            max_height.saturating_add(1).saturating_sub(current_height)
        } else {
            self.max_batch_size
        };

        match batch_size {
            0 => {
                // nothing to submit right now. Wait a little while
                tracing::trace!("Waiting for the next Bitcoin block...");
                delay_for(self.timeout).await;
            }
            1 => {
                // submit a single block header
                tracing::info!("Processing block at height {}", current_height);
                let header = self.get_block_header(current_height).await?;
                // TODO: check if block already stored
                self.issuing.submit_block_header(header).await?;
                tracing::info!("Submitted block at height {}", current_height);
            }
            _ => {
                tracing::info!(
                    "Processing blocks {} -> {} [{}]",
                    current_height,
                    current_height + batch_size,
                    batch_size
                );
                let headers = collect_headers(current_height, batch_size, &self.backing).await?;
                self.issuing.submit_block_header_batch(headers).await?;
                tracing::info!(
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
    use super::*;
    use async_trait::async_trait;
    use std::{
        cell::{Ref, RefCell, RefMut},
        collections::HashMap,
        rc::Rc,
    };

    #[derive(Debug, PartialEq)]
    struct DummyError();

    impl StdError for DummyError {}

    impl std::fmt::Display for DummyError {
        fn fmt(&self, _f: &mut std::fmt::Formatter) -> std::fmt::Result {
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

    #[async_trait]
    impl Issuing<DummyError> for DummyIssuing {
        async fn is_initialized(&self) -> Result<bool, Error<DummyError>> {
            Ok(!self.get_headers().is_empty())
        }

        async fn initialize(&self, header: Vec<u8>, height: u32) -> Result<(), Error<DummyError>> {
            if self.get_headers().is_empty() {
                self.get_headers_mut().insert(height, header);
                Ok(())
            } else {
                Err(Error::AlreadyInitialized)
            }
        }

        async fn submit_block_header(&self, header: Vec<u8>) -> Result<(), Error<DummyError>> {
            let is_stored = self.is_block_stored(header.clone()).await?;
            if is_stored {
                Err(Error::BlockExists)
            } else {
                let height = self.get_best_height().await? + 1;
                // NOTE: assume hash(header) == header
                self.get_headers_mut().insert(height, header);
                Ok(())
            }
        }

        async fn submit_block_header_batch(&self, headers: Vec<Vec<u8>>) -> Result<(), Error<DummyError>> {
            for header in headers {
                self.submit_block_header(header.to_vec()).await?;
            }
            Ok(())
        }

        async fn get_best_height(&self) -> Result<u32, Error<DummyError>> {
            self.get_headers()
                .keys()
                .max()
                .map(|v| *v)
                .ok_or(Error::CannotFetchBestHeight)
        }

        async fn get_block_hash(&self, height: u32) -> Result<Vec<u8>, Error<DummyError>> {
            self.get_headers()
                .get(&height)
                .map(|v| v.clone())
                .ok_or(Error::BlockHashNotFound)
        }

        async fn is_block_stored(&self, hash: Vec<u8>) -> Result<bool, Error<DummyError>> {
            Ok(self.get_headers().iter().find(|&(_, h)| &h[..] == &hash[..]).is_some())
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
    impl Backing<DummyError> for DummyBacking {
        async fn get_block_count(&self) -> Result<u32, Error<DummyError>> {
            self.hashes.keys().max().map(|v| *v).ok_or(Error::CannotFetchBestHeight)
        }

        async fn get_block_header(&self, height: u32) -> Result<Option<Vec<u8>>, Error<DummyError>> {
            Ok(self.hashes.get(&height).map(|v| v.clone()))
        }

        async fn get_block_hash(&self, height: u32) -> Result<Vec<u8>, Error<DummyError>> {
            self.hashes
                .get(&height)
                .map(|v| v.clone())
                .ok_or(Error::BlockHashNotFound)
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
            Err(Error::<DummyError>::AlreadyInitialized)
        );
        assert_eq!(issuing.get_best_height().await, Ok(4));
        assert_eq!(issuing.get_block_hash(2).await, Ok(make_hash("a")));
        assert_eq!(issuing.get_block_hash(5).await, Err(Error::BlockHashNotFound));
        assert_eq!(issuing.is_block_stored(make_hash("a")).await, Ok(true));
        assert_eq!(issuing.is_block_stored(make_hash("x")).await, Ok(false));
        assert_eq!(
            issuing.submit_block_header(make_hash("a")).await,
            Err(Error::BlockExists)
        );
        assert_eq!(issuing.submit_block_header(make_hash("d")).await, Ok(()));
        assert_eq!(issuing.get_best_height().await, Ok(5));
    }

    #[tokio::test]
    async fn compute_start_height_simple() {
        let hashes = make_hashes(vec![(2, "a"), (3, "b"), (4, "c")]);
        let backing = DummyBacking::new(hashes.clone());
        let issuing = DummyIssuing::new(hashes);
        assert_eq!(Ok(5), compute_start_height(&backing, &issuing).await);
    }

    #[tokio::test]
    async fn compute_start_height_missing_blocks() {
        let backing_hashes = make_hashes(vec![(2, "a"), (3, "b"), (4, "c")]);
        let issuing_hashes = make_hashes(vec![(2, "a"), (3, "b")]);
        let backing = DummyBacking::new(backing_hashes);
        let issuing = DummyIssuing::new(issuing_hashes);
        assert_eq!(Ok(4), compute_start_height(&backing, &issuing).await);
    }

    #[tokio::test]
    async fn compute_start_height_with_fork() {
        // height of c should also be 4 but we cannot model fork with this dummy implementation
        let backing_hashes = make_hashes(vec![(2, "a"), (3, "b"), (4, "c")]);
        let issuing_hashes = make_hashes(vec![(2, "a"), (3, "b"), (4, "d"), (0, "c")]);
        let backing = DummyBacking::new(backing_hashes);
        let issuing = DummyIssuing::new(issuing_hashes);
        assert_eq!(Ok(5), compute_start_height(&backing, &issuing).await);
    }

    #[tokio::test]
    async fn new_runner_with_best() -> Result<(), Error<DummyError>> {
        let hashes = make_hashes(vec![(2, "a"), (3, "b"), (4, "c")]);
        let backing = DummyBacking::new(hashes.clone());
        let issuing = DummyIssuing::new(hashes);
        let runner = Runner::new(
            backing,
            issuing,
            Config {
                start_height: None,
                max_batch_size: 1,
                timeout: None,
                required_btc_confirmations: 0,
            },
        );

        assert_eq!(runner.issuing.get_best_height().await.unwrap(), 4);
        Ok(())
    }

    #[tokio::test]
    async fn catchup_when_out_of_sync() -> Result<(), Error<DummyError>> {
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
                timeout: None,
                required_btc_confirmations: 0,
            },
        );

        let height_before = runner.issuing.get_best_height().await?;
        assert_eq!(height_before, 3);

        runner.submit_next().await?;
        let height_after = runner.issuing.get_best_height().await?;
        assert_eq!(height_after, 6);

        let best_height = runner.backing.get_block_count().await?;
        assert_eq!(height_after, best_height);

        assert!(runner.issuing.is_block_stored(make_hash("c")).await?);
        assert!(runner.issuing.is_block_stored(make_hash("d")).await?);
        assert!(runner.issuing.is_block_stored(make_hash("e")).await?);
        Ok(())
    }

    #[tokio::test]
    async fn submit_next_success() -> Result<(), Error<DummyError>> {
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
                timeout: None,
                required_btc_confirmations: 0,
            },
        );

        let height_before = runner.issuing.get_best_height().await?;
        assert_eq!(height_before, 3);

        runner.submit_next().await?;
        let height_after = runner.issuing.get_best_height().await?;
        assert_eq!(height_after, 4);

        assert!(runner.issuing.is_block_stored(make_hash("c")).await?);
        assert!(!runner.issuing.is_block_stored(make_hash("d")).await?);
        Ok(())
    }

    #[tokio::test]
    async fn submit_next_with_1_confirmation_batch_submission_succeeds() -> Result<(), Error<DummyError>> {
        let backing_hashes = make_hashes(vec![(2, "a"), (3, "b"), (4, "c"), (5, "d")]);
        let issuing_hashes = make_hashes(vec![(2, "a")]);
        let backing = DummyBacking::new(backing_hashes);
        let issuing = DummyIssuing::new(issuing_hashes);
        let runner = Runner::new(
            backing,
            issuing,
            Config {
                start_height: None,
                timeout: Some(Duration::from_secs(0)),
                max_batch_size: 16,
                required_btc_confirmations: 1,
            },
        );

        let height_before = runner.issuing.get_best_height().await?;
        assert_eq!(height_before, 2);

        runner.submit_next().await?;
        runner.submit_next().await?;

        let height_after = runner.issuing.get_best_height().await?;
        assert_eq!(height_after, 4);

        assert!(runner.issuing.is_block_stored(make_hash("c")).await?);
        // this block has not been confirmed yet, so we should not have submitted it
        assert!(!runner.issuing.is_block_stored(make_hash("d")).await?);
        Ok(())
    }

    #[tokio::test]
    async fn submit_next_with_1_confirmation_single_submission_succeeds() -> Result<(), Error<DummyError>> {
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
                timeout: Some(Duration::from_secs(0)),
                required_btc_confirmations: 1,
            },
        );

        let height_before = runner.issuing.get_best_height().await?;
        assert_eq!(height_before, 2);

        for _ in 0..10 {
            runner.submit_next().await?;
        }

        let height_after = runner.issuing.get_best_height().await?;
        assert_eq!(height_after, 4);

        assert!(runner.issuing.is_block_stored(make_hash("c")).await?);
        // this block has not been confirmed yet, so we should not have submitted it
        assert!(!runner.issuing.is_block_stored(make_hash("d")).await?);
        Ok(())
    }

    #[tokio::test]
    async fn submit_next_with_2_confirmation_succeeds() -> Result<(), Error<DummyError>> {
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
                timeout: Some(Duration::from_secs(0)),
                required_btc_confirmations: 2,
            },
        );

        let height_before = runner.issuing.get_best_height().await?;
        assert_eq!(height_before, 2);

        for _ in 0..10 {
            runner.submit_next().await?;
        }

        let height_after = runner.issuing.get_best_height().await?;
        assert_eq!(height_after, 3);

        assert!(runner.issuing.is_block_stored(make_hash("b")).await?);

        // these blocks have not been confirmed yet, so we should not have submitted it
        assert!(!runner.issuing.is_block_stored(make_hash("c")).await?);
        assert!(!runner.issuing.is_block_stored(make_hash("d")).await?);
        Ok(())
    }
}
