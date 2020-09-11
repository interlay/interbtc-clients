pub struct Mocker<R: Clone> {
    data: Option<R>,
}

impl<R: Clone> Default for Mocker<R> {
    fn default() -> Self {
        Self { data: None }
    }
}

#[derive(Clone, Copy)]
pub enum Error {}

#[derive(Default)]
pub struct Provider {
    ret_get_exchange_rate_info: Mocker<Result<(u64, u64, u64), Error>>,
    ret_get_time_now: Mocker<Result<u64, Error>>,
}

impl<R: Clone> Mocker<R> {
    pub fn returns(&mut self, r: R) {
        self.data = Some(r);
    }
}

impl Provider {
    pub fn mock_get_exchange_rate_info(&mut self) -> &mut Mocker<Result<(u64, u64, u64), Error>> {
        &mut self.ret_get_exchange_rate_info
    }

    pub async fn get_exchange_rate_info(&self) -> &Result<(u64, u64, u64), Error> {
        self.ret_get_exchange_rate_info.data.as_ref().unwrap()
    }

    pub fn mock_get_time_now(&mut self) -> &mut Mocker<Result<u64, Error>> {
        &mut self.ret_get_time_now
    }

    pub async fn get_time_now(&self) -> Result<u64, Error> {
        self.ret_get_time_now.data.unwrap()
    }
}
