use crate::Error;
use warp::Filter;

// TODO: provide db instance to read key-values
pub async fn start() -> Result<(), Error> {
    let getter = warp::path!("op_return" / String).map(|data| format!("{}", data));
    // TODO: configurable `SocketAddr`
    warp::serve(getter).run(([127, 0, 0, 1], 3030)).await;
    Ok(())
}
