use tracing_subscriber::{fmt, layer::SubscriberExt, prelude::*, EnvFilter};

fn init_filter() -> EnvFilter {
    EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new("info"))
        .unwrap()
}

pub fn init_json_subscriber() {
    let fmt_layer = fmt::layer().json();

    let _ = tracing_subscriber::registry()
        .with(init_filter())
        .with(fmt_layer)
        .try_init();
}

pub fn init_subscriber() {
    let fmt_layer = fmt::layer();

    let _ = tracing_subscriber::registry()
        .with(init_filter())
        .with(fmt_layer)
        .try_init();
}
