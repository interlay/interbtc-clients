FROM rust:latest

WORKDIR /usr/src/app

COPY . .

RUN cargo build --package staked-relayer

RUN cargo install --path staked-relayer

CMD ["staked-relayer"]