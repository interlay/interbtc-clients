# ===== FIRST STAGE ======

FROM registry.gitlab.com/interlay/containers/rust-base:nightly-2021-01-25 as builder
ENV DEBIAN_FRONTEND=noninteractive
ARG PROFILE=release
WORKDIR /app

COPY . /app

RUN cargo build "--$PROFILE" --package faucet

# ===== SECOND STAGE ======

FROM bitnami/minideb:buster
ARG PROFILE=release

COPY --from=builder /app/target/$PROFILE/faucet /usr/local/bin

# Checks
RUN ldd /usr/local/bin/faucet && \
	/usr/local/bin/faucet --version

CMD ["/usr/local/bin/faucet"]
