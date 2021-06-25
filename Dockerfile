# ===== FIRST STAGE ======

FROM registry.gitlab.com/interlay/containers/rust-base:nightly-2021-01-25 as builder
ARG PROFILE=release
ARG PACKAGE=vault
WORKDIR /app

COPY . /app

RUN cargo build "--$PROFILE" --package $PACKAGE

# ===== SECOND STAGE ======

FROM bitnami/minideb:buster
ARG PROFILE=release
ARG PACKAGE=vault

RUN install_packages libssl-dev

COPY --from=builder /app/interbtc-clients/target/$PROFILE/$PACKAGE /usr/local/bin

# Checks
RUN ldd /usr/local/bin/$PACKAGE && \
	/usr/local/bin/$PACKAGE --version

CMD ["/usr/local/bin/$PACKAGE"]
