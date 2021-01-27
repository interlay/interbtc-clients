# ===== FIRST STAGE ======

FROM registry.gitlab.com/interlay/containers/rust-base:nightly-2021-01-25 as builder
ENV DEBIAN_FRONTEND=noninteractive
ARG PROFILE=release
WORKDIR /app

COPY . /app

RUN cargo build "--$PROFILE" --package testdata-gen

# ===== SECOND STAGE ======

FROM bitnami/minideb:buster
ARG PROFILE=release

COPY --from=builder /app/target/$PROFILE/testdata-gen /usr/local/bin

RUN install_packages libssl1.1 ca-certificates

# Checks
RUN ldd /usr/local/bin/testdata-gen && \
	/usr/local/bin/testdata-gen --version

CMD ["/usr/local/bin/testdata-gen"]
