# ===== FIRST STAGE ======

FROM registry.gitlab.com/interlay/docker-rust:nightly-2020-10-01 as builder
ARG PROFILE=release
WORKDIR /app

COPY . /app

RUN cargo build "--$PROFILE" --package staked-relayer

# ===== SECOND STAGE ======

FROM phusion/baseimage:0.11
ARG PROFILE=release

RUN mv /usr/share/ca* /tmp && \
	rm -rf /usr/share/*  && \
	mv /tmp/ca-certificates /usr/share/

COPY --from=builder /app/target/$PROFILE/staked-relayer /usr/local/bin

# Checks
RUN ldd /usr/local/bin/staked-relayer && \
	/usr/local/bin/staked-relayer --version

# Shrinking
RUN rm -rf /usr/lib/python* && \
	rm -rf /usr/bin /usr/sbin /usr/share/man

CMD ["/usr/local/bin/staked-relayer"]