FROM ubuntu:20.04

ARG PROFILE=release
ARG BINARY=btc-parachain

RUN apt-get update && \
    apt-get install -y ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY target/${PROFILE}/${BINARY} /usr/local/bin

# Checks
RUN chmod +x /usr/local/bin/${BINARY} && \
    ldd /usr/local/bin/${BINARY} && \
    /usr/local/bin/${BINARY} --version

CMD ["/usr/local/bin/${BINARY}"]
