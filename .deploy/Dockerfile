FROM ubuntu:20.04

RUN apt-get update && \
    apt-get install -y ca-certificates tini && \
    rm -rf /var/lib/apt/lists/*

COPY ./artifacts/ /usr/local/bin

ENTRYPOINT ["tini", "--"]
