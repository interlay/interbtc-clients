FROM ubuntu:20.04

RUN apt-get update && \
    apt-get install -y ca-certificates tini && \
    rm -rf /var/lib/apt/lists/*

COPY ./artifacts/ /usr/local/bin
RUN find /usr/local/bin/ -type f -exec chmod +x {} \;

ENTRYPOINT ["tini", "--"]
