# PolkaBTC Kubernetes Helm Charts

A collection of Helm Charts to deploy specialized PolkaBTC services to a Kubernetes cluster.

## Staked Relayer

### Install

To install the chart with the release name `my-release` into namespace `my-namespace` from within this directory:

```bash
helm install --namespace my-namespace my-release staked-relayer/
```

### Upgrade

To upgrade the `my-release` deployment:

```bash
helm upgrade --namespace my-namespace my-release staked-relayer/
```
