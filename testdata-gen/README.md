# PolkaBTC Testdata

Generate testdata for the BTC-Parachain with this handy toolkit.

```shell
testdata-gen --keyring bob set-exchange-rate --exchange-rate 1
testdata-gen --keyring bob register-vault --btc-address tb1quv5c6jjt77kgad82dc99fjdlyrthj7drkkp3ac --collateral 100000
testdata-gen --keyring alice request-issue --issue-amount 1000 --vault bob
```