# Vault Monitoring

## Set up Prometheus
Download the latest stable release:
```bash
chmod +x download_latest
./download_latest prometheus
```

To customize the Prometheus configuration, edit `prometheus.yml`.
Finally, run the service with:
```ssh
./prometheus --config.file=prometheus.yml
```

## Set up AlertManager
The Prometheus AlertManager can be configured to send notifications on certain triggers.

```bash
chmod +x download_latest
./download_latest alertmanager
```

To customize the AlertManager alerting rules, edit `rules.yml`. To customize the destination of the alert, edit `alertmanager.yml`. Check [this guide](https://grafana.com/blog/2020/02/25/step-by-step-guide-to-setting-up-prometheus-alertmanager-with-slack-pagerduty-and-gmail/) for more details about configuring AlertManager.


Once AlertManager is configured, add unit tests to `tests.yml` and run them with:
```bash
apt-get install prometheus
promtool test rules test.yml
```


Finally, run the service with:
```ssh
./alertmanager --config.file=alertmanager.yml
```