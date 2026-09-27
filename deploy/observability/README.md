# Observability integrations

Install the Prometheus Operator and Grafana in the cluster, then enable
`serviceMonitor` and `prometheusRule` in the GAS Helm values. The metrics
endpoint is bearer-protected; the ServiceMonitor reads the existing token
Secret. Do not expose `/admin/metrics` outside the cluster.

Install Fluent Bit through its vendor chart using `fluent-bit-values.yaml`,
and provide the `centralized-logging` Secret with TLS-enabled `host` and `port`
values for the log forwarder. Logs should be retained according to the
organization's incident-response policy.
