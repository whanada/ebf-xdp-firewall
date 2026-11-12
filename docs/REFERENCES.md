# Reference review

- https://docs.ebpf.io/linux/ : XDP hooks, maps, verifier and attachment modes.
- https://blog.cloudflare.com/programmable-packet-filtering-with-magic-firewall/ :
  programmable filtering; this specific article integrates eBPF with nftables.
- https://labs.iximiuz.com/tutorials/ebpf-firewall-ed03d648 : LPM CIDR mechanics.
- https://github.com/ebpf-security/xdp-firewall : reviewed public README and MIT
  license. Public example documents generic-mode loading; the advertised web UI
  belongs to a separately described distribution. No code or trial executable
  from this repository has been incorporated or executed.

The single-host MVP uses Python standard-library services and SQLite instead of
the initially proposed Go/PostgreSQL stack. This keeps deployment small and
testable while preserving the separate privileged agent boundary. PostgreSQL,
multi-user OIDC, durable analytics, atomic policy generations and queue delivery
remain future work. No RabbitMQ dependency is needed for one host.
