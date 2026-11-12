# XDP Firewall

A single-host firewall prototype with a C XDP ingress program, C TC egress observer,
Python host agent, authenticated API, persistent SQLite policy store and web UI.
The web service runs in an unprivileged Docker container; only the host agent
writes kernel maps. See [architecture and roadmap](docs/PLAN.md) and
[reference review](docs/REFERENCES.md).

**Status: development MVP, not a production release. Main remains at the planning
baseline until the full local deployment acceptance gate is satisfied.**

## Implemented

- IPv4/IPv6 source blocks: individual addresses, CIDRs, start-end ranges, optional TTL.
- Observation mode by default; explicit enforcement with actual-drop counters.
- Bounded per-CPU UDP and SYN packet budgets. These are interface-wide fixed-window
  limits, not per-service limits or automatic source bans.
- Directional flow records and bidirectional grouping, plus separate kernel-local
  TCP socket states. Forwarded TCP state remains inferred.
- Up to two in-packet VLAN tags and one base RFC7348 VXLAN layer on UDP/4789,
  including inner IPv4/IPv6, tenant identity and inner VLAN tags.
- Rule revisions, pending/applied/error status, audit CSV, 24-hour counter samples.
- Host service lifecycle and single-host Ansible deployment sources.

## Local isolated tests

Requires Docker. The privileged test container has its own network namespace and
never attaches to physical host interfaces. It still uses the host kernel for BPF.

```sh
docker build -f Dockerfile.test -t xdp-firewall-test .
docker run --rm --privileged --network none \
  -v "$PWD:/input:ro,z" xdp-firewall-test sh /input/scripts/test-isolated.sh
```

Tests compile the programs, load them through the kernel verifier, execute packet
fixtures using BPF_PROG_TEST_RUN, test the API and agent, validate Ansible syntax,
and attach/detach on disposable veth interfaces. The test runner works on a copy
of the source and does not place build artifacts in your checkout.

End-to-end management containers:

```sh
docker build -t xdp-firewall-control:test .
docker compose -p xdp-fw-test -f deploy/compose.test.yml up -d
docker compose -p xdp-fw-test -f deploy/compose.test.yml exec -T control \
  python3 - < scripts/compose-smoke.py
docker compose -p xdp-fw-test -f deploy/compose.test.yml down -v
```

The Compose test uses no host network and publishes no ports. Its test token is
public fixture data and must never be used for deployment.

## Single-host deployment

Initial package targets: Debian 12+, Ubuntu 24.04+, and Fedora 42+ on x86-64, kernel 6.1 or newer,
with systemd and Docker support. Package and SELinux behavior still require full
host acceptance testing. Native XDP requires a supported NIC/driver. Wireless
RTL8852BE/rtw89 requires explicit generic mode for this prototype.

1. Install Ansible on the controller and copy
   `deploy/ansible/inventory.example.ini` to a private inventory.
2. Set the target host, SSH user, explicit interface, and `firewall_mode`.
3. Create an encrypted variables file with `ansible-vault create secrets.yml`.
   Set `firewall_api_token` to at least 32 random URL-safe characters.
4. Run the read-only preflight on the server:
   `sudo sh scripts/server-preflight.sh INTERFACE`.
5. Review and execute:

```sh
ansible-playbook -i inventory.ini deploy/ansible/site.yml \
  --ask-become-pass --ask-vault-pass -e @secrets.yml
```

The playbook installs build dependencies and Docker, copies and compiles sources,
builds the UI/API image, creates persistent storage, and starts the host and
container systemd services. No Docker daemon is exposed to the UI container.
The selected interface must not already have an XDP program attached; attachment
fails rather than replacing it. A reserved TC handle/priority must also be free.

Access the UI through an SSH tunnel:

```sh
ssh -L 8080:127.0.0.1:8080 admin@SERVER
```

Open `http://127.0.0.1:8080` and enter the token. Begin in observation mode and
validate legitimate traffic before enabling enforcement. Only administrators
should have this token. The MVP has a single administrative identity.

Backup with the SQLite online backup API (do not copy a live WAL database alone):

```sh
sudo python3 /opt/xdp-firewall/scripts/backup.py \
  /var/lib/xdp-firewall/control/firewall.db /SAFE/BACKUP/firewall.db
```

To restore: stop the control service, restore the backup to the persistent data
directory with UID/GID 10001 ownership, remove stale WAL/SHM files only while the
service is stopped, and restart. Rules reconcile to kernel maps within five seconds.
Host reboot clears kernel maps; the management database restores desired rules.
During that restoration window the fresh dataplane defaults to observation mode.

To stop and detach this application's hooks:

```sh
sudo systemctl stop xdp-firewall-control xdp-firewall
```

## Explicit limitations

- The parser preserves VID and tag depth, not PCP/DEI/TPID. Hardware-stripped tags
  are not recovered yet; an absent tag means **none or unknown**, not proven untagged.
- Unsupported L4 protocols, IPv4 fragments and IPv6 extension chains do not receive
  transport flood classification. Source blocks still apply when an IP header is
  available. Other unsupported L2 traffic passes, preserving ARP.
- VXLAN rules match the inner source when a supported inner IP header is parsed;
  dedicated outer/inner policy scopes and arbitrary tunnel ports are future work.
- TC observes only accessible linear headers. GSO/nonlinear packets may not yield
  flow records; egress hook counts are not exact wire packet counts.
- Flow state is bounded to 65,536 LRU entries; churn can evict active observations.
  The UI shows at most 2,000 records active within 120 seconds. Evictions are not
  individually counted. Kernel-local sockets cover the host namespace, not just
  the monitored interface, and are capped at 2,000 in the UI.
- Active overlapping CIDRs are rejected to avoid ambiguous expiration semantics.
  Rule IDs are never reused; this prototype supports 4,095 lifetime rule insertions.
- Multi-map updates are not atomic; applied revision is acknowledged only after
  all writes succeed. A failed update can leave partial policy until reconciliation.
- There is no SYN proxy, full TCP sequence validation, automatic source banning,
  RBAC/OIDC, RabbitMQ, hardware offload, durable flow archive, or multi-host support.
- Normal packet reordering is not treated as an attack.
- Native XDP still consumes host CPU/NAPI processing. It cannot prevent upstream
  link saturation. Generic mode cannot validate native-XDP performance claims.

## Server acceptance before release

Run the isolated suite, deploy with Ansible, rerun Ansible for idempotence, verify
service restart/reboot restoration and rollback, then validate native attachment,
actual VLAN/QinQ/VXLAN visibility and packet counters on the selected NIC. Exercise
legitimate traffic during controlled floods and measure PPS, loss, latency,
CPU/softirq and memory. Preserve results with driver/firmware/kernel versions.
No merge to main is authorized by a skipped or unavailable test.
