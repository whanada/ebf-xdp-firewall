# Delivery plan

## Git and integration

Use the configured human Git identity, never Codex as author or co-author.
Develop features on separate branches. Keep main unchanged until the complete
integration has run successfully on this computer. An unavailable check is a
blocker, not a pass. No remote repository or push is implied.

Branches, in dependency order:

- codex/project-plan: architecture and acceptance criteria.
- codex/dataplane: C XDP parser, IPv4/IPv6 CIDR policy, counters, expirations.
- codex/flow-monitoring: TC egress, bounded bidirectional flow state, VLAN/QinQ,
  VXLAN inner/outer identities, optional local socket-state confirmation.
- codex/control-plane: host agent, Go API, PostgreSQL, revisions and reconciliation.
- codex/ui-reporting: rule management, flow views, counters and audit reports.
- codex/flood-protection: bounded service budgets, observation mode, automatic bans.
- codex/ansible-deployment: complete single-host deployment and recovery.
- codex/integration: integrate all features and execute local acceptance checks.

Create implementation branches when work begins. Integrate into the integration
branch first; merge into main only after all required checks pass.

## Single-host deployment

Provide an Ansible inventory, documented variables, roles, and a site playbook.
Detect supported OS/package manager before changing the host. Install Docker
Engine and Compose, build prerequisites, the agent and BPF artifacts, systemd
units, and the containerized API/UI/PostgreSQL/Prometheus stack. Manage persistent
volumes, health checks, service startup ordering, authentication secrets, backups,
and policy restoration. Keep secrets out of Git; support Ansible Vault.

The host agent runs under systemd. Containers host management services. Pin maps
and manage program/link lifecycle explicitly. Database revisions survive reboot;
kernel state must be restored after reboot. Do not replace unrelated XDP programs
or firewall rules. Select interfaces explicitly and preserve management access.

Default to observation mode. Native XDP is required by the production performance
profile; generic mode requires an explicit compatibility setting and is reported
as degraded. Hardware offload is a separately validated optional profile.

## Compatibility

Probe kernel BPF features, NIC/driver/firmware, native attachment, MTU, multi-buffer
support, VLAN RX metadata, tunnel and segmentation offloads. Validate VLAN/QinQ
visibility against actual hardware. Never report missing VLAN metadata as untagged.
Bound parser depth and define unsupported-packet behavior explicitly. Record the
tested compatibility matrix; do not promise universal driver support.

## Local acceptance gate

Compile C/BPF and agent; load programs through the verifier; test packet decisions
with BPF program tests and isolated network namespaces. Exercise both directions,
IPv4/IPv6, VLAN/QinQ, VXLAN, malformed headers, fragments, expiration, map pressure,
and legitimate traffic during floods. Verify API authorization, rule revisions,
UI workflows, reports, and audit history. Exercise the complete container stack.

Run Ansible syntax validation and deployment on this computer, rerun to verify
idempotence, and test restart/recovery and rollback. Validate native attachment and
offload visibility on the selected NIC separately from virtual-interface tests.
Measure PPS, latency, CPU/softirq, NIC loss, memory, and telemetry loss. Record
commands, results, environment, limitations, and failed checks. Missing host
permissions or tooling blocks corresponding checks and the final main merge.

## Future recommendations

After the single-host release: authenticated multi-host agents, optional RabbitMQ
with transactional outbox and revision-based reconciliation, centralized analytics,
high availability, and staged policy rollout. Later evaluate service-specific SYN
proxy, bidirectional TCP validation, hardware offload/SmartNIC profiles, and upstream
DDoS integration. Do not automatically ban normal TCP packet reordering. Keep the
packet path independent of management-service availability throughout.

## Initial environment observations

The planning session found Docker on PATH but no clang, bpftool, or
ansible-playbook on PATH. Kernel release: 7.2.10-200.fc44.x86_64.
Network-interface enumeration failed with a netlink permission error inside the
execution sandbox. NIC compatibility and privileged runtime checks remain untested.
