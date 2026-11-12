# Local validation — 2026-11-11

Environment: Fedora host, kernel 7.2.10-200.fc44.x86_64; Docker Engine 29.9.1.
Build/test toolchain: isolated Debian bookworm container, Clang 14, libbpf 1.1.2.
The physical wireless adapter is RTL8852BE using rtw89_8852be. No program was
attached to the wireless card or physical Ethernet adapter.

## Passed

- C loader and BPF compilation with BPF v3 instructions.
- Kernel verifier acceptance for both XDP ingress and TC egress.
- 19 automated tests: real kernel packet fixtures, API authentication and input
  validation, IP ranges, expiration, agent failure status, flow grouping and sockets.
- IPv4/IPv6 CIDR drops, observation mode, QinQ/VLAN identity, VXLAN inner policy,
  malformed lengths, UDP/SYN budgets, fragment/extension source policy, TC accounting.
- Generic and native XDP attachment on disposable veth interfaces.
- Actual injected packets passing in observation mode and dropping under CIDR rules.
- Refusal to replace existing XDP attachments; clean XDP and TC detach.
- Ansible syntax check and actual rendering of all three deployment templates.
- Rendered Compose confinement and localhost port configuration checks.
- JavaScript syntax validation.
- Separate privileged agent and unprivileged UI/API containers communicating over
  a shared Unix socket: rule create/remove, real map reconciliation, telemetry,
  UI asset delivery and audit CSV export.
- Persistent-volume recovery: a rule survives API/agent container restart and is
  restored into fresh BPF maps by reconciliation.

The detailed isolated test output is in LOCAL_TEST_RESULTS.txt.

## Required gates still outstanding

- Full Ansible installation on this computer, a second idempotence run, systemd
  service lifecycle, host reboot recovery, and deployment rollback.
- Browser interaction/visual QA (UI assets were served and JS syntax checked).
- Physical-NIC native support, VLAN offload visibility, QinQ/VXLAN traffic on real
  hardware, MTU/nonlinear/GSO behavior, and realistic throughput/CPU/latency tests.
- Production hardening and features explicitly deferred in README.md.

These are not passes. The project owner explicitly requested integration into
main with these gaps documented. The development merge does not constitute a
production release or successful completion of the outstanding acceptance gates.
