#!/bin/sh
# Read-only inventory. Does not load programs or change NIC settings.
set -eu
iface=${1:?usage: server-preflight.sh INTERFACE}
case "$iface" in *[!a-zA-Z0-9_.:-]*|'') echo 'Invalid interface' >&2; exit 2;; esac
uname -a
ip -details link show dev "$iface"
ethtool -i "$iface"
ethtool -k "$iface"
if command -v bpftool >/dev/null 2>&1; then
 bpftool feature probe kernel
else
 echo 'bpftool is missing; install deployment prerequisites before BPF checks.'
fi
