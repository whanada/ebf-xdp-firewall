#!/bin/sh
set -eu
mount -t bpf bpf /sys/fs/bpf
mkdir /sys/fs/bpf/maps
bpftool prog loadall /src/build/firewall.bpf.o /sys/fs/bpf/progs pinmaps /sys/fs/bpf/maps
chgrp 10001 /run/xdp-firewall
chmod 0750 /run/xdp-firewall
exec python3 /src/agent/service.py --maps /sys/fs/bpf/maps
