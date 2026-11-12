#!/bin/sh
set -eu
cp -r /input /tmp/project
cd /tmp/project
rm -rf build
make all
mount -t bpf bpf /sys/fs/bpf
mkdir /sys/fs/bpf/test-progs /sys/fs/bpf/test-maps
bpftool prog loadall build/firewall.bpf.o /sys/fs/bpf/test-progs pinmaps /sys/fs/bpf/test-maps
bpftool -j map dump pinned /sys/fs/bpf/test-maps/settings
