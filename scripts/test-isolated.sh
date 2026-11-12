#!/bin/sh
set -eu
# Run only inside a disposable privileged container with its own network namespace.
cp -r /input /tmp/project
cd /tmp/project
rm -rf build
make all
mount -t bpf bpf /sys/fs/bpf
mkdir -p /sys/fs/bpf/firewall-tests/maps /sys/fs/bpf/firewall-tests/progs
bpftool prog loadall build/firewall.bpf.o /sys/fs/bpf/firewall-tests/progs pinmaps /sys/fs/bpf/firewall-tests/maps
BPF_TEST_ROOT=/sys/fs/bpf/firewall-tests python3 -m unittest discover -s tests -v
ansible-playbook -i deploy/ansible/inventory.example.ini deploy/ansible/site.yml --syntax-check
ansible-playbook -i localhost, tests/render-deployment.yml
python3 -c "import yaml; c=yaml.safe_load(open('/tmp/firewall-compose.yml')); assert c['services']['control']['cap_drop']==['ALL']; assert c['services']['control']['ports']==['127.0.0.1:8080:8080']"
# Verify actual attachment and clean detach using a disposable veth pair.
ip link add fwtest0 type veth peer name fwtest1
ip link set fwtest0 up
ip link set fwtest1 up
for mode in generic native; do
 mkdir /sys/fs/bpf/attach-$mode
 build/loader build/firewall.bpf.o fwtest0 /sys/fs/bpf/attach-$mode "$mode" > /tmp/loader.log 2>&1 &
 loader_pid=$!
 trap 'kill "$loader_pid" 2>/dev/null || true; ip link del fwtest0 2>/dev/null || true' EXIT
 sleep 1
 grep -q READY /tmp/loader.log
 PYTHONPATH=. python3 scripts/live-packet-smoke.py /sys/fs/bpf/attach-$mode
 mkdir /sys/fs/bpf/collision-$mode
 if build/loader build/firewall.bpf.o fwtest0 /sys/fs/bpf/collision-$mode "$mode" >/tmp/collision.log 2>&1; then
  echo 'ERROR: replaced an existing attachment' >&2; exit 1
 fi
 kill "$loader_pid"
 wait "$loader_pid"
 if ip -details link show fwtest0 | grep -q 'prog/xdp'; then exit 1; fi
 if tc filter show dev fwtest0 egress | grep -q '49152'; then exit 1; fi
 echo "PASS: $mode veth attachment, replacement refusal and clean detach"
done
ip link del fwtest0
trap - EXIT
