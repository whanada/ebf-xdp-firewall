#!/usr/bin/env python3
"""Own only the maps and child processes created by this service invocation."""
import argparse
import os
from pathlib import Path
import signal
import subprocess
import sys
import time


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--root', required=True)
    p.add_argument('--interface', required=True)
    p.add_argument('--mode', choices=['native', 'generic'], default='native')
    args = p.parse_args()
    bpffs = Path('/sys/fs/bpf')
    # mountpoint detects an actual mount; ordinary directories cannot pin BPF maps.
    if subprocess.run(['mountpoint', '-q', str(bpffs)]).returncode:
        subprocess.run(['mount', '-t', 'bpf', 'bpf', str(bpffs)], check=True)
    pins = bpffs / f'xdp-firewall-{os.getpid()}'
    pins.mkdir()
    children = []
    stopping = False
    def stop(*_):
        nonlocal stopping
        stopping = True
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    code = 1
    try:
        loader = subprocess.Popen([f'{args.root}/build/loader', f'{args.root}/build/firewall.bpf.o', args.interface, str(pins), args.mode], stdout=subprocess.PIPE, text=True)
        children.append(loader)
        if loader.stdout.readline().strip() != 'READY':
            raise RuntimeError('dataplane failed to attach')
        service = subprocess.Popen([sys.executable, f'{args.root}/agent/service.py', '--maps', str(pins)])
        children.append(service)
        while not stopping and all(c.poll() is None for c in children):
            time.sleep(.25)
        code = 0 if stopping else 1
    finally:
        # Stop API-to-map writes before detaching the loader.
        for child in reversed(children):
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
        for pin in pins.iterdir():
            pin.unlink()
        pins.rmdir()
    return code


if __name__ == '__main__':
    sys.exit(main())
