#!/usr/bin/env python3
"""Online-consistent SQLite backup, including committed WAL data."""
import argparse
import os
import sqlite3
p=argparse.ArgumentParser()
p.add_argument('source')
p.add_argument('destination')
a=p.parse_args()
os.umask(0o077)
with sqlite3.connect('file:'+a.source+'?mode=ro',uri=True) as src:
    with sqlite3.connect(a.destination) as dst:
        src.backup(dst)
print('Backup complete')
