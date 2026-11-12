#!/usr/bin/env python3
"""Prefer Compose v2 while supporting distro-packaged standalone Compose."""
import os
import shutil
import subprocess
import sys
if subprocess.run(['docker','compose','version'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode == 0:
    command=['docker','compose']
elif shutil.which('docker-compose'):
    command=['docker-compose']
else:
    raise SystemExit('Install Docker Compose v2 or docker-compose')
os.execvp(command[0],command+['-f','compose.yml']+sys.argv[1:])
