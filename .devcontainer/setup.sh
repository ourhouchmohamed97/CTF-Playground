#!/usr/bin/env bash
set -eux

apt update && apt install -y \
  gdb gdb-multiarch git curl wget vim nano netcat-traditional socat \
  nmap gobuster sqlmap john hashcat binwalk steghide exiftool \
  python3-pip python3-venv python3-dev build-essential \
  libssl-dev libffi-dev libgmp-dev

# Python packages
pip install pwntools ropper capstone unicorn keystone-engine \
            pycryptodome sympy requests beautifulsoup4

# Setup GDB enhancements
bash -c "$(curl -fsSL https://gef.blah.cat/sh)" || true

echo "CTF environment ready!"
