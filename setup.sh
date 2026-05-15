#!/bin/bash
# BugHunt.ai Setup Script
# Run: bash setup.sh

echo "[*] BugHunt.ai Auto-Setup"
echo ""

# Check if Python 3 installed
if ! command -v python3 &> /dev/null; then
    echo "[!] Python3 required"
    exit 1
fi

echo "[+] Python3 found"
echo ""

# Run Python setup
python3 bughunt.py setup
