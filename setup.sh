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

# Install Python dependencies first so the main script can start.
if [ -f requirements_groq.txt ]; then
    python3 -m pip install -r requirements_groq.txt
fi

# Run Python setup
python3 bughunt_groq.py setup
