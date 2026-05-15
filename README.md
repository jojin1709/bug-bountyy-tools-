# BugHunt.ai - Groq Edition

Automated bug bounty reconnaissance, AI-assisted vulnerability hypotheses, basic payload testing, and HTML report generation.

Use this only on targets you own or have explicit permission to test.

## WSL Quick Start

Open Ubuntu/WSL and run:

```bash
sudo apt update
sudo apt install -y git python3 python3-pip python3-venv golang-go curl jq

git clone https://github.com/jojin1709/bug-bountyy-tools-.git
cd bug-bountyy-tools-

python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements_groq.txt
python3 bughunt_groq.py setup

export PATH="$PATH:$(go env GOPATH)/bin"
export GROQ_API_KEY="your-groq-api-key-here"
```

Run a hunt:

```bash
python3 bughunt_groq.py hunt example.com
```

Run with a scope file:

```bash
python3 bughunt_groq.py hunt example.com scope_example.txt
```

The report is generated as an HTML file, for example:

```text
example_com_report.html
```

## Update Existing Install

If you already cloned this repo before and only want the newest edited files:

```bash
cd bug-bountyy-tools-
git pull origin main
```

Then refresh Python dependencies:

```bash
source .venv/bin/activate
pip install -r requirements_groq.txt --upgrade
```

If you edited files locally and Git refuses to pull, save your local edits first:

```bash
cd bug-bountyy-tools-
git status
git stash
git pull origin main
git stash pop
```

## Alternative Setup Script

After cloning the repo:

```bash
cd bug-bountyy-tools-
chmod +x setup.sh
./setup.sh
```

Then set your Groq key and run the hunt:

```bash
export PATH="$PATH:$(go env GOPATH)/bin"
export GROQ_API_KEY="your-groq-api-key-here"
python3 bughunt_groq.py hunt example.com
```

## Scope File Format

Use one domain or subdomain per line:

```text
example.com
api.example.com
admin.example.com
*.internal.example.com
```

You can use the included `scope_example.txt` as a template.

## Environment Variables

Required:

```bash
export GROQ_API_KEY="your-groq-api-key-here"
```

Optional:

```bash
export TOOL_TIMEOUT="120"
export PARALLEL_TESTS="10"
export BUGHUNT_USER_AGENT="your-program-approved-user-agent"
export HTTP_PROXY="http://proxy:8080"
export HTTPS_PROXY="http://proxy:8080"
```

If a bug bounty program asks you to use a specific user agent, copy and paste it like this before running:

```bash
export BUGHUNT_USER_AGENT="bug-bounty-jojin1709 contact: your-email@example.com"
python3 bughunt_groq.py hunt example.com
```

You can also copy `.env.example` to `.env`, edit it, and load it:

```bash
cp .env.example .env
nano .env
source .env
```

## What Setup Installs

System packages:

- `golang-go`
- `git`
- `curl`
- `jq`
- `whatweb`

Go tools:

- `subfinder`
- `naabu`
- `httpx`
- `nuclei`
- `waybackurls`
- `gau`
- `katana`

Python packages:

- `groq`
- `cloudscraper`
- `requests`
- `urllib3`

## How It Works

1. Enumerates subdomains.
2. Scans open ports.
3. Checks live HTTP services.
4. Fetches historical URLs.
5. Detects technology stack.
6. Sends recon data to Groq for vulnerability hypotheses.
7. Tests basic SQLi, XSS, SSRF, and LFI payloads.
8. Generates an HTML report.

## Troubleshooting

### `GROQ_API_KEY not set`

```bash
export GROQ_API_KEY="your-groq-api-key-here"
```

### `subfinder`, `naabu`, `httpx`, `nuclei`, `gau`, `katana`, or `waybackurls` not found

```bash
export PATH="$PATH:$(go env GOPATH)/bin"
```

To make that permanent:

```bash
echo 'export PATH="$PATH:$(go env GOPATH)/bin"' >> ~/.bashrc
source ~/.bashrc
```

### Python package errors

Activate the virtual environment and reinstall dependencies:

```bash
source .venv/bin/activate
pip install -r requirements_groq.txt
```

### Permission denied on setup script

```bash
chmod +x setup.sh
./setup.sh
```

## Files

- `bughunt_groq.py` - Main scanner script.
- `requirements_groq.txt` - Python dependencies.
- `setup.sh` - WSL/Linux setup helper.
- `scope_example.txt` - Example scope file.
- `.env.example` - Example environment variables.

## Legal

Only scan systems where you have explicit authorization. Respect all program scope, rate limits, and platform rules.
