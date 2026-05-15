# 🔓 BugHunt.ai - Automated Bug Bounty Framework

**One command. Everything runs. Reports generated.**

Fully automated reconnaissance → vulnerability hypothesis → testing → reporting.

## 🚀 Quick Start

### Step 1: Setup (First Time Only)

```bash
bash setup.sh
# OR
python3 bughunt.py setup
```

Wait 5-10 minutes. Everything installs auto.

### Step 2: Create Scope File (Optional)

```bash
cat > scope.txt << EOF
target.com
api.target.com
admin.target.com
EOF
```

### Step 3: Hunt

```bash
# Hunt without scope (scan entire domain)
python3 bughunt.py hunt target.com

# Hunt with scope (filter to specific subdomains)
python3 bughunt.py hunt target.com scope.txt
```

Done. Wait 20-30 mins. Report auto-generates: `target_com_report.html`

---

## 📋 What Installs

### Tools
- **subfinder** - Subdomain enumeration
- **naabu** - Fast port scanning
- **httpx** - Check live hosts
- **nuclei** - Vulnerability scanning
- **waybackurls** - Historical URL fetching
- **whatweb** - Tech stack detection

### Python Packages
- anthropic (Claude API)
- requests (HTTP)
- jinja2 (templating)

### System
- golang
- git
- curl
- jq

---

## 🔍 How It Works

### Phase 1: Reconnaissance (5 mins)
- Enumerates subdomains
- Scans open ports
- Checks live hosts
- Fetches historical URLs
- Detects tech stack

### Phase 2: Filtering
- Filters results by scope
- Removes out-of-scope domains
- Prioritizes high-value targets

### Phase 3: Hypothesis Generation
- Sends recon data to Claude AI
- Generates 15 likely vulnerability locations
- Returns prioritized checklist

### Phase 4: Automated Testing (15 mins)
- Tests SQLi payloads
- Tests XSS payloads
- Tests SSRF payloads
- Tests LFI payloads
- Parallel execution (fast)

### Phase 5: Reporting
- Generates professional HTML report
- Includes PoCs for each vuln
- Ready to submit to HackerOne/Bugcrowd

---

## 📊 Report Contents

Each report includes:
- **Summary** - Total vulns found
- **Statistics** - Type breakdown
- **Detailed findings** - Each vulnerability with:
  - Type (SQLi, XSS, SSRF, LFI)
  - Endpoint affected
  - Payload used
  - Proof of Concept (copy-paste ready)
  - Response sample

---

## 🎯 Real Example

```bash
# Setup
python3 bughunt.py setup

# Create scope
cat > scope.txt << EOF
example.com
api.example.com
EOF

# Hunt
python3 bughunt.py hunt example.com scope.txt

# Wait 25 mins...

# Output: example_com_report.html
```

Open `example_com_report.html` in browser. See all vulnerabilities found + PoCs.

---

## ⚙️ Environment Variables

Set before running:

```bash
export ANTHROPIC_API_KEY="sk-..."
python3 bughunt.py hunt target.com
```

---

## 🔧 Troubleshooting

### "Command not found: subfinder"
```bash
export PATH="$PATH:$(go env GOPATH)/bin"
python3 bughunt.py hunt target.com
```

### "ANTHROPIC_API_KEY not set"
```bash
export ANTHROPIC_API_KEY="your-key-here"
```

### "Failed to install [tool]"
Manual install:
```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

### "Permission denied"
```bash
chmod +x bughunt.py setup.sh
```

---

## 📝 Scope File Format

One domain per line:

```
target.com
api.target.com
admin.target.com
*.internal.target.com
```

Wildcards supported. Out-of-scope domains filtered automatically.

---

## 💡 Tips

1. **First hunt?** Start with small scope. Test with known vulnerable app.
2. **False positives?** Manual verification always required. This = initial screening.
3. **Speed slow?** Reduce domain count in scope. Fewer targets = faster hunt.
4. **More payloads?** Edit PAYLOADS dict in bughunt.py
5. **Custom endpoints?** Add to hypotheses in Phase 3 manually.

---

## 🚨 Legal

- Only hunt targets with explicit permission
- Respect scope limits
- Follow platform rules (HackerOne, Bugcrowd, etc)
- This tool = reconnaissance only. Use responsibly.

---

## 📦 Files Included

- `bughunt.py` - Main script (all-in-one)
- `requirements.txt` - Python deps
- `setup.sh` - Auto-setup script
- `README.md` - This file

---

## 🎓 Learning

This tool teaches:
- Recon automation
- API integration (Claude)
- Parallel async testing
- Vulnerability detection patterns
- Report generation

---

## 🤝 Contributing

Want to improve?
- Add more payload types
- Better detection logic
- New vulnerability types
- Faster tools

Edit `bughunt.py` and test!

---

## ⚡ TL;DR

```bash
bash setup.sh                    # Install
python3 bughunt.py hunt target.com  # Hunt
# Report auto-generated
```

That's it. Ship reports. Get bounties. 🔓

---

**Built for bug bounty hunters, by hackers.**
