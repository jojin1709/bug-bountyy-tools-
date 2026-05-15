#!/usr/bin/env python3
"""
BugHunt.ai - Automated Bug Bounty Reconnaissance Framework
Groq API Edition (Free)
One command. Everything runs. Reports generated.
"""

import asyncio
import subprocess
import sys
import os
import json
import time
import platform
from typing import List, Dict
from pathlib import Path

try:
    import requests
    from groq import Groq
except ImportError:
    print("[!] Missing dependencies. Run: pip3 install -r requirements_groq.txt")
    sys.exit(1)

# ============ CONFIG ============
TOOLS = {
    "subfinder": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder",
    "naabu": "github.com/projectdiscovery/naabu/v2/cmd/naabu",
    "httpx": "github.com/projectdiscovery/httpx/cmd/httpx",
    "nuclei": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei",
    "waybackurls": "github.com/tomnomnom/waybackurls",
}

PIP_PACKAGES = ["groq", "requests"]
APT_PACKAGES = ["golang-go", "git", "curl", "jq", "whatweb"]

# Payloads for testing
PAYLOADS = {
    "sqli": [
        "' OR '1'='1",
        "admin'--",
        "1' AND SLEEP(5)--",
        "' OR 1=1--",
        "\" OR \"1\"=\"1",
    ],
    "xss": [
        "<img src=x onerror=alert(1)>",
        "';alert(1);//",
        "<svg onload=alert(1)>",
        "\"><script>alert(1)</script>",
        "<iframe src=javascript:alert(1)>",
    ],
    "ssrf": [
        "http://127.0.0.1:8080",
        "http://169.254.169.254",
        "http://localhost:8080",
        "http://127.0.0.1/admin",
    ],
    "lfi": [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "....//....//....//etc/passwd",
        "/etc/passwd%00",
    ],
}

# ============ SETUP / INSTALL ============

def check_tool(tool_name: str) -> bool:
    """Check if tool exists."""
    result = subprocess.run(
        f"which {tool_name}",
        shell=True,
        capture_output=True,
        text=True
    )
    return result.returncode == 0

def install_apt(package: str):
    """Install apt package."""
    if check_tool(package.split()[0]):
        print(f"[+] {package} already installed")
        return
    print(f"[*] Installing {package}...")
    result = subprocess.run(
        f"sudo apt install -y {package}",
        shell=True,
        capture_output=True,
        text=True
    )
    if result.returncode == 0:
        print(f"[+] {package} installed")
    else:
        print(f"[!] Failed: {package}")

def install_go_tool(tool_name: str, repo: str):
    """Install Go tool."""
    if check_tool(tool_name):
        print(f"[+] {tool_name} already installed")
        return
    print(f"[*] Installing {tool_name}...")
    result = subprocess.run(
        f"go install {repo}@latest",
        shell=True,
        capture_output=True,
        text=True,
        timeout=120
    )
    if result.returncode == 0:
        print(f"[+] {tool_name} installed")
    else:
        print(f"[!] Failed: {tool_name}")

def install_pip(package: str):
    """Install Python package."""
    print(f"[*] Installing {package}...")
    result = subprocess.run(
        f"pip3 install {package}",
        shell=True,
        capture_output=True,
        text=True
    )
    if result.returncode == 0:
        print(f"[+] {package} installed")

def setup():
    """Full setup."""
    print("""
╔═══════════════════════════════════════╗
║     🔧 BugHunt.ai Setup               ║
║     Groq Edition (FREE)               ║
║     Installing all dependencies       ║
╚═══════════════════════════════════════╝
""")
    
    # Check OS
    if "linux" not in sys.platform.lower():
        print("[!] Linux required. Use WSL/Kali.")
        sys.exit(1)
    
    # Check Go
    if not check_tool("go"):
        print("[!] Go required. Install from golang.org")
        sys.exit(1)
    print("[+] Go found")
    
    # APT
    print("\n[*] Installing system packages...")
    for pkg in APT_PACKAGES:
        install_apt(pkg)
    
    # Go tools
    print("\n[*] Installing Go tools (5-10 mins)...")
    for tool, repo in TOOLS.items():
        install_go_tool(tool, repo)
    
    # Python
    print("\n[*] Installing Python packages...")
    for pkg in PIP_PACKAGES:
        install_pip(pkg)
    
    print("""
╔═══════════════════════════════════════╗
║     ✅ Setup Complete!                ║
║     Next steps:                       ║
║     1. Get free Groq API key:         ║
║        https://console.groq.com       ║
║     2. Set env variable:              ║
║        export GROQ_API_KEY="..."      ║
║     3. Hunt:                          ║
║        python3 bughunt_groq.py hunt <url>  ║
╚═══════════════════════════════════════╝
""")

# ============ PHASE 1: RECON ============

def run_cmd(cmd: str, timeout: int = 120) -> str:
    """Run command safely."""
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        return ""
    except Exception as e:
        return ""

def recon(target: str) -> Dict:
    """Phase 1: Reconnaissance."""
    print(f"\n[*] PHASE 1: RECON on {target}\n")
    
    results = {
        "target": target,
        "subdomains": [],
        "live_hosts": [],
        "ports": [],
        "urls": [],
        "tech": "",
    }
    
    # Subdomains
    print("[*] Enumerating subdomains (subfinder)...")
    output = run_cmd(f"subfinder -d {target} -silent -t 100", timeout=180)
    results["subdomains"] = [s.strip() for s in output.split("\n") if s.strip()]
    print(f"[+] Found {len(results['subdomains'])} subdomains")
    
    # Check live hosts
    print("[*] Checking live hosts (httpx)...")
    if results["subdomains"]:
        subs_str = "\n".join(results["subdomains"][:20])
        output = run_cmd(
            f"echo '{subs_str}' | httpx -silent -status-code -title -timeout 5",
            timeout=120
        )
        results["live_hosts"] = [h.strip() for h in output.split("\n") if h.strip()]
    print(f"[+] Found {len(results['live_hosts'])} live hosts")
    
    # Port scan
    print("[*] Port scanning (naabu)...")
    output = run_cmd(f"naabu -host {target} -p - -rate 1000 -silent", timeout=300)
    results["ports"] = [p.strip() for p in output.split("\n") if p.strip()]
    print(f"[+] Found {len(results['ports'])} open ports")
    
    # Historical URLs
    print("[*] Fetching historical URLs (waybackurls)...")
    output = run_cmd(f"echo {target} | waybackurls", timeout=120)
    urls = [u.strip() for u in output.split("\n") if u.strip()]
    results["urls"] = urls[:100]
    print(f"[+] Found {len(results['urls'])} historical URLs")
    
    # Tech stack
    print("[*] Detecting tech stack (whatweb)...")
    output = run_cmd(f"whatweb -a 3 {target}", timeout=60)
    results["tech"] = output[:500]
    print(f"[+] Tech detected")
    
    return results

# ============ PHASE 2: FILTER SCOPE ============

def filter_scope(recon_data: Dict, scope: str) -> Dict:
    """Phase 2: Filter by scope."""
    print(f"\n[*] PHASE 2: FILTERING BY SCOPE\n")
    
    allowed = set(s.strip() for s in scope.split("\n") if s.strip())
    
    filtered_subs = [
        s for s in recon_data["subdomains"]
        if any(a in s for a in allowed)
    ]
    filtered_urls = [
        u for u in recon_data["urls"]
        if any(a in u for a in allowed)
    ]
    
    result = {
        **recon_data,
        "subdomains": filtered_subs,
        "urls": filtered_urls,
    }
    
    print(f"[+] Filtered to {len(filtered_subs)} in-scope subdomains")
    print(f"[+] Filtered to {len(filtered_urls)} in-scope URLs")
    
    return result

# ============ PHASE 3: HYPOTHESIS (GROQ) ============

def get_hypotheses(recon_data: Dict, target: str) -> List[Dict]:
    """Phase 3: Groq AI generates vuln hypotheses (FREE)."""
    print(f"\n[*] PHASE 3: GENERATING HYPOTHESES (Groq - FREE)\n")
    
    groq_api_key = os.getenv("GROQ_API_KEY")
    if not groq_api_key:
        print("[!] GROQ_API_KEY not set")
        print("[!] Get free key: https://console.groq.com")
        print("[!] Then: export GROQ_API_KEY='your-key'")
        return []
    
    client = Groq(api_key=groq_api_key)
    
    prompt = f"""You are elite security researcher. Given recon data, identify LIKELY vulnerability locations.
Be specific: endpoint, method, vuln type, reason.

Target: {target}
Subdomains: {', '.join(recon_data['subdomains'][:10])}
URLs: {', '.join(recon_data['urls'][:10])}
Tech: {recon_data['tech'][:300]}
Ports: {', '.join(recon_data['ports'][:10])}

RESPOND ONLY WITH VALID JSON ARRAY. NO MARKDOWN. NO TEXT.

[
  {{"endpoint": "/api/users", "method": "GET", "vuln_type": "IDOR", "reason": "..."}},
  {{"endpoint": "/search", "method": "GET", "vuln_type": "SQLi", "reason": "..."}}
]

Top 15 hypotheses only. ONLY JSON."""
    
    try:
        print("[*] Calling Groq API (free tier)...")
        response = client.messages.create(
            model="mixtral-8x7b-32768",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=2000,
        )
        
        text = response.content[0].text.strip()
        
        # Extract JSON
        start = text.find("[")
        end = text.rfind("]") + 1
        if start >= 0 and end > start:
            json_str = text[start:end]
            hypotheses = json.loads(json_str)
            print(f"[+] Generated {len(hypotheses)} hypotheses (Groq)")
            return hypotheses
        else:
            print("[!] Could not parse JSON response")
            return []
    
    except Exception as e:
        print(f"[!] Groq error: {e}")
        print("[!] Check API key: https://console.groq.com")
        return []

# ============ PHASE 4: TESTING ============

async def test_vuln(target: str, hyp: Dict) -> Dict:
    """Test single hypothesis."""
    endpoint = hyp.get("endpoint", "/")
    vuln_type = hyp.get("vuln_type", "unknown")
    method = hyp.get("method", "GET").upper()
    
    url = f"https://{target}{endpoint}"
    
    result = {
        "endpoint": endpoint,
        "vuln_type": vuln_type,
        "vulnerable": False,
        "payload": None,
        "poc": None,
        "response_sample": None,
    }
    
    payloads_to_test = PAYLOADS.get(vuln_type.lower(), [])
    
    for payload in payloads_to_test:
        try:
            if method == "GET":
                r = requests.get(
                    url,
                    params={"q": payload, "id": payload, "url": payload, "search": payload},
                    timeout=5,
                    verify=False,
                    headers={"User-Agent": "Mozilla/5.0"}
                )
            else:
                r = requests.post(
                    url,
                    data={"q": payload, "id": payload, "url": payload},
                    timeout=5,
                    verify=False,
                    headers={"User-Agent": "Mozilla/5.0"}
                )
            
            # Detection logic
            if vuln_type.lower() == "sqli":
                if any(err in r.text.lower() for err in ["sql", "syntax", "error", "mysql", "postgresql"]):
                    result["vulnerable"] = True
                    result["payload"] = payload
                    result["poc"] = f"curl '{url}?id={payload}'"
                    result["response_sample"] = r.text[:300]
                    break
            
            elif vuln_type.lower() == "xss":
                if payload in r.text:
                    result["vulnerable"] = True
                    result["payload"] = payload
                    result["poc"] = f"curl '{url}?q={payload}'"
                    result["response_sample"] = r.text[:300]
                    break
            
            elif vuln_type.lower() == "ssrf":
                if any(x in r.text.lower() for x in ["aws", "gcp", "internal", "localhost", "127.0.0.1"]):
                    result["vulnerable"] = True
                    result["payload"] = payload
                    result["poc"] = f"curl -X POST '{url}' -d 'url={payload}'"
                    result["response_sample"] = r.text[:300]
                    break
            
            elif vuln_type.lower() == "lfi":
                if any(x in r.text for x in ["root:", "bin:", "etc/passwd", "windows"]):
                    result["vulnerable"] = True
                    result["payload"] = payload
                    result["poc"] = f"curl '{url}?file={payload}'"
                    result["response_sample"] = r.text[:300]
                    break
        
        except requests.exceptions.RequestException:
            pass
        except Exception:
            pass
    
    return result

async def test_all(target: str, hypotheses: List[Dict]) -> List[Dict]:
    """Phase 4: Test all hypotheses in parallel."""
    print(f"\n[*] PHASE 4: TESTING {len(hypotheses)} HYPOTHESES (PARALLEL)\n")
    
    tasks = [test_vuln(target, h) for h in hypotheses]
    results = await asyncio.gather(*tasks)
    vulns = [r for r in results if r["vulnerable"]]
    
    print(f"[+] Found {len(vulns)} potential vulnerabilities")
    return vulns

# ============ PHASE 5: REPORTING ============

def generate_report(target: str, vulns: List[Dict]) -> str:
    """Phase 5: Generate HTML report."""
    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BugHunt Report - {target}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Courier New', monospace;
            background: linear-gradient(135deg, #0a0e27 0%, #1a1f3a 100%);
            color: #e0e0e0;
            padding: 40px 20px;
            min-height: 100vh;
        }}
        .container {{
            max-width: 900px;
            margin: 0 auto;
        }}
        .header {{
            text-align: center;
            margin-bottom: 40px;
            border-bottom: 2px solid #00d4ff;
            padding-bottom: 20px;
        }}
        .header h1 {{
            color: #00d4ff;
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        .header p {{
            color: #888;
            font-size: 1.1em;
        }}
        .badge {{
            display: inline-block;
            background: #00d4ff;
            color: #000;
            padding: 5px 10px;
            border-radius: 3px;
            font-size: 0.8em;
            margin-top: 10px;
            font-weight: bold;
        }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin: 30px 0;
        }}
        .stat-box {{
            background: #1a1f3a;
            border: 1px solid #00d4ff;
            padding: 20px;
            border-radius: 5px;
            text-align: center;
        }}
        .stat-box .number {{
            color: #00d4ff;
            font-size: 2em;
            font-weight: bold;
        }}
        .stat-box .label {{
            color: #888;
            font-size: 0.9em;
            margin-top: 5px;
        }}
        .vuln {{
            background: #1a1f3a;
            border-left: 4px solid #00d4ff;
            padding: 20px;
            margin: 20px 0;
            border-radius: 3px;
        }}
        .vuln h3 {{
            color: #00d4ff;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .vuln .critical {{ color: #ff0000; font-weight: bold; }}
        .vuln .high {{ color: #ff6b6b; }}
        .vuln .medium {{ color: #ffa500; }}
        .vuln .low {{ color: #ffff00; }}
        .vuln-detail {{
            margin: 10px 0;
            padding: 8px 0;
            border-bottom: 1px solid #333;
        }}
        .vuln-detail strong {{
            color: #00d4ff;
        }}
        pre {{
            background: #0d0d0d;
            padding: 12px;
            border-radius: 3px;
            overflow-x: auto;
            margin: 10px 0;
            border: 1px solid #333;
            color: #00d4ff;
        }}
        .footer {{
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #333;
            color: #666;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 BugHunt Report</h1>
            <p>Automated Reconnaissance & Vulnerability Analysis</p>
            <p style="margin-top: 10px; color: #00d4ff;">Target: <strong>{target}</strong></p>
            <span class="badge">Groq AI Powered (Free)</span>
        </div>
        
        <div class="stats">
            <div class="stat-box">
                <div class="number">{len(vulns)}</div>
                <div class="label">Vulnerabilities</div>
            </div>
            <div class="stat-box">
                <div class="number">{len([v for v in vulns if v['vuln_type'] in ['SQLi', 'XSS']])}</div>
                <div class="label">Critical</div>
            </div>
            <div class="stat-box">
                <div class="number">{int(time.time())}</div>
                <div class="label">Scan Time</div>
            </div>
        </div>
"""
    
    if not vulns:
        html += """
        <div style="text-align: center; padding: 40px; color: #888;">
            <p style="font-size: 1.2em;">✅ No vulnerabilities detected in initial scan.</p>
            <p style="margin-top: 10px;">Further manual testing recommended.</p>
        </div>
"""
    else:
        html += "<h2 style='color: #00d4ff; margin: 30px 0;'>🔴 Detected Vulnerabilities</h2>\n"
        for i, vuln in enumerate(vulns, 1):
            severity = "critical" if vuln["vuln_type"] in ["SQLi", "XXE", "RCE"] else "high"
            html += f"""
        <div class="vuln">
            <h3>
                <span class="{severity}">{i}.</span>
                <strong>{vuln['vuln_type']}</strong> @ {vuln['endpoint']}
            </h3>
            
            <div class="vuln-detail">
                <strong>Type:</strong> {vuln['vuln_type']}
            </div>
            <div class="vuln-detail">
                <strong>Endpoint:</strong> {vuln['endpoint']}
            </div>
            <div class="vuln-detail">
                <strong>Payload:</strong>
                <pre>{vuln['payload']}</pre>
            </div>
            <div class="vuln-detail">
                <strong>Proof of Concept:</strong>
                <pre>{vuln['poc']}</pre>
            </div>
            <div class="vuln-detail">
                <strong>Response Sample:</strong>
                <pre>{vuln['response_sample'][:400] if vuln['response_sample'] else 'N/A'}</pre>
            </div>
        </div>
"""
    
    html += """
        <div class="footer">
            <p>Generated by BugHunt.ai - Automated Bug Bounty Framework</p>
            <p style="margin-top: 5px; color: #555;">Groq AI Edition (Free) - For bug bounty hunters, by hackers 🔓</p>
        </div>
    </div>
</body>
</html>
"""
    return html

# ============ MAIN ============

async def main():
    """Main orchestration."""
    if len(sys.argv) < 2:
        print("""
╔═══════════════════════════════════════╗
║      🔓 BugHunt.ai                    ║
║   Automated Recon Framework           ║
║   Groq Edition (FREE)                 ║
╚═══════════════════════════════════════╝

Usage:
  python3 bughunt_groq.py setup              # Install everything
  python3 bughunt_groq.py hunt <target>      # Run hunt
  python3 bughunt_groq.py hunt <target> <scope>

Example:
  python3 bughunt_groq.py setup
  python3 bughunt_groq.py hunt target.com
  python3 bughunt_groq.py hunt target.com scope.txt

Get free Groq API key:
  https://console.groq.com (no credit card)

Set environment:
  export GROQ_API_KEY="your-key-here"
""")
        sys.exit(1)
    
    cmd = sys.argv[1]
    
    if cmd == "setup":
        setup()
        return
    
    if cmd == "hunt":
        if len(sys.argv) < 3:
            print("Usage: python3 bughunt_groq.py hunt <target> [scope.txt]")
            sys.exit(1)
        
        target = sys.argv[2]
        scope_file = sys.argv[3] if len(sys.argv) > 3 else None
        
        if scope_file and os.path.exists(scope_file):
            scope = open(scope_file).read()
        else:
            scope = target
        
        print(f"""
╔═══════════════════════════════════════╗
║   🔍 BugHunt.ai - Auto Recon          ║
║   Target: {target:<24} ║
║   Groq: FREE AI Powered               ║
╚═══════════════════════════════════════╝
""")
        
        # Execute phases
        recon_data = recon(target)
        filtered = filter_scope(recon_data, scope)
        hypotheses = get_hypotheses(filtered, target)
        
        if not hypotheses:
            print("[!] No hypotheses generated. Check API key.")
            sys.exit(1)
        
        vulns = await test_all(target, hypotheses)
        html = generate_report(target, vulns)
        
        # Save report
        filename = f"{target.replace('.', '_')}_report.html"
        with open(filename, "w") as f:
            f.write(html)
        
        print(f"""
╔═══════════════════════════════════════╗
║   ✅ Hunt Complete!                   ║
║   Report: {filename:<24} ║
║   Vulns: {len(vulns):<28} ║
╚═══════════════════════════════════════╝
""")
        print(f"\n[+] Open {filename} in browser to view report\n")

if __name__ == "__main__":
    if sys.platform.lower().startswith('win'):
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())
