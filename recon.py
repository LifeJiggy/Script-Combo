#!/usr/bin/env python3
import sys
import os
import re
import json
import requests
from datetime import datetime
from tabulate import tabulate
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode
import tldextract

# -----------------------------
# Dependency check
# -----------------------------
def check_dependencies():
    try:
        import requests  # noqa: F401
        from tabulate import tabulate  # noqa: F401
        import tldextract  # noqa: F401
    except ImportError:
        print("[!] Missing dependencies: requests, tabulate, tldextract. Install with: pip install requests tabulate tldextract")
        sys.exit(1)

check_dependencies()

# -----------------------------
# Argument parsing
# -----------------------------
if len(sys.argv) < 6:
    print("Usage: recon.py <domain> <output_dir> <recon_types> <threads> <delay> [cookies] [proxy]")
    sys.exit(1)

DOMAIN = sys.argv[1].strip()
OUTPUT_DIR = sys.argv[2]
RECON_TYPES = [t.strip().lower() for t in sys.argv[3].split(',') if t.strip()]
THREADS = int(sys.argv[4])
DELAY = int(sys.argv[5])
COOKIES_RAW = sys.argv[6] if len(sys.argv) > 6 else ''
PROXY = sys.argv[7] if len(sys.argv) > 7 else ''
TIMESTAMP = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
REPORT_DIR = os.path.join(OUTPUT_DIR, f"recon_{TIMESTAMP}")
os.makedirs(REPORT_DIR, exist_ok=True)

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
HEADERS = {"User-Agent": USER_AGENT}
PROXIES = {"http": PROXY, "https": PROXY} if PROXY else None

# Performance caps to avoid huge datasets/timeouts
MAX_URLS = int(os.environ.get('RECON_MAX_URLS', '100000'))
MAX_WAYBACK = int(os.environ.get('RECON_MAX_WAYBACK', '50000'))
REQUEST_TIMEOUT = 20

# -----------------------------
# Helpers: domain and URL validation/normalization
# -----------------------------

def get_root_domain(domain: str) -> str:
    ext = tldextract.extract(domain)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}".lower()
    return domain.lower()

ROOT_DOMAIN = get_root_domain(DOMAIN)

SUBDOMAIN_RE = re.compile(r"^(?:[a-z0-9_\-]+\.)+" + re.escape(ROOT_DOMAIN) + r"\.?")

STATIC_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".css", ".woff", ".woff2", ".ttf", ".otf",
    ".mp4", ".mp3", ".webm", ".avi", ".mov",
    ".eot", ".map", ".pdf", ".zip", ".rar", ".7z"
}

DYNAMIC_EXTENSIONS = {".php", ".asp", ".aspx", ".jsp", ".do", ".json", ".xml", ".graphql"}

API_PATH_HINTS = (
    "/api/", "/graphql", "/v1/", "/v2/", "/auth/", "/login", "/logout", "/register", "/oauth", "/wp-json"
)


def parse_cookies(raw: str):
    if not raw:
        return None
    try:
        # Accept JSON string of cookies dict or cookie header string
        if raw.strip().startswith('{'):
            obj = json.loads(raw)
            if isinstance(obj, dict):
                return obj
        # Fallback: parse simple "k=v; k2=v2" string
        parts = [p.strip() for p in raw.split(';') if '=' in p]
        return {p.split('=', 1)[0].strip(): p.split('=', 1)[1].strip() for p in parts}
    except Exception:
        return None


COOKIES = parse_cookies(COOKIES_RAW)


def normalize_domain(name: str) -> str:
    if not name:
        return ""
    name = name.strip().lower().strip('.')
    if name.startswith('*.'):
        name = name[2:]
    # remove any stray whitespace or invalid chars
    name = re.sub(r"[^a-z0-9._\-]", "", name)
    return name


def is_valid_subdomain(name: str) -> bool:
    name = normalize_domain(name)
    if not name or name == ROOT_DOMAIN:
        return False
    # Ensure ends with ROOT_DOMAIN and contains at least one label before it
    if not name.endswith(ROOT_DOMAIN):
        return False
    if not SUBDOMAIN_RE.match(name + "."):
        return False
    # Basic label length checks
    for label in name.split('.'):
        if not label or len(label) > 63:
            return False
    return True


def normalize_url(u: str) -> str | None:
    try:
        p = urlparse(u)
        if p.scheme not in ("http", "https"):
            return None
        host = p.hostname.lower() if p.hostname else ""
        if not host:
            return None
        # drop default ports
        port = (":" + str(p.port)) if p.port and not ((p.scheme == 'http' and p.port == 80) or (p.scheme == 'https' and p.port == 443)) else ""
        if host.endswith("."):
            host = host[:-1]
        # in-scope only
        if not (host == ROOT_DOMAIN or host.endswith("." + ROOT_DOMAIN)):
            return None
        path = re.sub(r"/+", "/", p.path or "/")
        # Keep query but sort params for dedup stability
        query_pairs = parse_qsl(p.query, keep_blank_values=True)
        query_pairs.sort()
        query = urlencode(query_pairs, doseq=True)
        # Rebuild URL
        rebuilt = urlunparse((p.scheme, host + port, path, "", query, ""))
        # Avoid fragment noise by design (omitted in urlunparse)
        return rebuilt
    except Exception:
        return None


def is_static_asset(path: str) -> bool:
    _, ext = os.path.splitext(path.lower())
    return ext in STATIC_EXTENSIONS


def is_dynamic_endpoint(path: str) -> bool:
    # Dynamic if matches hints or dynamic extension
    lp = path.lower()
    if any(h in lp for h in API_PATH_HINTS):
        return True
    _, ext = os.path.splitext(lp)
    return ext in DYNAMIC_EXTENSIONS


# -----------------------------
# Storage
# -----------------------------
subdomains: set[str] = set()
urls: set[str] = set()
endpoints: set[str] = set()
js_links: set[str] = set()
sensitive_urls: set[str] = set()
api_endpoints: set[str] = set()
live_subdomains: set[str] = set()


def write_list(filename, items):
    with open(filename, 'w', encoding='utf-8') as f:
        for item in items:
            f.write(f"{item}\n")


# -----------------------------
# Recon logic
# -----------------------------

def passive_recon():
    # Subdomains: crt.sh (Certificate Transparency)
    try:
        resp = requests.get(
            f"https://crt.sh/?q=%25.{ROOT_DOMAIN}&output=json",
            headers=HEADERS,
            timeout=REQUEST_TIMEOUT,
        )
        if resp.ok:
            try:
                data = resp.json()
            except Exception:
                data = []
            for entry in data:
                for name in str(entry.get('name_value', '')).split('\n'):
                    cand = normalize_domain(name)
                    if is_valid_subdomain(cand):
                        subdomains.add(cand)
    except Exception as e:
        print(f"[!] crt.sh error: {e}")

    # Subdomains: threatcrowd (use apex host to avoid SSL hostname issue)
    try:
        resp = requests.get(
            f"https://threatcrowd.org/searchApi/v2/domain/report/?domain={ROOT_DOMAIN}",
            headers=HEADERS,
            timeout=REQUEST_TIMEOUT,
        )
        if resp.ok:
            try:
                subs = resp.json().get('subdomains', [])
            except Exception:
                subs = []
            for s in subs:
                cand = normalize_domain(s)
                if is_valid_subdomain(cand):
                    subdomains.add(cand)
    except Exception as e:
        print(f"[!] threatcrowd error: {e}")

    # URLs: web.archive.org CDX (dedup by urlkey and cap results)
    try:
        cdx_url = (
            f"https://web.archive.org/cdx/search/cdx?url=*.{ROOT_DOMAIN}/*"
            f"&output=json&fl=original&collapse=urlkey&limit={MAX_WAYBACK}"
        )
        resp = requests.get(cdx_url, headers=HEADERS, timeout=REQUEST_TIMEOUT)
        if resp.ok:
            try:
                rows = resp.json()[1:]  # skip header
            except Exception:
                rows = []
            for row in rows:
                if not row:
                    continue
                raw = row[0]
                u = normalize_url(raw)
                if not u:
                    continue
                # classify while adding
                if len(urls) < MAX_URLS:
                    urls.add(u)
                path = urlparse(u).path
                if is_dynamic_endpoint(path):
                    endpoints.add(u)
                if u.lower().endswith('.js'):
                    js_links.add(u)
                if any(h in path.lower() for h in ('/admin', '/login', '/auth', '/graphql', '/api/', '/v1/', '/v2/')):
                    sensitive_urls.add(u)
    except Exception as e:
        print(f"[!] web.archive.org error: {e}")

    # URLs: urlscan.io (lightweight)
    try:
        resp = requests.get(
            f"https://urlscan.io/api/v1/search/?q=domain:{ROOT_DOMAIN}",
            headers=HEADERS,
            timeout=REQUEST_TIMEOUT,
        )
        if resp.ok:
            try:
                results = resp.json().get('results', [])
            except Exception:
                results = []
            for result in results:
                page_url = result.get('page', {}).get('url')
                if not page_url:
                    continue
                u = normalize_url(page_url)
                if not u:
                    continue
                if len(urls) < MAX_URLS:
                    urls.add(u)
                path = urlparse(u).path
                if is_dynamic_endpoint(path):
                    endpoints.add(u)
                if u.lower().endswith('.js'):
                    js_links.add(u)
                if any(h in path.lower() for h in ('/admin', '/login', '/auth', '/graphql', '/api/', '/v1/', '/v2/')):
                    sensitive_urls.add(u)
    except Exception as e:
        print(f"[!] urlscan.io error: {e}")

    # Persist lists
    write_list(os.path.join(REPORT_DIR, 'subdomains.txt'), sorted(subdomains))
    write_list(os.path.join(REPORT_DIR, 'urls.txt'), sorted(urls))
    write_list(os.path.join(REPORT_DIR, 'endpoints.txt'), sorted(endpoints))
    write_list(os.path.join(REPORT_DIR, 'js_links.txt'), sorted(js_links))
    write_list(os.path.join(REPORT_DIR, 'sensitive_urls.txt'), sorted(sensitive_urls))

    # API endpoints validation (HEAD, fast, only likely API)
    for u in list(endpoints):
        lp = u.lower()
        if ('/api/' not in lp and '/graphql' not in lp and not lp.endswith('.json')):
            continue
        try:
            resp = requests.head(u, headers=HEADERS, cookies=COOKIES, proxies=PROXIES, timeout=5, allow_redirects=True)
            ctype = resp.headers.get('Content-Type', '')
            if resp.ok and ('application/json' in ctype or 'graphql' in ctype or lp.endswith('.json')):
                api_endpoints.add(u)
        except Exception:
            pass
    write_list(os.path.join(REPORT_DIR, 'api_endpoints.txt'), sorted(api_endpoints))


def active_recon():
    if not subdomains:
        print("[!] No subdomains found in passive recon. Skipping active recon.")
        return
    for sub in sorted(subdomains):
        for scheme in ("http", "https"):
            try:
                resp = requests.head(f"{scheme}://{sub}", headers=HEADERS, timeout=3, allow_redirects=True)
                if resp.ok:
                    live_subdomains.add(sub)
                    break
            except Exception:
                continue
    write_list(os.path.join(REPORT_DIR, 'live_subdomains.txt'), sorted(live_subdomains))


# -----------------------------
# Output & reporting
# -----------------------------

def display_table():
    table = [
        ["Subdomains", len(subdomains)],
        ["Live Subdomains", len(live_subdomains)],
        ["URLs", len(urls)],
        ["Endpoints", len(endpoints)],
        ["JS Links", len(js_links)],
        ["Sensitive URLs", len(sensitive_urls)],
        ["API Endpoints", len(api_endpoints)],
    ]
    print("\nRecon Results Summary:")
    print(tabulate(table, headers=["Type", "Count"], tablefmt="grid"))
    with open(os.path.join(REPORT_DIR, 'recon.log'), 'a', encoding='utf-8') as f:
        f.write(tabulate(table, headers=["Type", "Count"], tablefmt="grid") + '\n')


def output_json():
    data = {
        "root_domain": ROOT_DOMAIN,
        "subdomains": sorted(list(subdomains)),
        "live_subdomains": sorted(list(live_subdomains)),
        "urls": sorted(list(urls)),
        "endpoints": sorted(list(endpoints)),
        "js_links": sorted(list(js_links)),
        "sensitive_urls": sorted(list(sensitive_urls)),
        "api_endpoints": sorted(list(api_endpoints)),
    }
    # Write to timestamped report dir
    report_path = os.path.join(REPORT_DIR, 'recon.json')
    with open(report_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    # Also write a copy to OUTPUT_DIR for orchestrators expecting it right under the scan dir
    flat_path = os.path.join(OUTPUT_DIR, 'recon.json')
    with open(flat_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    print(f"[*] Recon results saved to {report_path}")


# -----------------------------
# Main
# -----------------------------
if 'passive' in RECON_TYPES:
    print("[*] Starting passive recon...")
    passive_recon()
    print("[*] Passive recon completed.")

if 'active' in RECON_TYPES:
    print("[*] Starting active recon...")
    active_recon()
    print("[*] Active recon completed.")

output_json()
display_table()
