#!/usr/bin/env python3
import json
import os
import subprocess
import re
import time
import random
from pathlib import Path
from datetime import datetime
from termcolor import colored
import pyfiglet
import requests
from urllib.parse import urlparse
from tabulate import tabulate
import logging  
import platform
import subprocess
import validators
import jsonschema
from jsonschema import validate

# Setup logging with JSON format
logging.basicConfig(
    filename="triad_error.log",
    level=logging.ERROR,
    format='%(asctime)s - %(levelname)s - %(message)s - Context: %(context)s'
)


# Dependency check
def check_dependencies():
    required = ['termcolor', 'pyfiglet', 'requests', 'tabulate', 'validators', 'jsonschema']
    missing = []
    for dep in required:
        try:
            __import__(dep)
        except ImportError:
            missing.append(dep)
    if missing:
        print(colored(f"[!] Missing dependencies: {', '.join(missing)}", "red"))
        print(colored("[!] Install with: pip install " + " ".join(missing), "red"))
        exit(1)

check_dependencies()

# JSON schemas for validation
LOGIN_CREDS_SCHEMA = {
    "type": "object",
    "properties": {
        "username": {"type": "string"},
        "password": {"type": "string"},
        "proxy": {"type": "string"}
    },
    "additionalProperties": False
}

SELECTIONS_SCHEMA = {
    "type": "array",
    "items": {
        "type": "object",
        "properties": {
            "type": {"type": "string"},
            "details": {"type": ["array", "object"]},
            "reflected": {"type": "boolean"},
            "vulnerable": {"type": "boolean"},
            "vuln_reason": {"type": "string"},
            "sanitized": {"type": "boolean"},
            "sanitization_method": {"type": "string"},
            "bypass_method": {"type": "string"}
        },
        "required": ["type", "details"],
        "additionalProperties": True
    }
}

# Banner (UNCHANGED)
def display_banner():
    banner = pyfiglet.figlet_format("Triad")
    print(colored(banner, "green"))
    print(colored("Ultimate Recon & Mapping Tool for Bug Bounty Hunters", "cyan"))
    print(colored("Version 7.0", "cyan"))
    print(colored("By ArkhAngelLifeJiggy", "cyan"))
    print(colored("========================================", "cyan"))

# Validate URL
def validate_url(url, timeout=360):
    if not validators.url(url):
        print(colored(f"[!] Invalid URL format: {url}", "red"))
        print(colored("[!] Please enter a valid URL (e.g., https://example.com)", "red"))
        return None
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ['http', 'https']:
            print(colored(f"[!] Invalid URL scheme: {url}", "red"))
            return None
        if not parsed.netloc:
            print(colored(f"[!] Invalid URL netloc: {url}", "red"))
            return None
        response = requests.get(url, allow_redirects=True, timeout=timeout)
        if response.status_code not in [200, 301, 302]:
            print(colored(f"[!] URL {url} returned status {response.status_code}", "red"))
            return None
        final_url = response.url
        print(colored(f"[*] Following redirect to: {final_url}", "green"))
        return final_url
    except requests.RequestException as e:
        print(colored(f"[!] URL validation error: {e}", "red"))
        logging.error(f"URL validation error: {str(e)}", extra={"context": {"url": url}})
        retry = input(colored("[*] Retry URL entry? (y/n): ", "yellow")).strip().lower()
        if retry != 'y':
            exit(1)
        return None

# NEW: Moved sanitize_data here and fixed
def sanitize_data(data):
    if isinstance(data, dict):
        return {k: sanitize_data(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [sanitize_data(item) for item in data]
    elif isinstance(data, str):
        return data.encode('utf-8', errors='ignore').decode('utf-8')
    return data

# Save output to JSON
def save_json(data, filename):
    try:
        data = sanitize_data(data)
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(colored(f"[*] Saved output to {filename}", "green"))
    except Exception as e:
        print(colored(f"[!] Error saving JSON: {e}", "red"))
        logging.error(f"JSON save error: {str(e)}", extra={"context": {"filename": filename}})
        raise

# Detect WAF
def detect_waf(url, headers, user_agents, timeout=360):
    try:
        headers = headers[0] if headers else {}
        headers['User-Agent'] = random.choice(user_agents) if user_agents else "Mozilla/5.0"
        response = requests.get(url, headers=headers, allow_redirects=True, timeout=timeout)
        if response.status_code != 200:
            print(colored(f"[!] WAF detection failed: Status {response.status_code}", "yellow"))
            return None
        waf_headers = ['server', 'x-powered-by', 'x-waf', 'x-firewall']
        waf_signatures = ["cloudflare", "akamai", "imperva", "f5", "sucuri", "aws_waf", "fastly", "incapsula", "mod_security", "citrix"]
        detected_waf = None
        for header in response.headers:
            if header.lower() in waf_headers:
                for waf in waf_signatures:
                    if waf.lower() in response.headers[header].lower():
                        detected_waf = waf
                        break
        return detected_waf
    except requests.RequestException as e:
        print(colored(f"[!] WAF detection error: {e}", "yellow"))
        logging.error(f"WAF detection error: {str(e)}", extra={"context": {"url": url}})
        return None
# Random user agents, headers, encodings (UNCHANGED)
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko20100101 Firefox/89.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.48",
    "Mozilla/5.0 (Linux; Android 11; SM-G991B) AppleWebKit/53736 605.1.15 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/53736.36",
    "Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0"
]
HEADERS = [
    {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5", "Connection": "keep-alive"},
    {"Accept": "application/json, text/javascript, */*; q=0.01", "X-Requested-With": "XMLHttpRequest", "Connection": "close"},
    {"Accept": "*/*", "Accept-Encoding": "gzip, deflate, br", "via": "1.1 vegur"},
    {"Accept": "text/html,application/xhtml+xml", "DNT": "1", "Connection": "keep-alive"},
    {"Accept": "application/json", "Accept-Language": "en-US,en;q=0.9", "Connection": "keep-alive"},
    {"Accept": "text/plain, */*; q=0.01", "X-Forwarded-For": "127.0.0.1", "Connection": "keep-alive"},
    {"Accept": "application/xml", "Accept-Encoding": "gzip, deflate", "Connection": "close"},
    {"Accept": "text/html", "Referer": "https://www.google.com", "Connection": "keep-alive"},
    {"Accept": "application/json, text/plain, */*", "Origin": "https://www.google.com", "Connection": "close"},
    {"Accept": "*/*", "Accept-Language": "en-GB,en;q=0.5", "Connection": "keep-alive"}
]
ENCODINGS = [
    "urlencode", "base64", "double_urlencode", "htmlencode", "unicode_escape",
    "hex", "urlencode_plus", "base64_urlsafe", "percent_encoding", "json_escape",
    "utf8_encode", "xml_escape", "backslash_escape", "percent_encode_slash",
    "unicode_hex", "base64_padded", "urlencode_space", "html_entity",
    "raw_unicode", "double_base64"
]

def get_random_headers(count):
    return random.sample(HEADERS, min(count, len(HEADERS)))

def get_random_user_agent(count):
    return random.sample(USER_AGENTS, min(count, len(USER_AGENTS)))

# Validate proxy
def validate_proxy(proxy, timeout=360):
    if not proxy:
        return True
    try:
        response = requests.get("https://www.google.com", proxies={"http": proxy, "https": proxy}, timeout=timeout)
        return response.status_code == 200
    except requests.RequestException as e:
        print(colored(f"[!] Proxy validation failed: {e}", "red"))
        logging.error(f"Proxy validation error: {str(e)}", extra={"context": {"proxy": proxy}})
        return False


# Run Bash recon
def run_recon(url, recon_types, output_dir, threads, delay, cookies, proxy, timeout=360, retry_count=5):
    print(colored(f"[*] Starting recon for {url}...", "yellow"))
    bash_path = "bash"
    if platform.system() == "Windows":
        bash_path = r"C:\Program Files\Git\bin\bash.exe"
        if not os.path.exists(bash_path):
            print(colored("[!] Git Bash not found. Please install Git or adjust bash_path.", "red"))
            return None
    
    cmd = [bash_path, "recon.sh", url, output_dir, ",".join(recon_types), str(threads), str(delay), cookies or "", proxy or ""]
    for attempt in range(retry_count):
        try:
            print(colored(f"[*] Recon attempt {attempt + 1}/{retry_count}...", "blue"))
            response = requests.get(url, allow_redirects=True, timeout=timeout)
            if response.status_code != 200:
                print(colored(f"[!] Recon failed: Status {response.status_code}", "yellow"))
                continue
            result = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=timeout)
            print(result.stdout)
            output_file = f"{output_dir}/recon.json"
            if os.path.exists(output_file):
                with open(output_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    return sanitize_data(data)
            else:
                print(colored(f"[!] Recon output file not found: {output_file}", "red"))
                continue
        except Exception as e:
            print(colored(f"[!] Recon error (attempt {attempt + 1}): {e}", "red"))
            logging.error(f"Recon error: {str(e)}", extra={"context": {"url": url, "attempt": attempt + 1}})
            if attempt < retry_count - 1:
                print(colored(f"[*] Retrying in 5 seconds...", "yellow"))
                time.sleep(5)
    print(colored("[!] All recon retries failed. Skipping to next phase.", "red"))
    return None

# Run JS extraction
def run_js_extract(url, output_dir, js_links, headers, user_agents, timeout=360, retry_count=5, threads=30, delay=20):
    print(colored(f"[*] Extracting JS data for {url}...", "yellow"))
    cmd = [
        "node", "js_extract.js", url, output_dir, "regex",
        ",".join(js_links), json.dumps(headers), json.dumps(user_agents),
        "10", str(threads), str(delay), "{}"
    ]
    for attempt in range(retry_count):
        try:
            print(colored(f"[*] JS extract attempt {attempt + 1}/{retry_count}...", "blue"))
            response = requests.get(url, allow_redirects=True, timeout=timeout)
            if response.status_code != 200:
                print(colored(f"[!] JS extract failed: Status {response.status_code}", "yellow"))
                continue
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 60)
            if result.returncode != 0:
                print(colored(f"[!] JS extraction failed: {result.stderr}", "red"))
                logging.error(f"JS extraction failed: {result.stderr}", extra={"context": {"url": url, "attempt": attempt + 1}})
                continue
            output_file = f"{output_dir}/js_data.json"
            if os.path.exists(output_file):
                with open(output_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    return sanitize_data(data)
            else:
                print(colored(f"[!] JS data file not found: {output_file}", "red"))
                continue
        except Exception as e:
            print(colored(f"[!] JS extract error (attempt {attempt + 1}): {e}", "red"))
            logging.error(f"JS extract error: {str(e)}", extra={"context": {"url": url, "attempt": attempt + 1}})
            if attempt < retry_count - 1:
                print(colored(f"[*] Retrying in 5 seconds...", "yellow"))
                time.sleep(5)
    print(colored("[!] All JS extract retries failed. Skipping to next phase.", "red"))
    return None

# Interactive menu (UNCHANGED)
def interactive_menu():
    display_banner()
    while True:
        print(colored("[*] Enter target URL (e.g., https://example.com):", "cyan"))
        url = input("> ").strip()
        url = validate_url(url)
        if url:
            break
        print(colored("[!] Please enter a valid URL.", "red"))
        retry = input(colored("[*] Retry URL entry? (y/n): ", "cyan")).strip().lower()
        if retry != 'y':
            return None, None, None, None, [], None, None, None, None, None, None

    detected_waf = detect_waf(url, HEADERS, USER_AGENTS)
    if detected_waf:
        print(colored(f"[!] Detected WAF: {detected_waf}", "yellow"))
    else:
        print(colored("[*] No WAF detected.", "green"))

    valid_phases = ["recon", "regex", "mapping"]
    while True:
        print(colored("[*] Select phases (comma-separated: recon,regex,mapping):", "cyan"))
        phases = input("> ").strip().lower().split(',')
        if all(p in valid_phases for p in phases):
            break
        print(colored(f"[!] Invalid phases. Choose: {', '.join(valid_phases)}", "red"))
        retry = input(colored("[*] Retry phase selection? (y/n): ", "cyan")).strip().lower()
        if retry != 'y':
            return None, None, None, None, None, None, None, None, None, None, None

    recon_types = []
    if "recon" in phases:
        valid_recon_types = ["passive", "active"]
        while True:
            print(colored("[*] Select recon types (comma-separated: passive,active):", "cyan"))
            recon_types = input("> ").strip().lower().split(',')
            if all(r in valid_recon_types for r in recon_types):
                break
            print(colored(f"[!] Invalid recon types. Choose: {', '.join(valid_recon_types)}", "red"))
            retry = input(colored("[*] Retry recon type selection? (y/n): ", "cyan")).strip().lower()
            if retry != 'y':
                return None, None, None, None, None, None, None, None, None, None, None

    threads = 30
    delay = 20
    timeout = 360
    ua_count = 5
    rh_count = 5
    rotate_time = 600
    crawl_depth = 10
    login_creds = None
    proxy = None
    
    if "recon" in phases or "mapping" in phases:
        while True:
            print(colored("[*] Enter threads (1-500, default 30):", "cyan"))
            threads = input("> ").strip() or "30"
            print(colored("[*] Enter delay (1-100s, default 20):", "cyan"))
            delay = input("> ").strip() or "20"
            print(colored("[*] Enter navigation timeout in seconds (30-600, default 360):", "cyan"))
            timeout = input("> ").strip() or "360"
            print(colored("[*] Enter number of user agents (1-10, default 5):", "cyan"))
            ua_count = input("> ").strip() or "5"
            print(colored("[*] Enter number of request headers (1-10, default 5):", "cyan"))
            rh_count = input("> ").strip() or "5"
            print(colored("[*] Enter header rotation time (seconds, default 600):", "cyan"))
            rotate_time = input("> ").strip() or "600"
            print(colored("[*] Enter crawl depth (1-300, default 10):", "cyan"))
            crawl_depth = input("> ").strip() or "10"
            print(colored("[*] Enter login credentials (JSON, e.g., {\"username\":\"user\",\"password\":\"pass\"}) or press Enter to skip:", "cyan"))
            login_input = input("> ").strip()
            if login_input:
                try:
                    login_creds = json.loads(login_input)
                    validate(login_creds, LOGIN_CREDS_SCHEMA)
                except (json.JSONDecodeError, jsonschema.exceptions.ValidationError) as e:
                    print(colored(f"[!] Invalid login credentials JSON: {e}", "red"))
                    login_creds = None
                    retry = input(colored("[*] Retry login credentials? (y/n): ", "cyan")).strip().lower()
                    if retry != 'y':
                        return None, None, None, None, None, None, None, None, None, None, None
                    continue
            print(colored("[*] Enter Burp proxy (e.g., http://127.0.0.1:8080) or press Enter to skip:", "cyan"))
            proxy = input("> ").strip() or None
            if proxy and not validate_proxy(proxy):
                retry = input(colored("[*] Retry proxy entry? (y/n): ", "cyan")).strip().lower()
                if retry != 'y':
                    proxy = None
                continue
            try:
                threads = int(threads)
                delay = int(delay)
                timeout = int(timeout)
                ua_count = int(ua_count)
                rh_count = int(rh_count)
                rotate_time = int(rotate_time)
                crawl_depth = int(crawl_depth)
                if (1 <= threads <= 500 and 1 <= delay <= 100 and
                    30 <= timeout <= 600 and 1 <= ua_count <= 10 and
                    1 <= rh_count <= 10 and 1 <= crawl_depth <= 300):
                    break
                print(colored("[!] Invalid input values", "red"))
                retry = input(colored("[*] Retry input values? (y/n): ", "cyan")).strip().lower()
                if retry != 'y':
                    return None, None, None, None, None, None, None, None, None, None, None
            except ValueError:
                print(colored("[!] Invalid numeric input", "red"))
                retry = input(colored("[*] Retry input values? (y/n): ", "cyan")).strip().lower()
                if retry != 'y':
                    return None, None, None, None, None, None, None, None, None, None, None

    return url, phases, recon_types, threads, delay, timeout, ua_count, rh_count, rotate_time, crawl_depth, login_creds, proxy


# Mapping function
def run_mapping(url, output_dir, threads, delay, headers, user_agents, crawl_depth, login_creds=None, proxy=None, phase="enumerate", selections=None, timeout=360, retry_count=5):
    print(colored(f"[*] Starting {phase} phase for {url}...", "yellow"))
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    domain = urlparse(url).netloc
    output_path = Path(output_dir) / domain / f"_{timestamp}"
    output_path.mkdir(parents=True, exist_ok=True)
    output_file = str(output_path / f"{phase}.json")
    
    # Corrected argument order to match js_extract.js
    cmd = [
        "node", "js_extract.js", url, str(output_path), phase,
        ",".join([]),  # jsLinks (empty for non-regex modes)
        json.dumps(headers), json.dumps(user_agents),
        str(crawl_depth), str(threads), str(delay),
        json.dumps(login_creds or {}), json.dumps(selections or []), str(timeout * 1000)  # Convert to ms
    ]
    
    for attempt in range(retry_count):
        print(colored(f"[*] {phase.capitalize()} attempt {attempt + 1}/{retry_count}...", "blue"))
        try:
            env = os.environ.copy()
            if proxy:
                env["HTTP_PROXY"] = proxy
                env["HTTPS_PROXY"] = proxy
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 120, env=env)
            if result.returncode != 0:
                print(colored(f"[!] {phase.capitalize()} failed: {result.stderr}", "red"))
                logging.error(f"{phase} failed: {result.stderr}", extra={"context": {"url": url, "attempt": attempt + 1}})
                if "TimeoutError" in result.stderr or "ProtocolError" in result.stderr:
                    print(colored(f"[*] Detected timeout in JS execution. Retrying with shorter crawl depth...", "yellow"))
                    cmd[8] = str(max(1, int(crawl_depth) // 2))
                    continue
                continue
            if os.path.exists(output_file):
                with open(output_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    data = sanitize_data(data)
                    try:
                        if phase in ["reflection", "sinks", "vulnerable", "sanitization", "characters"]:
                            validate(data, {"type": "object", "properties": {phase: SELECTIONS_SCHEMA}, "required": [phase]})
                        for key in data:
                            if isinstance(data[key], list):
                                data[key] = [item for item in data[key] if item]
                            elif isinstance(data[key], dict):
                                data[key] = {k: v for k, v in data[key].items() if v}
                        if phase == "enumerate" and len(data.get('functionalities', [])) < 50:
                            logging.warning(f"Low functionality count: {len(data.get('functionalities', []))}", extra={"context": {"url": url}})
                        return data
                    except jsonschema.exceptions.ValidationError as e:
                        print(colored(f"[!] Invalid data schema in {phase}: {e}", "red"))
                        logging.error(f"Schema validation error in {phase}: {str(e)}", extra={"context": {"file": output_file}})
                        continue
            else:
                print(colored(f"[!] {phase.capitalize()} file not found: {output_file}", "red"))
                continue
        except Exception as e:
            print(colored(f"[!] {phase.capitalize()} error (attempt {attempt + 1}): {e}", "red"))
            logging.error(f"{phase} error: {str(e)}", extra={"context": {"url": url, "attempt": attempt + 1}})
            if attempt < retry_count - 1:
                print(colored(f"[*] Retrying in 5 seconds...", "yellow"))
                time.sleep(5)
    print(colored(f"[!] All {phase} retries failed. Skipping phase.", "red"))
    return None

# Display table (UNCHANGED)
def display_table(phase, data, headers):
    if not data:
        print(colored(f"[!] No data to display for {phase}", "red"))
        return
    table = []
    filtered = []
    for item in data:
        row = [item.get(h, '') for h in headers]
        if not item.get('details') or (isinstance(item.get('details'), list) and not item.get('details')):
            filtered.append(item)
            table.append(row)  # Include even empty details
        else:
            table.append(row)
    if not table:
        print(colored(f"[!] No data to display for {phase} after filtering", "red"))
        return
    if filtered:
        logging.warning(f"Filtered {len(filtered)} empty entries in {phase}", extra={"context": {"filtered": filtered}})
        print(colored(f"[*] Note: {len(filtered)} functionalities with empty details included in table", "yellow"))
    print(colored(f"\n[*] {phase.capitalize()} Results:", "cyan"))
    print(tabulate(table, headers=headers, tablefmt="grid"))



# Run enumeration
def run_enumeration(url, config):
    try:
        return run_mapping(
            url=url,
            output_dir=config['output_dir'],
            threads=config['threads'],
            delay=config['delay'],
            headers=config['headers'],
            user_agents=config['user_agents'],
            crawl_depth=config['crawl_depth'],
            login_creds=config['login_creds'],
            proxy=config['proxy'],
            timeout=config['timeout'],
            phase="enumerate"
        )
    except Exception as e:
        print(colored(f"[!] Enumeration error: {e}", "red"))
        logging.error(f"Enumeration error: {str(e)}", extra={"context": {"url": url}})
        return None

# Save output
def save_output(data, output_dir, phase):
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    domain = urlparse(data.get('url', 'http://example.com')).netloc
    output_path = Path(output_dir) / domain / f"_{timestamp}"
    output_path.mkdir(parents=True, exist_ok=True)
    output_file = str(output_path / f"{phase}.json")
    save_json(data, output_file)

# Display enumeration results
def display_enum_results(data):
    table_data = [
        {
            "Type": f["type"],
            "Details": str(f["details"])[:50] + "..." if len(str(f["details"])) > 50 else str(f["details"])
        } for f in data.get('functionalities', [])
    ]
    display_table("Enumeration", table_data, ["Type", "Details"])
    print(colored(f"[*] Total functionalities enumerated: {len(table_data)}", "green"))

# Main execution
def main():
    while True:
        url, phases, recon_types, threads, delay, timeout, ua_count, rh_count, rotate_time, crawl_depth, login_creds, proxy = interactive_menu()
        if not url:
            print(colored("[!] Exiting due to invalid input", "red"))
            return

        output_dir = f"output/{url.replace('https://', '').replace('http://', '')}_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}"
        os.makedirs(output_dir, exist_ok=True)
        headers = get_random_headers(rh_count)
        user_agents = get_random_user_agent(ua_count)
        start_time = time.time()

        config = {
            'url': url,
            'output_dir': output_dir,
            'threads': threads,
            'delay': delay,
            'timeout': timeout,
            'headers': headers,
            'user_agents': user_agents,
            'crawl_depth': crawl_depth,
            'login_creds': login_creds,
            'proxy': proxy
        }

        recon_data = None
        js_data = None
        enum_data = None
        reflect_data = None
        sink_data = None
        vuln_data = None
        sani_data = None
        char_data = None


        if "recon" in phases:
            recon_data = run_recon(url, recon_types, output_dir, threads, delay, "", proxy, timeout)
            if recon_data:
                save_json(recon_data, f"{output_dir}/recon.json")
                table_data = [
                    {"Subdomain": s, "URL": u} for s, u in zip(recon_data.get('subdomains', []), recon_data.get('urls', []))
                ]
                display_table("Recon", table_data, ["Subdomain", "URL"])
                print(colored(f"[*] Recon completed: {len(recon_data.get('subdomains', []))} subdomains, {len(recon_data.get('urls', []))} URLs", "green"))
            else:
                retry = input(colored("[*] Retry recon phase? (y/n): ", "cyan")).strip().lower()
                if retry == 'y':
                    continue
                recon_data = {}

        if "regex" in phases:
            if not recon_data or not recon_data.get('js_links'):
                print(colored("[!] No JS links found. Run recon first.", "red"))
                retry = input(colored("[*] Retry with recon phase? (y/n): ", "cyan")).strip().lower()
                if retry == 'y':
                    phases.append("recon")
                    continue
            js_links = recon_data.get('js_links', [])
            print(colored(f"[*] Found {len(js_links)} JS files:", "cyan"))
            for i, link in enumerate(js_links, 1):
                print(colored(f"  {i}. {link}", "cyan"))
            print(colored("[*] Select JS links to analyze (e.g., 1,3,6 or 'all'):", "cyan"))
            choice = input("> ").strip().lower()
            try:
                selected_links = js_links if choice == 'all' else [js_links[int(i) - 1] for i in choice.split(',') if i.isdigit() and 1 <= int(i) <= len(js_links)]
            except (IndexError, ValueError) as e:
                print(colored(f"[!] Invalid JS link selection: {e}", "red"))
                retry = input(colored("[*] Retry JS link selection? (y/n): ", "cyan")).strip().lower()
                if retry != 'y':
                    continue
                selected_links = js_links
              
            js_data = run_js_extract(url, output_dir, selected_links, headers, user_agents, timeout)
            if js_data:
                save_json(js_data, f"{output_dir}/js_data.json")
                table_data = [{"Link": s["link"], "Match": s["value"]} for s in js_data.get('sensitive', [])]
                display_table("Regex", table_data, ["Link", "Match"])
                print(colored(f"[*] JS extraction completed: {len(js_data.get('sensitive', []))} sensitive findings", "green"))
            else:
                retry = input(colored("[*] Retry regex phase? (y/n): ", "cyan")).strip().lower()
                if retry == 'y':
                    continue
                js_data = {}

        if "mapping" in phases:
            print(colored("[*] Starting Enumeration Phase...", "yellow"))
            enum_data = run_enumeration(url, config)
            if enum_data:
                save_json(enum_data, f"{output_dir}/enumerate.json")
                display_enum_results(enum_data)
                print(colored(f"[*] Enumeration completed: {len(enum_data.get('functionalities', []))} functionalities", "green"))
            else:
                retry = input(colored("[*] Retry enumeration phase? (y/n): ", "cyan")).strip().lower()
                if retry == 'y':
                    enum_data = run_enumeration(url, config)
                    if enum_data:
                        save_output(enum_data, output_dir, 'enumerate')
                        display_enum_results(enum_data)
                        print(colored(f"[*] Enumeration retry completed: {len(enum_data.get('functionalities', []))} functionalities", "green"))
                    else:
                        print(colored("[*] Skipping enumeration phase", "yellow"))
                        enum_data = {}
                    continue
                enum_data = {}

            if enum_data.get('functionalities'):
                print(colored("[*] Select functionalities for reflection check (e.g., 1,3,5 or 'all'):", "cyan"))
                for i, f in enumerate(enum_data.get('functionalities', []), 1):
                    print(colored(f"  {i}. {f['type']}: {str(f['details'])[:50]}...", "cyan"))
                choice = input("> ").strip().lower()
                try:
                    selections = [enum_data['functionalities'][int(i) - 1] for i in choice.split(',') if i.isdigit() and 1 <= int(i) <= len(enum_data['functionalities'])] if choice != 'all' else enum_data['functionalities']
                    validate(selections, SELECTIONS_SCHEMA)
                except (IndexError, ValueError, jsonschema.exceptions.ValidationError) as e:
                    print(colored(f"[!] Invalid functionality selection: {e}", "red"))
                    retry = input(colored("[*] Retry functionality selection? (y/n): ", "cyan")).strip().lower()
                    if retry != 'y':
                        selections = enum_data['functionalities']
                    else:
                        continue

                print(colored("[*] Check reflection in (body,dom,both):", "cyan"))
                reflect_scope = input("> ").strip().lower().split(',')
                if not all(s in ['body', 'dom', 'both'] for s in reflect_scope):
                    reflect_scope = ['both']
                
                try:
                    reflect_data = run_mapping(url, output_dir, threads, delay, headers, user_agents, crawl_depth, login_creds, proxy, "reflection", selections, timeout)
                    if reflect_data:
                        save_json(reflect_data, f"{output_dir}/reflection.json")
                        table_data = [
                            {
                                "Type": f["type"],
                                "Details": str(f["details"])[:50] + "..." if len(str(f["details"])) > 50 else str(f["details"]),
                                "Reflected": f["reflected"],
                                "Scope": ", ".join(reflect_scope)
                            } for f in reflect_data.get('reflection', [])
                        ]
                        display_table("Reflection", table_data, ["Type", "Details", "Reflected", "Scope"])
                        print(colored("[*] Reflection check completed", "green"))
                    else:
                        retry = input(colored("[*] Retry reflection phase? (y/n): ", "cyan")).strip().lower()
                        if retry == 'y':
                            continue
                        reflect_data = {}
                except Exception as e:
                    print(colored(f"[!] Reflection error: {e}", "red"))
                    logging.error(f"Reflection error: {str(e)}", extra={"context": {"url": url}})
                    reflect_data = {}

            if reflect_data and reflect_data.get('reflection'):
                try:
                    print(colored("[*] Select functionalities for sink check (e.g., 1,3,5 or 'all'):", "cyan"))
                    for i, f in enumerate(enum_data.get('functionalities', []), 1):
                        print(colored(f"  {i}. {f['type']}: {str(f['details'])[:50]}...", "cyan"))
                    choice = input("> ").strip().lower()
                    selections = [enum_data['functionalities'][int(i) - 1] for i in choice.split(',') if i.isdigit() and 1 <= int(i) <= len(enum_data['functionalities'])] if choice != 'all' else enum_data['functionalities']
                    validate(selections, SELECTIONS_SCHEMA)

                    sink_data = run_mapping(url, output_dir, threads, delay, headers, user_agents, crawl_depth, login_creds, proxy, "sinks", selections, timeout)
                    if sink_data:
                        save_json(sink_data, f"{output_dir}/sinks.json")
                        table_data = [
                            {
                                "Type": f["type"],
                                "Details": str(f["details"])[:50] + "..." if len(str(f["details"])) > 50 else str(f["details"]),
                                "Sink": f["sink"],
                                "Sink Type": f.get("sink_type", "Unknown")
                            } for f in sink_data.get('sinks', [])
                        ]
                        display_table("Sinks", table_data, ["Type", "Details", "Sink", "Sink Type"])
                        print(colored("[*] Sink check completed", "green"))
                    else:
                        retry = input(colored("[*] Retry sinks phase? (y/n): ", "cyan")).strip().lower()
                        if retry == 'y':
                            continue
                        sink_data = {}
                except Exception as e:
                    print(colored(f"[!] Sink check error: {e}", "red"))
                    logging.error(f"Sink error: {str(e)}", extra={"context": {"url": url}})
                    sink_data = {}

            if sink_data:
                try:
                    print(colored("[*] Select functionalities for vulnerability check (e.g., 1,3,5 or 'all'):", "cyan"))
                    for i, f in enumerate(enum_data.get('functionalities', []), 1):
                        print(colored(f"  {i}. {f['type']}: {str(f['details'])[:50]}...", "cyan"))
                    choice = input("> ").strip().lower()
                    selections = [enum_data['functionalities'][int(i) - 1] for i in choice.split(',') if i.isdigit() and 1 <= int(i) <= len(enum_data['functionalities'])] if choice != 'all' else enum_data['functionalities']
                    validate(selections, SELECTIONS_SCHEMA)

                    vuln_data = run_mapping(url, output_dir, threads, delay, headers, user_agents, crawl_depth, login_creds, proxy, "vulnerable", selections, timeout)
                    if vuln_data:
                        save_json(vuln_data, f"{output_dir}/vulnerable.json")
                        table_data = [
                            {
                                "Type": f["type"],
                                "Details": str(f["details"])[:50] + "..." if len(str(f["details"])) > 50 else str(f["details"]),
                                "Vulnerable": f["vulnerable"],
                                "Reason": f.get("vuln_reason", "Unknown")
                            } for f in vuln_data.get('vulnerable', [])]
                        display_table("Vulnerable", table_data, ["Type", "Details", "Vulnerable", "Reason"])
                        print(colored("[*] Vulnerability check completed", "green"))
                    else:
                        retry = input(colored("[*] Retry vulnerable phase? (y/n): ", "cyan")).strip().lower()
                        if retry == 'y':
                            continue
                        vuln_data = {}
                except Exception as e:
                    print(colored(f"[!] Vulnerability check error: {e}", "red"))
                    logging.error(f"Vulnerability error: {str(e)}", extra={"context": {"url": url}})
                    vuln_data = {}

            if vuln_data:
                try:
                    print(colored("[*] Select functionalities for sanitization check (e.g., 1,3,5 or 'all'):", "cyan"))
                    for i, f in enumerate(enum_data.get('functionalities', []), 1):
                        print(colored(f"  {i}. {f['type']}: {str(f['details'])[:50]}...", "cyan"))
                    choice = input("> ").strip().lower()
                    selections = [enum_data['functionalities'][int(i) - 1] for i in choice.split(',') if i.isdigit() and 1 <= int(i) <= len(enum_data['functionalities'])] if choice != 'all' else enum_data['functionalities']
                    validate(selections, SELECTIONS_SCHEMA)

                    sani_data = run_mapping(url, output_dir, threads, delay, headers, user_agents, crawl_depth, login_creds, proxy, "sanitization", selections, timeout)
                    if sani_data:
                        save_json(sani_data, f"{output_dir}/sanitization.json")
                        table_data = [
                            {
                                "Type": f["type"],
                                "Details": str(f["details"])[:50] + "..." if len(str(f["details"])) > 50 else str(f["details"]),
                                "Sanitized": f["sanitized"],
                                "Method": f.get("method", "None"),
                                "Bypass": f.get("bypass_method", "None")
                            } for f in sani_data.get('sanitization', [])]
                        display_table("Sanitization", table_data, ["Type", "Details", "Sanitized", "Method", "Bypass"])
                        print(colored("[*] Sanitization check completed", "green"))
                    else:
                        retry = input(colored("[*] Retry sanitization phase? (y/n): ", "cyan")).strip().lower()
                        if retry == 'y':
                            continue
                        sani_data = {}
                except Exception as e:
                    print(colored(f"[!] Sanitization error: {e}", "red"))
                    logging.error(f"Sanitization error: {str(e)}", extra={"context": {"url": url}})
                    sani_data = {}

            if sani_data:
                try:
                    print(colored("[*] Select functionalities for special character check (e.g., 1,3,5 or 'all'):", "cyan"))
                    for i, f in enumerate(enum_data.get('functionalities', []), 1):
                        print(colored(f"  {i}. {f['type']}: {str(f['details'])[:50]}...", "cyan"))
                    choice = input("> ").strip().lower()
                    selections = [enum_data['functionalities'][int(i) - 1] for i in choice.split(',') if i.isdigit() and 1 <= int(i) <= len(enum_data['functionalities'])] if choice != 'all' else enum_data['functionalities']
                    validate(selections, SELECTIONS_SCHEMA)

                    print(colored("[*] Select special characters (e.g., <,>,\" or 'all'):", "cyan"))
                    char_choice = input("> ").strip().lower()
                    chars = char_choice.split(',') if char_choice != 'all' else ['<', '>', '"', '\'', ';', '&', '--', '-', '|', '(', ')', '`', ',', ':', '{', '}', '[', ']', '$', '*', '%', '#', '@', '!', '?', '/', '\\', '=', '+', '-', '_', '\u202E']
                    char_data = run_mapping(url, output_dir, threads, delay, headers, user_agents, crawl_depth, login_creds, proxy, "characters", [selections, chars], timeout)
                    if char_data:
                        save_json(char_data, f"{output_dir}/characters.json")
                        table_data = [
                            {
                                "Type": f["type"],
                                "Details": str(f["details"])[:50] + "..." if len(str(f["details"])) > 50 else str(f["details"]),
                                "Allowed": f.get("allowed", False),
                                "Vulnerable": f.get("vulnerable", "")
                            } for f in char_data.get('chars', [])]
                        display_table("Characters", table_data, ["Type", "Details", "Allowed", "Vulnerable"])
                        print(colored("[*] Special character check completed", "green"))
                    else:
                        retry = input(colored("[*] Retry characters phase? (y/n): ", "cyan")).strip().lower()
                        if retry == 'y':
                            continue
                        char_data = {}
                except Exception as e:
                    print(colored(f"[!] Special character error: {e}", "red"))
                    logging.error(f"Character error: {str(e)}", extra={"context": {"url": url}})
                    char_data = {}

        print(colored(f"[*] Triad execution completed in {time.time() - start_time:.2f} seconds! Happy hunting!", "green"))
        retry = input(colored("[*] Run another scan? (y/n): ", "cyan")).strip().lower()
        if retry != 'y':
            break

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(colored("\n[!] Hunt interrupted by user.", "red"))
        exit(0)
    except Exception as e:
        print(colored(f"[!] Fatal error: {e}", "red"))
        logging.error(f"Fatal error: {str(e)}", extra={"context": {}})
        exit(1)