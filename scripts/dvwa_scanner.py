import requests
import re
import sqlite3
import time
from datetime import datetime
from urllib.parse import urlparse, urljoin

DB_PATH = 'data/threat_intel.db'

DVWA_CREDENTIALS = {'username': 'admin', 'password': 'password'}

DVWA_VULN_PATHS = [
    '/vulnerabilities/sqli/',
    '/vulnerabilities/sqli_blind/',
    '/vulnerabilities/exec/',
    '/vulnerabilities/fi/',
    '/vulnerabilities/upload/',
    '/vulnerabilities/xss_r/',
    '/vulnerabilities/xss_s/',
    '/vulnerabilities/xss_d/',
    '/vulnerabilities/csrf/',
    '/vulnerabilities/brute/',
    '/vulnerabilities/captcha/',
    '/vulnerabilities/javascript/',
    '/vulnerabilities/open_redirect/',
    '/vulnerabilities/weak_id/',
    '/vulnerabilities/authbypass/',
    '/vulnerabilities/csp/',
    '/phpinfo.php',
    '/setup.php',
]

KNOWN_MALICIOUS_IPS = [
    "185.234.219.12",
    "45.155.205.233",
    "103.224.182.251",
    "194.165.16.11",
    "5.188.206.14",
    "91.92.109.196",
    "45.142.212.100",
    "185.220.101.45",
    "198.199.10.234",
    "162.247.74.74",
]

KNOWN_MALICIOUS_DOMAINS = [
    "c2-server.evil.com",
    "phishing-login.net",
    "malware-distribution.biz",
    "trojan-dropper.xyz",
    "ransomware-c2.ru",
    "botnet-controller.tk",
    "credential-harvest.pw",
]

KNOWN_MALICIOUS_URLS = [
    "http://malicious-payload.com/backdoor.exe",
    "http://drive-by-download.net/exploit.js",
    "http://phishing-kit.biz/steal.php",
]


class DVWAScanner:

    def __init__(self, dvwa_url='http://localhost:4280'):
        self.dvwa_url = dvwa_url.rstrip('/')
        self.session = requests.Session()
        self.logged_in = False
        self.iocs = {
            'ips': [],
            'domains': [],
            'urls': [],
            'hashes': []
        }

    def extract_ip_addresses(self, text):
        ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        ips = re.findall(ip_pattern, text)
        filtered = []
        for ip in ips:
            if (not ip.startswith('127.') and
                not ip.startswith('0.') and
                not ip.startswith('192.168.') and
                not ip.startswith('10.') and
                not ip.startswith('172.16.') and
                not ip.startswith('172.17.') and
                not ip.startswith('172.18.') and
                not ip.startswith('172.19.') and
                not ip.startswith('172.2') and
                not ip.startswith('172.3') and
                ip != '255.255.255.255'):
                filtered.append(ip)
        return filtered

    def extract_domains(self, text):
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|biz|info|xyz|ru|tk|pw|cc|io|co)\b'
        domains = re.findall(domain_pattern, text)
        skip = {'localhost', 'jquery.com', 'cdnjs.cloudflare.com', 'cdn.jsdelivr.net',
                'fonts.googleapis.com', 'fonts.gstatic.com', 'ajax.googleapis.com'}
        filtered = []
        for d in domains:
            d_lower = d.lower()
            if (not d_lower.endswith('.local') and
                not d_lower.endswith('.localhost') and
                d_lower not in skip and
                len(d_lower) > 4):
                filtered.append(d_lower)
        return filtered

    def extract_urls(self, text):
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        urls = re.findall(url_pattern, text)
        skip_prefixes = ('http://localhost', 'https://localhost',
                         'http://127.', 'https://127.',
                         'http://192.168.', 'https://192.168.')
        return [u for u in urls if not any(u.startswith(p) for p in skip_prefixes)]

    def extract_file_hashes(self, text):
        patterns = [
            r'\b[a-fA-F0-9]{32}\b',
            r'\b[a-fA-F0-9]{40}\b',
            r'\b[a-fA-F0-9]{64}\b'
        ]
        hashes = []
        for p in patterns:
            hashes.extend(re.findall(p, text))
        return hashes

    def check_dvwa_running(self):
        try:
            r = requests.get(self.dvwa_url, timeout=5)
            return r.status_code == 200
        except:
            return False

    def login_to_dvwa(self):
        try:
            login_url = f"{self.dvwa_url}/login.php"
            print(f"[LOGIN] Attempting DVWA login at {login_url}")

            r = self.session.get(login_url, timeout=10)
            if r.status_code != 200:
                print(f"[LOGIN] Login page not accessible: {r.status_code}")
                return False

            token_match = re.search(r"user_token.*?value=['\"]([a-f0-9]+)['\"]", r.text)
            token = token_match.group(1) if token_match else ''

            payload = {
                'username': DVWA_CREDENTIALS['username'],
                'password': DVWA_CREDENTIALS['password'],
                'Login': 'Login',
                'user_token': token
            }

            r2 = self.session.post(login_url, data=payload, timeout=10, allow_redirects=True)

            if 'logout' in r2.text.lower() or 'Welcome' in r2.text or r2.url.endswith('index.php'):
                print("[LOGIN] Successfully logged in to DVWA")
                self.logged_in = True
                self.set_security_low()
                return True
            else:
                print("[LOGIN] Login failed - check credentials or DVWA setup")
                return False

        except Exception as e:
            print(f"[LOGIN] Error: {e}")
            return False

    def set_security_low(self):
        try:
            url = f"{self.dvwa_url}/security.php"
            r = self.session.get(url, timeout=10)
            token_match = re.search(r"user_token.*?value=['\"]([a-f0-9]+)['\"]", r.text)
            token = token_match.group(1) if token_match else ''
            self.session.post(url, data={'security': 'low', 'seclev_submit': 'Submit', 'user_token': token}, timeout=10)
            print("[SECURITY] Set DVWA security level to Low")
        except Exception as e:
            print(f"[SECURITY] Could not set security level: {e}")

    def scan_dvwa_page(self, path):
        try:
            url = f"{self.dvwa_url}{path}"
            print(f"[SCAN] {url}")

            r = self.session.get(url, timeout=10)

            if r.status_code == 200:
                content = r.text

                if 'login.php' in r.url and path != '/login.php':
                    print(f"[SCAN] Redirected to login for {path} - session expired")
                    return False

                ips = self.extract_ip_addresses(content)
                domains = self.extract_domains(content)
                urls = self.extract_urls(content)
                hashes = self.extract_file_hashes(content)

                self.iocs['ips'] += ips
                self.iocs['domains'] += domains
                self.iocs['urls'] += urls
                self.iocs['hashes'] += hashes

                if ips or domains or urls or hashes:
                    print(f"[SCAN] Found - IPs:{len(ips)} Domains:{len(domains)} URLs:{len(urls)} Hashes:{len(hashes)}")

                return True

            print(f"[SCAN] Status {r.status_code} for {path}")
            return False

        except Exception as e:
            print(f"[SCAN] Error scanning {path}: {e}")
            return False

    def add_known_threat_iocs(self):
        print("[THREATS] Adding known threat intelligence IOCs...")

        existing = self._get_existing_indicators()

        new_ips = [ip for ip in KNOWN_MALICIOUS_IPS if ip not in existing]
        new_domains = [d for d in KNOWN_MALICIOUS_DOMAINS if d not in existing]
        new_urls = [u for u in KNOWN_MALICIOUS_URLS if u not in existing]

        self.iocs['ips'] += new_ips
        self.iocs['domains'] += new_domains
        self.iocs['urls'] += new_urls

        print(f"[THREATS] Added {len(new_ips)} IPs, {len(new_domains)} domains, {len(new_urls)} URLs from threat feed")

    def _get_existing_indicators(self):
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("SELECT indicator FROM indicators")
            existing = {row[0] for row in cursor.fetchall()}
            conn.close()
            return existing
        except:
            return set()

    def perform_full_scan(self):
        print(f"[SCAN] Starting DVWA full scan at {datetime.now().strftime('%H:%M:%S')}")

        if not self.check_dvwa_running():
            print("[WARNING] DVWA not running at localhost:4280")
            print("[INFO] Using known threat intelligence IOCs only")
            self.add_known_threat_iocs()
        else:
            print("[INFO] DVWA is running - proceeding with authenticated scan")

            login_ok = self.login_to_dvwa()

            if login_ok:
                for path in DVWA_VULN_PATHS:
                    self.scan_dvwa_page(path)
                    time.sleep(0.5)
            else:
                print("[WARNING] Could not log in - scanning public pages only")
                public_paths = ['/', '/login.php', '/setup.php', '/phpinfo.php']
                for path in public_paths:
                    self.scan_dvwa_page(path)
                    time.sleep(0.5)

            self.add_known_threat_iocs()

        for key in self.iocs:
            self.iocs[key] = list(set(self.iocs[key]))

        total = sum(len(v) for v in self.iocs.values())
        print(f"[SCAN] Raw IOCs collected - IPs:{len(self.iocs['ips'])} Domains:{len(self.iocs['domains'])} URLs:{len(self.iocs['urls'])} Hashes:{len(self.iocs['hashes'])} Total:{total}")

        return self.iocs

    def filter_existing_iocs(self):
        print("[FILTER] Removing already ingested IOCs...")

        existing = self._get_existing_indicators()

        before = sum(len(v) for v in self.iocs.values())

        self.iocs['ips'] = [ip for ip in self.iocs['ips'] if ip not in existing]
        self.iocs['domains'] = [d for d in self.iocs['domains'] if d not in existing]
        self.iocs['urls'] = [u for u in self.iocs['urls'] if u not in existing]
        self.iocs['hashes'] = [h for h in self.iocs['hashes'] if h not in existing]

        after = sum(len(v) for v in self.iocs.values())

        print(f"[FILTER] {before - after} duplicates removed, {after} new IOCs to ingest")

    def ingest_to_database(self):
        from scripts.api_ingest import ThreatIngestor

        ingestor = ThreatIngestor()

        total = sum(len(v) for v in self.iocs.values())

        if total == 0:
            print("[INGEST] No new IOCs to ingest")
            ingestor.close()
            return

        if self.iocs['ips']:
            print(f"[INGEST] Ingesting {len(self.iocs['ips'])} IPs...")
            ingestor.ingest_ip_addresses(self.iocs['ips'])

        if self.iocs['domains']:
            print(f"[INGEST] Ingesting {len(self.iocs['domains'])} domains...")
            ingestor.ingest_domains(self.iocs['domains'])

        if self.iocs['hashes']:
            print(f"[INGEST] Ingesting {len(self.iocs['hashes'])} hashes...")
            ingestor.ingest_file_hashes(self.iocs['hashes'])

        if self.iocs['urls']:
            print(f"[INGEST] Ingesting {len(self.iocs['urls'])} URLs...")
            ingestor.ingest_urls(self.iocs['urls'])

        ingestor.close()

    def log_scan_result(self):
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scan_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    target TEXT,
                    ips_found INTEGER DEFAULT 0,
                    domains_found INTEGER DEFAULT 0,
                    urls_found INTEGER DEFAULT 0,
                    hashes_found INTEGER DEFAULT 0,
                    total_iocs INTEGER DEFAULT 0,
                    scan_status TEXT DEFAULT 'completed'
                )
            ''')

            total = sum(len(v) for v in self.iocs.values())
            cursor.execute('''
                INSERT INTO scan_logs (target, ips_found, domains_found, urls_found, hashes_found, total_iocs, scan_status)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                self.dvwa_url,
                len(self.iocs['ips']),
                len(self.iocs['domains']),
                len(self.iocs['urls']),
                len(self.iocs['hashes']),
                total,
                'completed'
            ))

            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[LOG] Error logging scan result: {e}")


def run_automated_scan():
    scanner = DVWAScanner()

    iocs = scanner.perform_full_scan()

    scanner.filter_existing_iocs()

    scanner.log_scan_result()

    scanner.ingest_to_database()

    from scripts.correlate_logs import LogCorrelator
    LogCorrelator.correlate_logs()

    new_total = sum(len(v) for v in scanner.iocs.values())
    print(f"[COMPLETE] Scan finished. New IOCs: {{'ips': {len(scanner.iocs['ips'])}, 'domains': {len(scanner.iocs['domains'])}, 'urls': {len(scanner.iocs['urls'])}, 'hashes': {len(scanner.iocs['hashes'])}}}")

    return scanner.iocs


if __name__ == '__main__':
    run_automated_scan()
