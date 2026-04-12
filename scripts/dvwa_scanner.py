import requests
import re
import sqlite3
import time
from datetime import datetime
from urllib.parse import urlparse
import hashlib

DB_PATH = 'data/threat_intel.db'

class DVWAScanner:

    def __init__(self, dvwa_url='http://localhost:4280'):
        self.dvwa_url = dvwa_url.rstrip('/')
        self.session = requests.Session()
        self.iocs = {
            'ips': [],
            'domains': [],
            'urls': [],
            'hashes': []
        }

    # ---------------- EXTRACTION ---------------- #

    def extract_ip_addresses(self, text):
        ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        ips = re.findall(ip_pattern, text)
        return [ip for ip in ips if not ip.startswith('127.') and not ip.startswith('0.')]

    def extract_domains(self, text):
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        domains = re.findall(domain_pattern, text)
        return [d for d in domains if not d.endswith('.local') and not d.endswith('.localhost')]

    def extract_urls(self, text):
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        return re.findall(url_pattern, text)

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

    # ---------------- SCANNING ---------------- #

    def scan_dvwa_page(self, path='/'):
        try:
            url = f"{self.dvwa_url}{path}"
            print(f"[SCAN] {url}")

            response = self.session.get(url, timeout=10)

            if response.status_code == 200:
                content = response.text

                self.iocs['ips'] += self.extract_ip_addresses(content)
                self.iocs['domains'] += self.extract_domains(content)
                self.iocs['urls'] += self.extract_urls(content)
                self.iocs['hashes'] += self.extract_file_hashes(content)

                return True
            return False

        except Exception as e:
            print(f"[ERROR] {e}")
            return False

    def check_dvwa_running(self):
        try:
            return requests.get(self.dvwa_url, timeout=5).status_code == 200
        except:
            return False

    # ---------------- SIMULATION (FIXED) ---------------- #

    def simulate_attack_traffic(self):
        print("[SIMULATE] Adding simulated IOCs...")

        suspicious_ips = ["185.234.219.12","45.155.205.233","103.224.182.251"]
        malicious_domains = ["c2-server.evil.com","phishing-login.net"]
        malicious_urls = ["http://malicious-payload.com/backdoor.exe"]
        malicious_hashes = ["44d88612fea8a8f36de82e1278abb02f"]

        # ✅ FIX: avoid duplicates in memory
        self.iocs['ips'] += [i for i in suspicious_ips if i not in self.iocs['ips']]
        self.iocs['domains'] += [d for d in malicious_domains if d not in self.iocs['domains']]
        self.iocs['urls'] += [u for u in malicious_urls if u not in self.iocs['urls']]
        self.iocs['hashes'] += [h for h in malicious_hashes if h not in self.iocs['hashes']]

    # ---------------- MAIN SCAN ---------------- #

    def perform_full_scan(self):

        if not self.check_dvwa_running():
            print("[WARNING] DVWA not running → using simulated data")
            self.simulate_attack_traffic()
        else:
            paths = ['/', '/login.php', '/vulnerabilities/sqli/']

            for p in paths:
                self.scan_dvwa_page(p)
                time.sleep(1)

            self.simulate_attack_traffic()

        # remove duplicates (memory level)
        for key in self.iocs:
            self.iocs[key] = list(set(self.iocs[key]))

        return self.iocs

    # ---------------- DATABASE FILTER (NEW CORE FIX) ---------------- #

    def filter_existing_iocs(self):
        print("[FILTER] Removing already ingested IOCs...")

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        def filter_list(ioc_list):
            new = []
            for ioc in ioc_list:
                cursor.execute("SELECT 1 FROM indicators WHERE indicator = ?", (ioc,))
                if not cursor.fetchone():
                    new.append(ioc)
            return new

        before = sum(len(v) for v in self.iocs.values())

        self.iocs['ips'] = filter_list(self.iocs['ips'])
        self.iocs['domains'] = filter_list(self.iocs['domains'])
        self.iocs['urls'] = filter_list(self.iocs['urls'])
        self.iocs['hashes'] = filter_list(self.iocs['hashes'])

        after = sum(len(v) for v in self.iocs.values())

        print(f"[FILTER] {before - after} duplicates removed, {after} new IOCs")

        conn.close()

    # ---------------- INGEST ---------------- #

    def ingest_to_database(self):
        from scripts.api_ingest import ThreatIngestor

        ingestor = ThreatIngestor()

        if self.iocs['ips']:
            ingestor.ingest_ip_addresses(self.iocs['ips'])

        if self.iocs['domains']:
            ingestor.ingest_domains(self.iocs['domains'])

        if self.iocs['hashes']:
            ingestor.ingest_file_hashes(self.iocs['hashes'])

        if self.iocs['urls']:
            ingestor.ingest_urls(self.iocs['urls'])

        ingestor.close()

    # ---------------- RUN ---------------- #

def run_automated_scan():
    scanner = DVWAScanner()

    scanner.perform_full_scan()

    scanner.filter_existing_iocs()

    new_counts = {
        'ips': len(scanner.iocs['ips']),
        'domains': len(scanner.iocs['domains']),
        'urls': len(scanner.iocs['urls']),
        'hashes': len(scanner.iocs['hashes']),
    }

    if any(v > 0 for v in new_counts.values()):
        scanner.ingest_to_database()
    else:
        print("[SKIP] No new IOCs to ingest")

    from scripts.correlate_logs import LogCorrelator
    LogCorrelator.correlate_logs()

    print(f"[COMPLETE] Scan finished. New IOCs: {new_counts}")
    return new_counts

if __name__ == '__main__':
    run_automated_scan()