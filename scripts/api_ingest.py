import sqlite3
import requests
import re
import time
import os
from dotenv import load_dotenv

load_dotenv()

DB_PATH = "data/threat_intel.db"

MITRE_MAPPINGS = {
    'Malware C2': ('T1071 - Application Layer Protocol', 'Command and Control'),
    'Phishing': ('T1566 - Phishing', 'Initial Access'),
    'Malicious Activity': ('T1059 - Command and Scripting Interpreter', 'Execution'),
    'Proxy/VPN': ('T1090 - Proxy', 'Command and Control'),
    'Suspicious Activity': ('T1046 - Network Service Discovery', 'Discovery'),
    'Malware Distribution': ('T1105 - Ingress Tool Transfer', 'Initial Access'),
    'Scanner': ('T1595 - Active Scanning', 'Reconnaissance'),
    'Botnet': ('T1583 - Acquire Infrastructure', 'Resource Development'),
    'Ransomware': ('T1486 - Data Encrypted for Impact', 'Impact'),
    'Credential Theft': ('T1110 - Brute Force', 'Credential Access'),
    'Safe': ('T1040 - Network Sniffing', 'Discovery'),
    'Clean': ('T1040 - Network Sniffing', 'Discovery'),
    'Legitimate': ('T1040 - Network Sniffing', 'Discovery'),
}

THREAT_CATEGORIES_BY_TYPE = {
    'IP': {
        'High': ['Malware C2', 'Botnet', 'Malicious Activity'],
        'Medium': ['Proxy/VPN', 'Scanner', 'Suspicious Activity'],
        'Low': ['Safe', 'Legitimate'],
    },
    'domain': {
        'High': ['Phishing', 'Malware Distribution', 'Malware C2'],
        'Medium': ['Suspicious Activity', 'Scanner'],
        'Low': ['Safe', 'Legitimate'],
    },
    'hash': {
        'High': ['Malware Distribution', 'Ransomware', 'Malicious Activity'],
        'Medium': ['Suspicious Activity'],
        'Low': ['Safe', 'Clean'],
    },
    'url': {
        'High': ['Phishing', 'Malware Distribution', 'Credential Theft'],
        'Medium': ['Suspicious Activity', 'Scanner'],
        'Low': ['Safe', 'Legitimate'],
    },
}

IP_RE = re.compile(
    r'^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$'
)
DOMAIN_RE = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
)
MD5_RE = re.compile(r'^[a-fA-F0-9]{32}$')
SHA1_RE = re.compile(r'^[a-fA-F0-9]{40}$')
SHA256_RE = re.compile(r'^[a-fA-F0-9]{64}$')
URL_RE = re.compile(r'^https?://.+')


def validate_ip(ip: str) -> bool:
    return bool(IP_RE.match(ip.strip()))


def validate_domain(domain: str) -> bool:
    return bool(DOMAIN_RE.match(domain.strip()))


def validate_hash(h: str) -> bool:
    h = h.strip()
    return bool(MD5_RE.match(h) or SHA1_RE.match(h) or SHA256_RE.match(h))


def validate_url(url: str) -> bool:
    return bool(URL_RE.match(url.strip()))


class ThreatIntelAPI:

    def __init__(self):
        self.virustotal_key = os.getenv("VIRUSTOTAL_API_KEY")
        self.abuseipdb_key = os.getenv("ABUSEIPDB_API_KEY")
        self.otx_key = os.getenv("ALIENVAULT_OTX_KEY")

        print("[API_INIT]", "="*60)
        print(f"[API_INIT] VirusTotal Key Loaded: {bool(self.virustotal_key)}")
        print(f"[API_INIT] AbuseIPDB Key Loaded: {bool(self.abuseipdb_key)}")
        print(f"[API_INIT] OTX Key Loaded: {bool(self.otx_key)}")
        print("[API_INIT]", "="*60)

    def fetch_virustotal_ip(self, ip):
        if not self.virustotal_key:
            return {"score": 0, "country": "Unknown"}

        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": self.virustotal_key}

        try:
            r = requests.get(url, headers=headers, timeout=10)
            if r.status_code == 200:
                data = r.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                score = min(100, (malicious * 8) + (suspicious * 4))
                country = data.get("data", {}).get("attributes", {}).get("country", "Unknown")
                return {"score": score, "country": country}
            return {"score": 0, "country": "Unknown"}
        except Exception as e:
            print(f"[VT_IP] EXCEPTION: {e}")
            return {"score": 0, "country": "Unknown"}

    def fetch_virustotal_domain(self, domain):
        if not self.virustotal_key:
            return {"score": 0}

        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {"x-apikey": self.virustotal_key}

        try:
            r = requests.get(url, headers=headers, timeout=10)
            if r.status_code == 200:
                data = r.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                score = min(100, (malicious * 8) + (suspicious * 4))
                return {"score": score}
            return {"score": 0}
        except Exception as e:
            print(f"[VT_DOMAIN] EXCEPTION: {e}")
            return {"score": 0}

    def fetch_virustotal_hash(self, file_hash):
        if not self.virustotal_key:
            return {"score": 0, "not_found": False}

        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": self.virustotal_key}

        try:
            r = requests.get(url, headers=headers, timeout=10)
            if r.status_code == 200:
                data = r.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                score = min(100, (malicious * 8) + (suspicious * 4))
                return {"score": score, "not_found": False}
            elif r.status_code == 404:
                print(f"[VT_HASH] NOT FOUND (404) - storing with score 0: {file_hash[:16]}...")
                return {"score": 0, "not_found": True}
            return {"score": 0, "not_found": False}
        except Exception as e:
            print(f"[VT_HASH] EXCEPTION: {e}")
            return {"score": 0, "not_found": False}

    def fetch_virustotal_url(self, url_to_check):
        if not self.virustotal_key:
            return {"score": 0}

        import base64
        url_id = base64.urlsafe_b64encode(url_to_check.encode()).decode().strip("=")
        url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {"x-apikey": self.virustotal_key}

        try:
            r = requests.get(url, headers=headers, timeout=10)
            if r.status_code == 200:
                data = r.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                score = min(100, (malicious * 8) + (suspicious * 4))
                return {"score": score}
            return {"score": 0}
        except Exception as e:
            print(f"[VT_URL] EXCEPTION: {e}")
            return {"score": 0}

    def fetch_abuseipdb(self, ip):
        if not self.abuseipdb_key:
            return {"score": 0, "country": "Unknown"}

        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": self.abuseipdb_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90}

        try:
            r = requests.get(url, headers=headers, params=params, timeout=10)
            if r.status_code == 200:
                data = r.json()["data"]
                return {"score": data["abuseConfidenceScore"], "country": data["countryCode"]}
            return {"score": 0, "country": "Unknown"}
        except Exception as e:
            print(f"[ABUSEIPDB] EXCEPTION: {e}")
            return {"score": 0, "country": "Unknown"}

    def fetch_otx_ip(self, ip):
        if not self.otx_key:
            return {"score": 0}

        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
        headers = {"X-OTX-API-KEY": self.otx_key}

        try:
            r = requests.get(url, headers=headers, timeout=10)
            if r.status_code == 200:
                data = r.json()
                pulse_count = data.get("pulse_info", {}).get("count", 0)
                score = min(100, pulse_count * 20)
                return {"score": score}
            return {"score": 0}
        except Exception as e:
            print(f"[OTX] EXCEPTION: {e}")
            return {"score": 0}


def _get_threat_category(indicator_type: str, risk_level: str, indicator: str) -> str:
    cats = THREAT_CATEGORIES_BY_TYPE.get(indicator_type, THREAT_CATEGORIES_BY_TYPE['IP'])
    options = cats.get(risk_level, cats.get('Low', ['Unknown']))
    idx = hash(indicator) % len(options)
    return options[idx]


def _get_mitre(threat_category: str):
    return MITRE_MAPPINGS.get(threat_category, ('T1071 - Application Layer Protocol', 'Command and Control'))


class ThreatIngestor:

    def __init__(self):
        self.api = ThreatIntelAPI()
        self.conn = sqlite3.connect(DB_PATH)
        self.cursor = self.conn.cursor()

    def close(self):
        if self.conn:
            self.conn.close()

    def classify_risk(self, score: float) -> str:
        if score >= 80:
            return "High"
        elif score >= 50:
            return "Medium"
        return "Low"

    def map_to_mitre(self, indicator, indicator_type, threat_category, risk_level):
        technique, tactic = _get_mitre(threat_category)
        self.cursor.execute("""
            INSERT OR REPLACE INTO mitre_mapping
            (indicator, type, mitre_technique, mitre_tactic, risk_level, confidence)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (indicator, indicator_type, technique, tactic, risk_level, 0.85))

    def _upsert_indicator(self, indicator, itype, source, score):
        self.cursor.execute("""
            INSERT INTO indicators (indicator, type, source, reputation_score)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(indicator) DO UPDATE SET
                reputation_score = excluded.reputation_score,
                source = excluded.source
        """, (indicator, itype, source, score))
        self.cursor.execute("SELECT id FROM indicators WHERE indicator=?", (indicator,))
        row = self.cursor.fetchone()
        return row[0] if row else None

    def _upsert_enriched(self, indicator_id, indicator, itype, country, score, threat_category):
        self.cursor.execute("""
            INSERT INTO enriched_indicators
                (indicator_id, indicator, type, country, reputation_score, threat_category, is_malicious)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(indicator) DO UPDATE SET
                country = excluded.country,
                reputation_score = excluded.reputation_score,
                threat_category = excluded.threat_category,
                is_malicious = excluded.is_malicious
        """, (indicator_id, indicator, itype, country, score, threat_category,
              1 if self.classify_risk(score) == 'High' else 0))

    def _upsert_risk_score(self, indicator_id, indicator, itype, score, risk, threat_category, country):
        self.cursor.execute("""
            INSERT INTO risk_scores
                (indicator_id, indicator, type, risk_score, risk_level, threat_category, country)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(indicator) DO UPDATE SET
                risk_score = excluded.risk_score,
                risk_level = excluded.risk_level,
                threat_category = excluded.threat_category,
                country = excluded.country
        """, (indicator_id, indicator, itype, score, risk, threat_category, country))

    def ingest_ip_addresses(self, ip_list):
        results = []
        invalid = []
        for ip in ip_list:
            ip = ip.strip()
            if not validate_ip(ip):
                invalid.append(ip)
                continue
            try:
                vt_data = self.api.fetch_virustotal_ip(ip)
                abuse_data = self.api.fetch_abuseipdb(ip)
                otx_data = self.api.fetch_otx_ip(ip)

                scores = [vt_data["score"], abuse_data["score"], otx_data["score"]]
                non_zero = [s for s in scores if s > 0]
                score = int(sum(non_zero) / len(non_zero)) if non_zero else 0
                country = abuse_data.get("country") or vt_data.get("country", "Unknown")
                risk = self.classify_risk(score)
                threat_category = _get_threat_category('IP', risk, ip)

                indicator_id = self._upsert_indicator(ip, "IP", "Multi-Source", score)
                if not indicator_id:
                    continue

                self._upsert_enriched(indicator_id, ip, "IP", country, score, threat_category)
                self._upsert_risk_score(indicator_id, ip, "IP", score, risk, threat_category, country)
                self.map_to_mitre(ip, "IP", threat_category, risk)

                results.append({'indicator': ip, 'type': 'IP', 'risk_level': risk, 'risk_score': score})
            except Exception as e:
                print(f"Error processing IP {ip}: {e}")

        self.conn.commit()
        if invalid:
            print(f"[VALIDATION] Skipped invalid IPs: {invalid}")
        return results

    def ingest_domains(self, domain_list):
        results = []
        invalid = []
        for domain in domain_list:
            domain = domain.strip()
            if not validate_domain(domain):
                invalid.append(domain)
                continue
            try:
                vt_data = self.api.fetch_virustotal_domain(domain)
                score = vt_data["score"]
                risk = self.classify_risk(score)
                threat_category = _get_threat_category('domain', risk, domain)
                country = "Unknown"

                indicator_id = self._upsert_indicator(domain, "domain", "VirusTotal", score)
                if not indicator_id:
                    continue

                self._upsert_enriched(indicator_id, domain, "domain", country, score, threat_category)
                self._upsert_risk_score(indicator_id, domain, "domain", score, risk, threat_category, country)
                self.map_to_mitre(domain, "domain", threat_category, risk)

                results.append({'indicator': domain, 'type': 'domain', 'risk_level': risk, 'risk_score': score})
            except Exception as e:
                print(f"Error processing domain {domain}: {e}")

        self.conn.commit()
        if invalid:
            print(f"[VALIDATION] Skipped invalid domains: {invalid}")
        return results

    def ingest_file_hashes(self, hash_list):
        results = []
        invalid = []
        for file_hash in hash_list:
            file_hash = file_hash.strip()
            if not validate_hash(file_hash):
                invalid.append(file_hash)
                continue
            try:
                vt_data = self.api.fetch_virustotal_hash(file_hash)
                score = vt_data["score"]
                risk = self.classify_risk(score)
                threat_category = _get_threat_category('hash', risk, file_hash)
                country = "Unknown"

                indicator_id = self._upsert_indicator(file_hash, "hash", "VirusTotal", score)
                if not indicator_id:
                    continue

                self._upsert_enriched(indicator_id, file_hash, "hash", country, score, threat_category)
                self._upsert_risk_score(indicator_id, file_hash, "hash", score, risk, threat_category, country)
                self.map_to_mitre(file_hash, "hash", threat_category, risk)

                results.append({'indicator': file_hash, 'type': 'hash', 'risk_level': risk, 'risk_score': score})
            except Exception as e:
                print(f"Error processing hash {file_hash}: {e}")

        self.conn.commit()
        if invalid:
            print(f"[VALIDATION] Skipped invalid hashes: {invalid}")
        return results

    def ingest_urls(self, url_list):
        results = []
        invalid = []
        for url in url_list:
            url = url.strip()
            if not validate_url(url):
                invalid.append(url)
                continue
            try:
                vt_data = self.api.fetch_virustotal_url(url)
                score = vt_data["score"]
                risk = self.classify_risk(score)
                threat_category = _get_threat_category('url', risk, url)
                country = "Unknown"

                indicator_id = self._upsert_indicator(url, "url", "VirusTotal", score)
                if not indicator_id:
                    continue

                self._upsert_enriched(indicator_id, url, "url", country, score, threat_category)
                self._upsert_risk_score(indicator_id, url, "url", score, risk, threat_category, country)
                self.map_to_mitre(url, "url", threat_category, risk)

                results.append({'indicator': url, 'type': 'url', 'risk_level': risk, 'risk_score': score})
            except Exception as e:
                print(f"Error processing URL {url}: {e}")

        self.conn.commit()
        if invalid:
            print(f"[VALIDATION] Skipped invalid URLs: {invalid}")
        return results


def ingest_sample_data():
    print("===================================")
    print("THREAT INTELLIGENCE INGESTION")
    print("===================================")

    ingestor = ThreatIngestor()

    ips = [
        "185.234.219.12",
        "45.155.205.233",
        "203.0.113.45",
        "192.0.2.1",
        "8.8.8.8"
    ]

    domains = [
        "malicious-site.com",
        "phishing-domain.net",
        "safe-website.org"
    ]

    print("Ingesting IP addresses...")
    ip_results = ingestor.ingest_ip_addresses(ips)
    print(f"Ingested {len(ip_results)} IP addresses")

    print("Ingesting domains...")
    domain_results = ingestor.ingest_domains(domains)
    print(f"Ingested {len(domain_results)} domains")

    ingestor.close()
    print("Ingestion Complete")


if __name__ == "__main__":
    ingest_sample_data()
