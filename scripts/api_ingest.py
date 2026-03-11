import sqlite3
import requests
import time
import os
import hashlib
from dotenv import load_dotenv

load_dotenv()

DB_PATH = "data/threat_intel.db"


class ThreatIntelAPI:

    def __init__(self):
        self.virustotal_key = os.getenv("VIRUSTOTAL_API_KEY")
        self.abuseipdb_key = os.getenv("ABUSEIPDB_API_KEY")
        self.otx_key = os.getenv("ALIENVAULT_OTX_KEY")

    def fetch_virustotal_ip(self, ip):
        if not self.virustotal_key:
            return self._mock_vt_ip(ip)

        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": self.virustotal_key}

        try:
            r = requests.get(url, headers=headers, timeout=10)
            if r.status_code == 200:
                data = r.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                score = min(100, (malicious + suspicious) * 10)
                country = data.get("data", {}).get("attributes", {}).get("country", "Unknown")
                return {"score": score, "country": country}
        except Exception as e:
            print(f"VirusTotal IP error: {e}")

        return self._mock_vt_ip(ip)

    def fetch_virustotal_domain(self, domain):
        if not self.virustotal_key:
            return self._mock_vt_domain(domain)

        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {"x-apikey": self.virustotal_key}

        try:
            r = requests.get(url, headers=headers, timeout=10)
            if r.status_code == 200:
                data = r.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                score = min(100, (malicious + suspicious) * 10)
                return {"score": score}
        except Exception as e:
            print(f"VirusTotal domain error: {e}")

        return self._mock_vt_domain(domain)

    def fetch_virustotal_hash(self, file_hash):
        if not self.virustotal_key:
            return self._mock_vt_hash(file_hash)

        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": self.virustotal_key}

        try:
            r = requests.get(url, headers=headers, timeout=10)
            if r.status_code == 200:
                data = r.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                score = min(100, (malicious + suspicious) * 5)
                return {"score": score}
        except Exception as e:
            print(f"VirusTotal hash error: {e}")

        return self._mock_vt_hash(file_hash)

    def fetch_virustotal_url(self, url_to_check):
        if not self.virustotal_key:
            return self._mock_vt_url(url_to_check)

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
                score = min(100, (malicious + suspicious) * 10)
                return {"score": score}
        except Exception as e:
            print(f"VirusTotal URL error: {e}")

        return self._mock_vt_url(url_to_check)

    def fetch_abuseipdb(self, ip):
        if not self.abuseipdb_key:
            return self._mock_abuseipdb(ip)

        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": self.abuseipdb_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90}

        try:
            r = requests.get(url, headers=headers, params=params, timeout=10)
            if r.status_code == 200:
                data = r.json()["data"]
                return {
                    "score": data["abuseConfidenceScore"],
                    "country": data["countryCode"]
                }
        except Exception as e:
            print(f"AbuseIPDB error: {e}")

        return self._mock_abuseipdb(ip)

    def fetch_otx_ip(self, ip):
        if not self.otx_key:
            return self._mock_otx(ip)

        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
        headers = {"X-OTX-API-KEY": self.otx_key}

        try:
            r = requests.get(url, headers=headers, timeout=10)
            if r.status_code == 200:
                data = r.json()
                pulse_count = data.get("pulse_info", {}).get("count", 0)
                score = min(100, pulse_count * 20)
                return {"score": score}
        except Exception as e:
            print(f"OTX error: {e}")

        return self._mock_otx(ip)

    def _mock_vt_ip(self, ip):
        import random
        return {"score": random.randint(0, 100), "country": random.choice(["US", "RU", "CN", "Unknown"])}

    def _mock_vt_domain(self, domain):
        import random
        return {"score": random.randint(20, 95)}

    def _mock_vt_hash(self, file_hash):
        import random
        return {"score": random.randint(30, 100)}

    def _mock_vt_url(self, url):
        import random
        return {"score": random.randint(10, 90)}

    def _mock_abuseipdb(self, ip):
        import random
        return {"score": random.randint(0, 100), "country": random.choice(["US", "RU", "CN", "Unknown"])}

    def _mock_otx(self, ip):
        import random
        return {"score": random.randint(0, 80)}


class ThreatIngestor:

    def __init__(self):
        self.api = ThreatIntelAPI()
        self.conn = sqlite3.connect(DB_PATH)
        self.cursor = self.conn.cursor()

    def close(self):
        if self.conn:
            self.conn.close()

    def classify_risk(self, score):
        if score >= 80:
            return "High"
        elif score >= 50:
            return "Medium"
        return "Low"

    def get_threat_category(self, indicator_type, risk_level):
        categories = {
            'High': ['Malware C2', 'Phishing', 'Malicious Activity', 'Malware Distribution'],
            'Medium': ['Proxy/VPN', 'Suspicious Activity', 'Scanner'],
            'Low': ['Safe', 'Clean', 'Legitimate']
        }
        import random
        return random.choice(categories.get(risk_level, ['Unknown']))

    def map_to_mitre(self, indicator, indicator_type, threat_category, risk_level):
        mitre_mappings = {
            'Malware C2': ('Command and Control', 'Execution'),
            'Phishing': ('Initial Access', 'Initial Access'),
            'Malicious Activity': ('Execution', 'Execution'),
            'Proxy/VPN': ('Command and Control', 'Command and Control'),
            'Suspicious Activity': ('Discovery', 'Discovery'),
            'Malware Distribution': ('Initial Access', 'Execution')
        }

        technique, tactic = mitre_mappings.get(threat_category, ('Unknown', 'Unknown'))

        self.cursor.execute("""
            INSERT OR REPLACE INTO mitre_mapping
            (indicator, type, mitre_technique, mitre_tactic, risk_level, confidence)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (indicator, indicator_type, technique, tactic, risk_level, 0.85))

    def ingest_ip_addresses(self, ip_list):
        results = []

        for ip in ip_list:
            try:
                vt_data = self.api.fetch_virustotal_ip(ip)
                abuse_data = self.api.fetch_abuseipdb(ip)
                otx_data = self.api.fetch_otx_ip(ip)

                avg_score = (vt_data["score"] + abuse_data["score"] + otx_data["score"]) / 3
                score = int(avg_score)
                country = abuse_data.get("country", vt_data.get("country", "Unknown"))
                risk = self.classify_risk(score)
                threat_category = self.get_threat_category('IP', risk)

                self.cursor.execute("""
                INSERT OR IGNORE INTO indicators
                (indicator, type, source, reputation_score)
                VALUES (?, ?, ?, ?)
                """, (ip, "IP", "Multi-Source", score))

                self.cursor.execute(
                    "SELECT id FROM indicators WHERE indicator=?",
                    (ip,)
                )

                row = self.cursor.fetchone()
                if not row:
                    continue

                indicator_id = row[0]

                self.cursor.execute("""
                INSERT OR REPLACE INTO enriched_indicators
                (indicator_id, indicator, type, country, reputation_score, threat_category, is_malicious)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (indicator_id, ip, "IP", country, score, threat_category, 1 if risk == 'High' else 0))

                self.cursor.execute("""
                INSERT OR REPLACE INTO risk_scores
                (indicator_id, indicator, type, risk_score, risk_level, threat_category, country)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (indicator_id, ip, "IP", score, risk, threat_category, country))

                self.map_to_mitre(ip, "IP", threat_category, risk)

                results.append({
                    'indicator': ip,
                    'type': 'IP',
                    'risk_level': risk,
                    'risk_score': score
                })

            except Exception as e:
                print(f"Error processing IP {ip}: {e}")
                continue

        self.conn.commit()
        return results

    def ingest_domains(self, domain_list):
        results = []

        for domain in domain_list:
            try:
                vt_data = self.api.fetch_virustotal_domain(domain)
                score = vt_data["score"]
                risk = self.classify_risk(score)
                threat_category = self.get_threat_category('domain', risk)
                country = "Unknown"

                self.cursor.execute("""
                INSERT OR IGNORE INTO indicators
                (indicator, type, source, reputation_score)
                VALUES (?, ?, ?, ?)
                """, (domain, "domain", "VirusTotal", score))

                self.cursor.execute(
                    "SELECT id FROM indicators WHERE indicator=?",
                    (domain,)
                )

                row = self.cursor.fetchone()
                if not row:
                    continue

                indicator_id = row[0]

                self.cursor.execute("""
                INSERT OR REPLACE INTO enriched_indicators
                (indicator_id, indicator, type, country, reputation_score, threat_category, is_malicious)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (indicator_id, domain, "domain", country, score, threat_category, 1 if risk == 'High' else 0))

                self.cursor.execute("""
                INSERT OR REPLACE INTO risk_scores
                (indicator_id, indicator, type, risk_score, risk_level, threat_category, country)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (indicator_id, domain, "domain", score, risk, threat_category, country))

                self.map_to_mitre(domain, "domain", threat_category, risk)

                results.append({
                    'indicator': domain,
                    'type': 'domain',
                    'risk_level': risk,
                    'risk_score': score
                })

            except Exception as e:
                print(f"Error processing domain {domain}: {e}")
                continue

        self.conn.commit()
        return results

    def ingest_file_hashes(self, hash_list):
        results = []

        for file_hash in hash_list:
            try:
                vt_data = self.api.fetch_virustotal_hash(file_hash)
                score = vt_data["score"]
                risk = self.classify_risk(score)
                threat_category = self.get_threat_category('hash', risk)
                country = "Unknown"

                self.cursor.execute("""
                INSERT OR IGNORE INTO indicators
                (indicator, type, source, reputation_score)
                VALUES (?, ?, ?, ?)
                """, (file_hash, "hash", "VirusTotal", score))

                self.cursor.execute(
                    "SELECT id FROM indicators WHERE indicator=?",
                    (file_hash,)
                )

                row = self.cursor.fetchone()
                if not row:
                    continue

                indicator_id = row[0]

                self.cursor.execute("""
                INSERT OR REPLACE INTO enriched_indicators
                (indicator_id, indicator, type, country, reputation_score, threat_category, is_malicious)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (indicator_id, file_hash, "hash", country, score, threat_category, 1 if risk == 'High' else 0))

                self.cursor.execute("""
                INSERT OR REPLACE INTO risk_scores
                (indicator_id, indicator, type, risk_score, risk_level, threat_category, country)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (indicator_id, file_hash, "hash", score, risk, threat_category, country))

                self.map_to_mitre(file_hash, "hash", threat_category, risk)

                results.append({
                    'indicator': file_hash,
                    'type': 'hash',
                    'risk_level': risk,
                    'risk_score': score
                })

            except Exception as e:
                print(f"Error processing hash {file_hash}: {e}")
                continue

        self.conn.commit()
        return results

    def ingest_urls(self, url_list):
        results = []

        for url in url_list:
            try:
                vt_data = self.api.fetch_virustotal_url(url)
                score = vt_data["score"]
                risk = self.classify_risk(score)
                threat_category = self.get_threat_category('url', risk)
                country = "Unknown"

                self.cursor.execute("""
                INSERT OR IGNORE INTO indicators
                (indicator, type, source, reputation_score)
                VALUES (?, ?, ?, ?)
                """, (url, "url", "VirusTotal", score))

                self.cursor.execute(
                    "SELECT id FROM indicators WHERE indicator=?",
                    (url,)
                )

                row = self.cursor.fetchone()
                if not row:
                    continue

                indicator_id = row[0]

                self.cursor.execute("""
                INSERT OR REPLACE INTO enriched_indicators
                (indicator_id, indicator, type, country, reputation_score, threat_category, is_malicious)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (indicator_id, url, "url", country, score, threat_category, 1 if risk == 'High' else 0))

                self.cursor.execute("""
                INSERT OR REPLACE INTO risk_scores
                (indicator_id, indicator, type, risk_score, risk_level, threat_category, country)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (indicator_id, url, "url", score, risk, threat_category, country))

                self.map_to_mitre(url, "url", threat_category, risk)

                results.append({
                    'indicator': url,
                    'type': 'url',
                    'risk_level': risk,
                    'risk_score': score
                })

            except Exception as e:
                print(f"Error processing URL {url}: {e}")
                continue

        self.conn.commit()
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
