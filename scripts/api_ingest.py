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

        print("[API_INIT]", "="*60)
        print(f"[API_INIT] VirusTotal Key Loaded: {bool(self.virustotal_key)}")
        print(f"[API_INIT] AbuseIPDB Key Loaded: {bool(self.abuseipdb_key)}")
        print(f"[API_INIT] OTX Key Loaded: {bool(self.otx_key)}")
        print("[API_INIT]", "="*60)

    def fetch_virustotal_ip(self, ip):
        if not self.virustotal_key:
            print(f"[VT_IP] NO API KEY - Skipping {ip}")
            return {"score": 0, "country": "Unknown"}

        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": self.virustotal_key}

        try:
            print(f"[VT_IP] Requesting {ip}...")
            r = requests.get(url, headers=headers, timeout=10)
            print(f"[VT_IP] Status: {r.status_code}")

            if r.status_code == 200:
                data = r.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                score = min(100, (malicious + suspicious) * 10)
                country = data.get("data", {}).get("attributes", {}).get("country", "Unknown")
                print(f"[VT_IP] SUCCESS - Malicious: {malicious}, Suspicious: {suspicious}, Score: {score}, Country: {country}")
                return {"score": score, "country": country}
            else:
                print(f"[VT_IP] ERROR {r.status_code}: {r.text[:200]}")
                return {"score": 0, "country": "Unknown"}
        except Exception as e:
            print(f"[VT_IP] EXCEPTION: {str(e)}")
            return {"score": 0, "country": "Unknown"}

    def fetch_virustotal_domain(self, domain):
        if not self.virustotal_key:
            print(f"[VT_DOMAIN] NO API KEY - Skipping {domain}")
            return {"score": 0}

        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {"x-apikey": self.virustotal_key}

        try:
            print(f"[VT_DOMAIN] Requesting {domain}...")
            r = requests.get(url, headers=headers, timeout=10)
            print(f"[VT_DOMAIN] Status: {r.status_code}")

            if r.status_code == 200:
                data = r.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                score = min(100, (malicious + suspicious) * 10)
                print(f"[VT_DOMAIN] SUCCESS - Malicious: {malicious}, Suspicious: {suspicious}, Score: {score}")
                return {"score": score}
            else:
                print(f"[VT_DOMAIN] ERROR {r.status_code}: {r.text[:200]}")
                return {"score": 0}
        except Exception as e:
            print(f"[VT_DOMAIN] EXCEPTION: {str(e)}")
            return {"score": 0}

    def fetch_virustotal_hash(self, file_hash):
        if not self.virustotal_key:
            print(f"[VT_HASH] NO API KEY - Skipping {file_hash[:16]}...")
            return {"score": 0, "not_found": False}

        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": self.virustotal_key}

        try:
            print(f"[VT_HASH] Requesting {file_hash[:16]}...")
            r = requests.get(url, headers=headers, timeout=10)
            print(f"[VT_HASH] Status: {r.status_code}")

            if r.status_code == 200:
                data = r.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                score = min(100, (malicious + suspicious) * 10)
                print(f"[VT_HASH] SUCCESS - Malicious: {malicious}, Suspicious: {suspicious}, Score: {score}")
                return {"score": score, "not_found": False}
            elif r.status_code == 404:
                print(f"[VT_HASH] NOT FOUND (404) - Hash unknown to VirusTotal: {file_hash[:16]}...")
                return {"score": 0, "not_found": True}
            else:
                print(f"[VT_HASH] ERROR {r.status_code}: {r.text[:200]}")
                return {"score": 0, "not_found": False}
        except Exception as e:
            print(f"[VT_HASH] EXCEPTION: {str(e)}")
            return {"score": 0, "not_found": False}

    def fetch_virustotal_url(self, url_to_check):
        if not self.virustotal_key:
            print(f"[VT_URL] NO API KEY - Skipping {url_to_check[:50]}")
            return {"score": 0}

        import base64
        url_id = base64.urlsafe_b64encode(url_to_check.encode()).decode().strip("=")
        url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {"x-apikey": self.virustotal_key}

        try:
            print(f"[VT_URL] Requesting {url_to_check[:50]}...")
            r = requests.get(url, headers=headers, timeout=10)
            print(f"[VT_URL] Status: {r.status_code}")

            if r.status_code == 200:
                data = r.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                score = min(100, (malicious + suspicious) * 10)
                print(f"[VT_URL] SUCCESS - Malicious: {malicious}, Suspicious: {suspicious}, Score: {score}")
                return {"score": score}
            else:
                print(f"[VT_URL] ERROR {r.status_code}: {r.text[:200]}")
                return {"score": 0}
        except Exception as e:
            print(f"[VT_URL] EXCEPTION: {str(e)}")
            return {"score": 0}

    def fetch_abuseipdb(self, ip):
        if not self.abuseipdb_key:
            print(f"[ABUSEIPDB] NO API KEY - Skipping {ip}")
            return {"score": 0, "country": "Unknown"}

        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": self.abuseipdb_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90}

        try:
            print(f"[ABUSEIPDB] Requesting {ip}...")
            r = requests.get(url, headers=headers, params=params, timeout=10)
            print(f"[ABUSEIPDB] Status: {r.status_code}")

            if r.status_code == 200:
                data = r.json()["data"]
                score = data["abuseConfidenceScore"]
                country = data["countryCode"]
                print(f"[ABUSEIPDB] SUCCESS - Score: {score}, Country: {country}")
                return {"score": score, "country": country}
            else:
                print(f"[ABUSEIPDB] ERROR {r.status_code}: {r.text[:200]}")
                return {"score": 0, "country": "Unknown"}
        except Exception as e:
            print(f"[ABUSEIPDB] EXCEPTION: {str(e)}")
            return {"score": 0, "country": "Unknown"}

    def fetch_otx_ip(self, ip):
        if not self.otx_key:
            print(f"[OTX] NO API KEY - Skipping {ip}")
            return {"score": 0}

        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
        headers = {"X-OTX-API-KEY": self.otx_key}

        try:
            print(f"[OTX] Requesting {ip}...")
            r = requests.get(url, headers=headers, timeout=10)
            print(f"[OTX] Status: {r.status_code}")

            if r.status_code == 200:
                data = r.json()
                pulse_count = data.get("pulse_info", {}).get("count", 0)
                score = min(100, pulse_count * 20)
                print(f"[OTX] SUCCESS - Pulse Count: {pulse_count}, Score: {score}")
                return {"score": score}
            else:
                print(f"[OTX] ERROR {r.status_code}: {r.text[:200]}")
                return {"score": 0}
        except Exception as e:
            print(f"[OTX] EXCEPTION: {str(e)}")
            return {"score": 0}

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

    def _indicator_exists(self, indicator):
        self.cursor.execute("SELECT id FROM indicators WHERE indicator=?", (indicator,))
        row = self.cursor.fetchone()
        return row[0] if row else None

    def _get_existing_result(self, indicator, itype):
        self.cursor.execute(
            "SELECT indicator, type, risk_score, risk_level FROM risk_scores WHERE indicator=?",
            (indicator,)
        )
        row = self.cursor.fetchone()
        if row:
            return {'indicator': row[0], 'type': row[1], 'risk_score': row[2], 'risk_level': row[3]}
        return {'indicator': indicator, 'type': itype, 'risk_score': 0, 'risk_level': 'Unknown'}

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
                    "UPDATE indicators SET reputation_score=? WHERE indicator=?",
                    (score, ip)
                )

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
                existing_id = self._indicator_exists(domain)
                if existing_id:
                    print(f"[SKIP] Domain {domain} already exists, skipping.")
                    results.append(self._get_existing_result(domain, 'domain'))
                    continue

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
                existing_id = self._indicator_exists(file_hash)
                if existing_id:
                    print(f"[SKIP] Hash {file_hash[:16]}... already exists, skipping.")
                    results.append(self._get_existing_result(file_hash, 'hash'))
                    continue

                vt_data = self.api.fetch_virustotal_hash(file_hash)
                if vt_data.get("not_found"):
                    print(f"[SKIP] Hash {file_hash[:16]}... not found in VirusTotal, skipping ingestion.")
                    continue
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
                existing_id = self._indicator_exists(url)
                if existing_id:
                    print(f"[SKIP] URL {url[:50]}... already exists, skipping.")
                    results.append(self._get_existing_result(url, 'url'))
                    continue

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
