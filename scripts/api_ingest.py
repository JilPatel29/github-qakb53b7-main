import sqlite3
import requests
import time
import os
from dotenv import load_dotenv

load_dotenv()

DB_PATH = "data/threat_intel.db"


class ThreatIntelAPI:

    def __init__(self):
        self.virustotal_key = os.getenv("VIRUSTOTAL_API_KEY")
        self.abuseipdb_key = os.getenv("ABUSEIPDB_API_KEY")
        self.otx_key = os.getenv("ALIENVAULT_OTX_KEY")


    def fetch_abuseipdb(self, ip):

        if not self.abuseipdb_key:
            print("No AbuseIPDB key found")
            return {
                "score": 0,
                "country": "Unknown"
            }

        url = "https://api.abuseipdb.com/api/v2/check"

        headers = {
            "Key": self.abuseipdb_key,
            "Accept": "application/json"
        }

        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90
        }

        try:

            r = requests.get(url, headers=headers, params=params)

            if r.status_code == 200:

                data = r.json()["data"]

                return {
                    "score": data["abuseConfidenceScore"],
                    "country": data["countryCode"]
                }

        except Exception as e:
            print("AbuseIPDB error:", e)

        return {
            "score": 0,
            "country": "Unknown"
        }


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
            'High': ['Malware C2', 'Phishing', 'Malicious Activity'],
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
            'Suspicious Activity': ('Discovery', 'Discovery')
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
                abuse = self.api.fetch_abuseipdb(ip)
                score = abuse["score"]
                country = abuse["country"]
                risk = self.classify_risk(score)
                threat_category = self.get_threat_category('IP', risk)

                self.cursor.execute("""
                INSERT OR IGNORE INTO indicators
                (indicator, type, source, reputation_score)
                VALUES (?, ?, ?, ?)
                """, (ip, "IP", "AbuseIPDB", score))

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
                import random
                score = random.randint(20, 95)
                risk = self.classify_risk(score)
                threat_category = self.get_threat_category('domain', risk)
                country = "Unknown"

                self.cursor.execute("""
                INSERT OR IGNORE INTO indicators
                (indicator, type, source, reputation_score)
                VALUES (?, ?, ?, ?)
                """, (domain, "domain", "Manual", score))

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