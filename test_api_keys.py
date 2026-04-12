#!/usr/bin/env python3
"""
Test script to verify API keys are working correctly
"""
import os
from dotenv import load_dotenv
import requests

load_dotenv()

def test_virustotal():
    """Test VirusTotal API"""
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        print("VirusTotal API Key: NOT FOUND")
        return False

    print(f"VirusTotal API Key: {api_key[:10]}...{api_key[-10:]}")

    # Test with a known IP
    url = "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8"
    headers = {"x-apikey": api_key}

    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            print("VirusTotal API: WORKING")
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            print(f"  Test IP 8.8.8.8: {stats}")
            return True
        else:
            print(f"VirusTotal API: ERROR (Status {response.status_code})")
            print(f"  Response: {response.text}")
            return False
    except Exception as e:
        print(f"VirusTotal API: ERROR - {e}")
        return False

def test_abuseipdb():
    """Test AbuseIPDB API"""
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        print("AbuseIPDB API Key: NOT FOUND")
        return False

    print(f"AbuseIPDB API Key: {api_key[:10]}...{api_key[-10:]}")

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": "8.8.8.8", "maxAgeInDays": 90}

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        if response.status_code == 200:
            print("AbuseIPDB API: WORKING")
            data = response.json()["data"]
            print(f"  Test IP 8.8.8.8: Abuse Score {data['abuseConfidenceScore']}, Country {data['countryCode']}")
            return True
        else:
            print(f"AbuseIPDB API: ERROR (Status {response.status_code})")
            print(f"  Response: {response.text}")
            return False
    except Exception as e:
        print(f"AbuseIPDB API: ERROR - {e}")
        return False

def test_alienvault_otx():
    """Test AlienVault OTX API"""
    api_key = os.getenv("ALIENVAULT_OTX_KEY")
    if not api_key:
        print("AlienVault OTX API Key: NOT FOUND")
        return False

    print(f"AlienVault OTX API Key: {api_key[:10]}...{api_key[-10:]}")

    url = "https://otx.alienvault.com/api/v1/indicators/IPv4/8.8.8.8/general"
    headers = {"X-OTX-API-KEY": api_key}

    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            print("AlienVault OTX API: WORKING")
            data = response.json()
            pulse_count = data.get("pulse_info", {}).get("count", 0)
            print(f"  Test IP 8.8.8.8: {pulse_count} pulses found")
            return True
        else:
            print(f"AlienVault OTX API: ERROR (Status {response.status_code})")
            print(f"  Response: {response.text}")
            return False
    except Exception as e:
        print(f"AlienVault OTX API: ERROR - {e}")
        return False

if __name__ == "__main__":
    print("=" * 70)
    print("THREAT INTELLIGENCE API KEY VERIFICATION")
    print("=" * 70)
    print()

    results = []

    print("[1/3] Testing VirusTotal API...")
    results.append(test_virustotal())
    print()

    print("[2/3] Testing AbuseIPDB API...")
    results.append(test_abuseipdb())
    print()

    print("[3/3] Testing AlienVault OTX API...")
    results.append(test_alienvault_otx())
    print()

    print("=" * 70)
    print("RESULTS")
    print("=" * 70)
    working = sum(results)
    total = len(results)
    print(f"APIs Working: {working}/{total}")

    if working == total:
        print("STATUS: ALL APIs are working correctly!")
    elif working > 0:
        print("STATUS: Some APIs are working, others may have invalid keys")
    else:
        print("STATUS: No APIs are working - please check your API keys")

    print()
    print("If all APIs are working, your threat intelligence platform is ready!")
    print("Run: python app.py")
    print("=" * 70)
