# Quick Start Guide

## Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Run the application:
```bash
python app.py
```

3. Open your browser and navigate to:
```
http://localhost:5000
```

That's it! The application will automatically:
- Create the SQLite database
- Set up all required tables
- Ingest sample threat intelligence data
- Correlate with network logs
- Start the web server

## What You'll See

- **Dashboard**: Real-time threat statistics and charts
- **Threats**: Searchable database of threat indicators
- **Log Correlations**: Network activity matched to threats
- **MITRE ATT&CK**: Framework-based threat analysis
- **Reports**: Executive summaries and recommendations

## Adding Your Own Data

### Ingest IP Addresses

```bash
curl -X POST http://localhost:5000/api/ingest/ip \
  -H "Content-Type: application/json" \
  -d '{"ip_addresses": ["1.2.3.4", "5.6.7.8"]}'
```

### Ingest Domains

```bash
curl -X POST http://localhost:5000/api/ingest/domain \
  -H "Content-Type: application/json" \
  -d '{"domains": ["suspicious.com", "malware.net"]}'
```

## Using Real API Keys (Optional)

Copy the example environment file:
```bash
cp .env.example .env
```

Edit `.env` and add your API keys:
```
VIRUSTOTAL_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
ALIENVAULT_OTX_KEY=your_key_here
```

Without API keys, the application uses mock data that's perfect for testing and demonstration.

## Troubleshooting

### Port Already in Use

If port 5000 is already in use, edit `app.py` and change the port:
```python
app.run(debug=True, host='0.0.0.0', port=8080)
```

### Database Issues

To reset the database:
```bash
rm data/threat_intel.db
python app.py
```

### Missing Dependencies

Ensure all packages are installed:
```bash
pip install flask flask-cors requests python-dotenv
```

## Next Steps

- Explore the web interface at http://localhost:5000
- Review the API endpoints in README.md
- Add custom threat indicators via the API
- Integrate with your existing security tools
- Customize risk scoring weights in `scripts/api_ingest.py`

## Architecture

```
Browser ────> Flask Server ────> SQLite Database ────> Threat Intel APIs
                                                            │
                                                            ├─ VirusTotal
                                                            ├─ AbuseIPDB
                                                            └─ AlienVault OTX
```

The platform fetches threat intelligence from APIs, stores it in SQLite, and serves it through a modern web interface.
