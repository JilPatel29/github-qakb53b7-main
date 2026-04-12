# Threat Intelligence Platform

Enterprise-grade threat intelligence platform with real-time API integration.

## Quick Start

1. **Install Dependencies**
```bash
pip install -r requirements.txt
```

2. **Run Application**
```bash
python app.py
```

3. **Access Dashboard**
```
http://localhost:5000
```

## Features

- Real-time threat intelligence from VirusTotal, AbuseIPDB, and AlienVault OTX
- SQLite database for fast local storage
- Risk scoring and classification (High/Medium/Low)
- MITRE ATT&CK framework mapping
- Network log correlation
- Interactive web dashboard
- RESTful API

## How It Works

### API Integration Flow

```
User adds indicator → API calls → Real data fetched → Risk calculated → Stored in SQLite
```

**API Sources:**
- **VirusTotal**: IP reputation, domain analysis, file hashes, URLs
- **AbuseIPDB**: IP abuse confidence scoring
- **AlienVault OTX**: Threat pulse intelligence

### Data Processing

When you add an indicator (IP, domain, hash, or URL):

1. System calls all relevant APIs simultaneously
2. Retrieves real threat intelligence data
3. Calculates composite risk score (0-100)
4. Classifies as High (80+), Medium (50-79), or Low (<50)
5. Maps to MITRE ATT&CK techniques
6. Stores in SQLite database
7. Auto-correlates with network logs

### Database Structure

SQLite database with 5 tables:
- `indicators` - Raw threat data
- `enriched_indicators` - Enhanced with geo/category data
- `risk_scores` - Risk classifications
- `log_correlations` - Network log matches
- `mitre_mapping` - ATT&CK framework mappings

## Project Structure

```
project/
├── app.py                      # Main Flask application
├── data/
│   └── threat_intel.db        # SQLite database (auto-created)
├── logs/
│   └── sample_logs.txt        # Network logs for correlation
├── scripts/
│   ├── db_init.py             # Database initialization
│   ├── api_ingest.py          # API-driven threat ingestion
│   └── correlate_logs.py      # Log correlation engine
├── static/
│   ├── app.js                 # Frontend JavaScript
│   └── styles.css             # Styling
├── templates/
│   ├── dashboard.html         # Main dashboard
│   ├── threats.html           # Threat indicators view
│   ├── logs.html              # Log correlations
│   ├── mitre.html             # MITRE ATT&CK mapping
│   └── reports.html           # Threat reports
└── requirements.txt
```

## API Endpoints

### Statistics & Analytics

- `GET /api/stats` - Overall statistics
- `GET /api/risk-distribution` - Risk level distribution
- `GET /api/type-distribution` - Indicator type distribution

### Threat Indicators

- `GET /api/indicators/all` - All threat indicators
- `GET /api/indicators/high-risk` - High-risk indicators only

### MITRE ATT&CK

- `GET /api/mitre/techniques` - MITRE techniques detected

### Log Correlations

- `GET /api/log-matches` - Correlated log entries

### Reports

- `GET /api/reports/summary` - Executive summary report

### Data Ingestion

- `POST /api/ingest/ip` - Ingest IP addresses
- `POST /api/ingest/domain` - Ingest domains

### Utility

- `POST /api/refresh` - Refresh log correlations
- `GET /api/health` - Health check

## Configuration

API keys are already configured in `.env` file:
- VirusTotal API Key
- AbuseIPDB API Key
- AlienVault OTX Key

The system automatically uses these keys for real-time threat intelligence.

## Adding Indicators

### Via Web Interface
Navigate to "Add Indicators" page and use the forms

### Via API
```bash
# Add IP addresses
curl -X POST http://localhost:5000/api/ingest/ip \
  -H "Content-Type: application/json" \
  -d '{"ip_addresses": ["1.2.3.4", "5.6.7.8"]}'

# Add domains
curl -X POST http://localhost:5000/api/ingest/domain \
  -H "Content-Type: application/json" \
  -d '{"domains": ["suspicious.com"]}'

# Add file hashes
curl -X POST http://localhost:5000/api/ingest/hash \
  -H "Content-Type: application/json" \
  -d '{"hashes": ["44d88612fea8a8f36de82e1278abb02f"]}'

# Add URLs
curl -X POST http://localhost:5000/api/ingest/url \
  -H "Content-Type: application/json" \
  -d '{"urls": ["http://malicious-site.com"]}'
```

## Architecture

```
Browser
   ↓
Flask Server (app.py)
   ↓
API Routes (/api/*)
   ↓
ThreatIngestor Class (scripts/api_ingest.py)
   ↓
   ├─→ VirusTotal API (Real-time)
   ├─→ AbuseIPDB API (Real-time)
   └─→ AlienVault OTX API (Real-time)
   ↓
SQLite Database (data/threat_intel.db)
   ↓
Log Correlation (scripts/correlate_logs.py)
```

## Troubleshooting

**Reset database:**
```bash
rm data/threat_intel.db
python app.py
```

**Check API connectivity:**
- The app will show actual data from APIs if keys are valid
- If APIs fail, it falls back to mock data
- Check terminal output for API error messages

## Security

- API keys stored in `.env` file (not committed to git)
- SQLite database with file-level permissions
- Input validation on all endpoints
- No credentials exposed in frontend

---

**Ready to use!** Your API keys are configured and the system will fetch real threat intelligence data.
