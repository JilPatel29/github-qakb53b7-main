# Threat Intelligence Analysis Platform

Enterprise-grade SOC tool for automated threat detection, risk assessment, and prioritization using real-time API ingestion.

## Architecture

```
Browser
   ↓
Flask Web Server (app.py)
   ↓
API Routes (/api/*)
   ↓
SQLite Database (data/threat_intel.db)
   ↓
Threat Intelligence APIs (VirusTotal, AbuseIPDB, AlienVault OTX)
```

## Features

- **API-Driven Ingestion**: Real-time threat data from VirusTotal, AbuseIPDB, and AlienVault OTX
- **SQLite Storage**: Lightweight, fast database for threat indicators
- **Automated Risk Scoring**: Composite scoring engine with configurable weights
- **MITRE ATT&CK Mapping**: Framework-based threat classification
- **Log Correlation**: Real-time matching against network logs
- **Interactive Dashboard**: Modern web interface with real-time analytics
- **RESTful API**: Complete API for programmatic access

## Quick Start

### Installation

```bash
pip install -r requirements.txt
```

### Running the Application

```bash
python app.py
```

The application will:
1. Initialize the SQLite database
2. Run initial threat intelligence ingestion
3. Correlate with network logs
4. Start the Flask web server on http://localhost:5000

### First Time Setup

On first run, the application automatically:
- Creates the database schema
- Ingests sample threat indicators from APIs
- Correlates threat data with sample network logs

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

### API Keys (Optional)

Set environment variables for live API access:

```bash
export VIRUSTOTAL_API_KEY="your_key_here"
export ABUSEIPDB_API_KEY="your_key_here"
export ALIENVAULT_OTX_KEY="your_key_here"
```

Without API keys, the application uses mock data for demonstration.

## Risk Scoring Algorithm

Composite risk score (0-100) calculated using:
- 40% Reputation Score
- 30% Threat Category Score
- 30% Maliciousness Score

### Risk Classifications

- **High**: Score ≥ 80
- **Medium**: Score 50-79
- **Low**: Score < 50

## Adding Custom Indicators

### Via API

```bash
curl -X POST http://localhost:5000/api/ingest/ip \
  -H "Content-Type: application/json" \
  -d '{"ip_addresses": ["1.2.3.4"]}'
```

## Security Best Practices

- API keys stored in environment variables
- SQLite database with file-level permissions
- Input validation on all API endpoints
- No credentials exposed in code

---

**Version**: 2.0
**Last Updated**: 2026-03-08
**Architecture**: API-Driven with SQLite Storage
