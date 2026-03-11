# Threat Intelligence Platform - Quick Start

## What's Fixed

- Database corruption resolved (fresh SQLite database created)
- All data loading errors fixed
- Modern, polished UI with improved colors and styling
- SQLite database working perfectly
- Real-time threat intelligence ingestion

## How to Run

### 1. Install Dependencies (if not already installed)
```bash
pip install flask flask-cors requests python-dotenv
```

### 2. Start the Application
```bash
python3 app.py
```

### 3. Open in Browser
```
http://localhost:5000
```

## What You'll See

The platform automatically loads with:
- **8 Threat Indicators** (5 IPs + 3 domains)
- **Risk Scoring** (High/Medium/Low classification)
- **Log Correlations** (3 suspicious network events)
- **MITRE ATT&CK Mapping** (Threat framework analysis)

## Features

### Dashboard
- Real-time statistics cards
- Risk distribution chart (doughnut chart)
- Threat type distribution (bar chart)
- High-risk indicators table

### Threats Page
- All threat indicators with filtering
- Search by indicator, category, or country
- Filter by risk level, type, and category
- Color-coded risk badges

### Log Correlations
- Network traffic matched to threat indicators
- Source/destination IP tracking
- Risk-based highlighting
- Real-time search

### MITRE ATT&CK
- Top detected techniques (horizontal bar chart)
- Tactics distribution (doughnut chart)
- Detailed technique table

### Reports
- Executive summary with key metrics
- High-risk indicators analysis
- Threat category breakdown
- MITRE ATT&CK mapping
- Actionable security recommendations

## UI Improvements

- Modern blue gradient navigation bar
- Improved card shadows and hover effects
- Professional color scheme (no purple!)
- Better contrast and readability
- Smooth animations and transitions
- Polished charts with updated colors
- Enhanced table styling

## Database

**Location:** `data/threat_intel.db`

**Tables:**
- `indicators` - Raw threat data
- `enriched_indicators` - Enriched with geo/category data
- `risk_scores` - Calculated risk classifications
- `log_correlations` - Network log matches
- `mitre_mapping` - ATT&CK framework mappings

## API Endpoints

- `GET /api/stats` - Dashboard statistics
- `GET /api/indicators/all` - All threat indicators
- `GET /api/indicators/high-risk` - High-risk only
- `GET /api/risk-distribution` - Chart data
- `GET /api/type-distribution` - Chart data
- `GET /api/log-matches` - Log correlations
- `GET /api/mitre/techniques` - MITRE data
- `POST /api/ingest/ip` - Add IP addresses
- `POST /api/ingest/domain` - Add domains

## Add Custom Indicators

```bash
# Add IPs
curl -X POST http://localhost:5000/api/ingest/ip \
  -H "Content-Type: application/json" \
  -d '{"ip_addresses": ["1.2.3.4"]}'

# Add Domains
curl -X POST http://localhost:5000/api/ingest/domain \
  -H "Content-Type: application/json" \
  -d '{"domains": ["evil.com"]}'
```

## Troubleshooting

**Database Errors?**
```bash
rm data/threat_intel.db
python3 scripts/db_init.py
python3 scripts/api_ingest.py
```

**Port 5000 in use?**
Edit `app.py` and change the port in the last line.

**No data showing?**
Run the ingestion script:
```bash
python3 scripts/api_ingest.py
python3 scripts/correlate_logs.py
```

## Architecture

```
Browser → Flask (app.py) → SQLite Database → Threat Intel APIs
                                                  ├─ VirusTotal
                                                  ├─ AbuseIPDB
                                                  └─ AlienVault OTX
```

Simple, clean, and effective!
