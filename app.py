from flask import Flask, jsonify, render_template, request
from flask_cors import CORS
import sqlite3
import sys
import os
from datetime import datetime

sys.path.insert(0, os.path.dirname(__file__))

from scripts.db_init import init_database
from scripts.api_ingest import ThreatIngestor
from scripts.correlate_logs import LogCorrelator

app = Flask(__name__)
CORS(app)

DB_PATH = 'data/threat_intel.db'

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@app.route('/threats')
def threats():
    return render_template('threats.html')

@app.route('/logs')
def logs():
    return render_template('logs.html')

@app.route('/mitre')
def mitre():
    return render_template('mitre.html')

@app.route('/reports')
def reports():
    return render_template('reports.html')

@app.route('/add-indicator')
def add_indicator():
    return render_template('add_indicator.html')

@app.route('/api/stats', methods=['GET'])
def get_stats():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM risk_scores")
        total = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM risk_scores WHERE risk_level='High'")
        high = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM risk_scores WHERE risk_level='Medium'")
        medium = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM log_correlations")
        correlations = cursor.fetchone()[0]

        conn.close()

        return jsonify({
            'total_indicators': total,
            'high_risk': high,
            'medium_risk': medium,
            'log_correlations': correlations
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/risk-distribution', methods=['GET'])
def get_risk_distribution():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT risk_level, COUNT(*) FROM risk_scores GROUP BY risk_level")
        rows = cursor.fetchall()

        conn.close()

        labels = []
        values = []
        for row in rows:
            labels.append(row[0])
            values.append(row[1])

        return jsonify({
            'labels': labels,
            'values': values
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/type-distribution', methods=['GET'])
def get_type_distribution():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT type, COUNT(*) FROM risk_scores GROUP BY type")
        rows = cursor.fetchall()

        conn.close()

        labels = []
        values = []
        for row in rows:
            labels.append(row[0])
            values.append(row[1])

        return jsonify({
            'labels': labels,
            'values': values
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/indicators/high-risk', methods=['GET'])
def get_high_risk_indicators():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT indicator, type, risk_score, risk_level, threat_category, country
            FROM risk_scores
            WHERE risk_level='High'
            ORDER BY risk_score DESC
            LIMIT 50
        """)
        rows = cursor.fetchall()

        conn.close()

        indicators = []
        for row in rows:
            indicators.append({
                'indicator': row[0],
                'type': row[1],
                'risk_score': row[2],
                'risk_level': row[3],
                'threat_category': row[4],
                'country': row[5]
            })

        return jsonify(indicators)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/indicators/all', methods=['GET'])
def get_all_indicators():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT indicator, type, risk_score, risk_level, threat_category, country
            FROM risk_scores
            ORDER BY risk_score DESC
        """)
        rows = cursor.fetchall()

        conn.close()

        indicators = []
        for row in rows:
            indicators.append({
                'indicator': row[0],
                'type': row[1],
                'risk_score': row[2],
                'risk_level': row[3],
                'threat_category': row[4],
                'country': row[5]
            })

        return jsonify(indicators)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/mitre/techniques', methods=['GET'])
def get_mitre_techniques():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT mitre_technique, mitre_tactic, COUNT(*) as count
            FROM mitre_mapping
            GROUP BY mitre_technique, mitre_tactic
            ORDER BY count DESC
        """)
        rows = cursor.fetchall()

        conn.close()

        techniques = []
        for row in rows:
            techniques.append({
                'technique': row[0],
                'tactic': row[1],
                'count': row[2]
            })

        return jsonify(techniques)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/log-matches', methods=['GET'])
def get_log_matches():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT timestamp, source_ip, destination_ip, destination_domain,
                   matched_indicator, indicator_type, risk_level
            FROM log_correlations
            ORDER BY timestamp DESC
        """)
        rows = cursor.fetchall()

        conn.close()

        correlations = []
        for row in rows:
            correlations.append({
                'timestamp': row[0],
                'source_ip': row[1],
                'destination_ip': row[2],
                'destination_domain': row[3],
                'matched_indicator': row[4],
                'indicator_type': row[5],
                'risk_level': row[6]
            })

        return jsonify(correlations)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/reports/summary', methods=['GET'])
def get_report_summary():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM risk_scores WHERE risk_level='High'")
        high_risk = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM risk_scores WHERE risk_level='Medium'")
        medium_risk = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM log_correlations WHERE risk_level='High'")
        critical_events = cursor.fetchone()[0]

        cursor.execute("""
            SELECT threat_category, COUNT(*) as count
            FROM risk_scores
            GROUP BY threat_category
            ORDER BY count DESC
            LIMIT 5
        """)
        top_threats = [{'category': row[0], 'count': row[1]} for row in cursor.fetchall()]

        cursor.execute("""
            SELECT mitre_tactic, COUNT(*) as count
            FROM mitre_mapping
            GROUP BY mitre_tactic
            ORDER BY count DESC
        """)
        mitre_tactics = [{'tactic': row[0], 'count': row[1]} for row in cursor.fetchall()]

        conn.close()

        recommendations = [
            "Block all high-risk IP addresses at perimeter firewalls",
            "Enable DNS filtering for malicious domains",
            "Update endpoint protection signatures",
            "Review logs for indicators of compromise",
            "Conduct threat hunting for MITRE ATT&CK techniques",
            "Monitor for C2 communication patterns",
            "Implement network segmentation",
            "Update incident response procedures"
        ]

        return jsonify({
            'summary': {
                'high_risk_indicators': high_risk,
                'medium_risk_indicators': medium_risk,
                'critical_log_events': critical_events
            },
            'top_threats': top_threats,
            'mitre_tactics': mitre_tactics,
            'recommendations': recommendations
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/ingest/ip', methods=['POST'])
def ingest_ip():
    try:
        data = request.get_json()
        ip_addresses = data.get('ip_addresses', [])

        if not ip_addresses:
            return jsonify({'error': 'No IP addresses provided'}), 400

        ingestor = ThreatIngestor()
        results = ingestor.ingest_ip_addresses(ip_addresses)
        ingestor.close()

        LogCorrelator.correlate_logs()

        return jsonify({
            'success': True,
            'ingested': len(results),
            'results': results
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/ingest/domain', methods=['POST'])
def ingest_domain():
    try:
        data = request.get_json()
        domains = data.get('domains', [])

        if not domains:
            return jsonify({'error': 'No domains provided'}), 400

        ingestor = ThreatIngestor()
        results = ingestor.ingest_domains(domains)
        ingestor.close()

        LogCorrelator.correlate_logs()

        return jsonify({
            'success': True,
            'ingested': len(results),
            'results': results
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/ingest/hash', methods=['POST'])
def ingest_hash():
    try:
        data = request.get_json()
        hashes = data.get('hashes', [])

        if not hashes:
            return jsonify({'error': 'No file hashes provided'}), 400

        ingestor = ThreatIngestor()
        results = ingestor.ingest_file_hashes(hashes)
        ingestor.close()

        LogCorrelator.correlate_logs()

        return jsonify({
            'success': True,
            'ingested': len(results),
            'results': results
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/ingest/url', methods=['POST'])
def ingest_url():
    try:
        data = request.get_json()
        urls = data.get('urls', [])

        if not urls:
            return jsonify({'error': 'No URLs provided'}), 400

        ingestor = ThreatIngestor()
        results = ingestor.ingest_urls(urls)
        ingestor.close()

        LogCorrelator.correlate_logs()

        return jsonify({
            'success': True,
            'ingested': len(results),
            'results': results
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/upload-logs', methods=['POST'])
def upload_logs():
    try:
        data = request.get_json()
        log_content = data.get('log_content', '')
        filename = data.get('filename', 'uploaded_logs.txt')

        if not log_content:
            return jsonify({'error': 'No log content provided'}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO uploaded_logs (filename, content)
            VALUES (?, ?)
        """, (filename, log_content))

        conn.commit()
        conn.close()

        with open('logs/uploaded_logs.txt', 'a') as f:
            f.write('\n' + log_content)

        LogCorrelator.correlate_logs()

        return jsonify({
            'success': True,
            'message': 'Logs uploaded and correlated successfully'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/generate-pdf-report', methods=['GET'])
def generate_pdf_report():
    try:
        from scripts.pdf_generator import PDFReportGenerator
        import tempfile
        import os

        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf')
        temp_path = temp_file.name
        temp_file.close()

        generator = PDFReportGenerator()
        generator.generate_report(temp_path)
        generator.close()

        from flask import send_file
        return send_file(
            temp_path,
            mimetype='application/pdf',
            as_attachment=True,
            download_name='threat_intelligence_report.pdf'
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/refresh', methods=['POST'])
def refresh_data():
    try:
        LogCorrelator.correlate_logs()

        return jsonify({
            'success': True,
            'message': 'Data refreshed successfully'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy', 'service': 'threat-intelligence-api'})

def initialize_app():
    os.makedirs('data', exist_ok=True)
    os.makedirs('logs', exist_ok=True)

    if not os.path.exists(DB_PATH):
        print("Initializing database...")
        init_database()

        print("Running initial data ingestion...")
        from scripts.api_ingest import ingest_sample_data
        ingest_sample_data()

        print("Correlating logs...")
        LogCorrelator.correlate_logs()

        print("Setup complete!")

if __name__ == '__main__':
    initialize_app()
    print("\n" + "=" * 70)
    print("THREAT INTELLIGENCE PLATFORM")
    print("=" * 70)
    print("\nServer running on http://localhost:5000")
    print("\nEndpoints:")
    print("  Dashboard: http://localhost:5000/")
    print("  API: http://localhost:5000/api/stats")
    print("\nPress Ctrl+C to stop the server\n")
    print("=" * 70 + "\n")

    app.run(debug=True, host='0.0.0.0', port=5000)
