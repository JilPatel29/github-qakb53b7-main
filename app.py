from flask import Flask, jsonify, render_template, request, Response
from flask_cors import CORS
import sqlite3
import sys
import os
import threading
import time
import json
from datetime import datetime

sys.path.insert(0, os.path.dirname(__file__))

from scripts.db_init import init_database
from scripts.api_ingest import ThreatIngestor
from scripts.correlate_logs import LogCorrelator

app = Flask(__name__)
CORS(app)

_ingestion_state = {
    'running': False,
    'thread': None,
    'interval': 30,
    'last_scan': None,
    'scan_count': 0,
    'log': []
}
_ingestion_lock = threading.Lock()


def _continuous_ingestion_worker(interval):
    from scripts.dvwa_scanner import run_automated_scan
    while True:
        with _ingestion_lock:
            if not _ingestion_state['running']:
                break
        try:
            ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            with _ingestion_lock:
                _ingestion_state['log'].insert(0, {'time': ts, 'status': 'scanning', 'msg': 'Scanning DVWA for new IOCs...'})
                _ingestion_state['log'] = _ingestion_state['log'][:50]

            iocs = run_automated_scan()

            ts2 = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            with _ingestion_lock:
                _ingestion_state['last_scan'] = ts2
                _ingestion_state['scan_count'] += 1
                total = sum(len(v) if isinstance(v, list) else v for v in iocs.values()) if iocs else 0
                new_ips = len(iocs.get("ips", []))
                new_domains = len(iocs.get("domains", []))
                new_urls = len(iocs.get("urls", []))
                new_hashes = len(iocs.get("hashes", []))
                new_total = new_ips + new_domains + new_urls + new_hashes
                msg = (f'Scan complete. New IOCs: {new_total} '
                       f'(IPs: {new_ips}, Domains: {new_domains}, URLs: {new_urls}, Hashes: {new_hashes})'
                       if new_total > 0 else 'Scan complete. No new IOCs (all already ingested)')
                _ingestion_state['log'].insert(0, {
                    'time': ts2,
                    'status': 'ok',
                    'msg': msg
                })
                _ingestion_state['log'] = _ingestion_state['log'][:50]
        except Exception as e:
            ts_e = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            with _ingestion_lock:
                _ingestion_state['log'].insert(0, {'time': ts_e, 'status': 'error', 'msg': f'Error: {str(e)}'})
                _ingestion_state['log'] = _ingestion_state['log'][:50]

        elapsed = 0
        with _ingestion_lock:
            interval_val = _ingestion_state['interval']
        while elapsed < interval_val:
            with _ingestion_lock:
                if not _ingestion_state['running']:
                    return
            time.sleep(1)
            elapsed += 1

DB_PATH = 'data/threat_intel.db'

def get_db_connection():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
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

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    try:
        from scripts.alert_system import AlertSystem

        alert_system = AlertSystem()
        alerts_list = alert_system.get_all_alerts(limit=200)
        alert_system.close()

        return jsonify(alerts_list)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/alerts/stats', methods=['GET'])
def get_alert_stats():
    try:
        from scripts.alert_system import AlertSystem

        alert_system = AlertSystem()
        stats = alert_system.get_alert_statistics()
        alert_system.close()

        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/alerts')
def alerts():
    return render_template('alerts.html')

@app.route('/api/alert-config', methods=['GET'])
def get_alert_config():
    try:
        from scripts.alert_system import AlertSystem

        alert_system = AlertSystem()
        config = alert_system.get_email_config()
        alert_system.close()

        return jsonify({
            'sender': config['sender'],
            'recipient': config['recipient'],
            'enabled': config['enabled']
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/alert-config', methods=['POST'])
def update_alert_config():
    try:
        from scripts.alert_system import AlertSystem

        data = request.get_json()
        alert_system = AlertSystem()
        alert_system.update_email_config(
            data.get('recipient'),
            data.get('sender'),
            data.get('password'),
            data.get('enabled', False)
        )
        alert_system.close()

        return jsonify({'success': True, 'message': 'Configuration updated'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/test-gmail', methods=['POST'])
def test_gmail():
    try:
        from scripts.alert_system import AlertSystem

        data = request.get_json()
        alert_system = AlertSystem()

        temp_config = alert_system.get_email_config()
        alert_system.update_email_config(
            temp_config['recipient'],
            data.get('sender'),
            data.get('password'),
            False
        )

        result = alert_system.test_gmail_connection()
        alert_system.close()

        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/alerts/acknowledge/<int:alert_id>', methods=['POST'])
def acknowledge_alert(alert_id):
    try:
        from scripts.alert_system import AlertSystem

        alert_system = AlertSystem()
        alert_system.acknowledge_alert(alert_id)
        alert_system.close()

        return jsonify({'success': True, 'message': f'Alert {alert_id} acknowledged'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/alerts/acknowledge-all', methods=['POST'])
def acknowledge_all_alerts():
    try:
        from scripts.alert_system import AlertSystem

        alert_system = AlertSystem()
        alert_system.acknowledge_all_alerts()
        alert_system.close()

        return jsonify({'success': True, 'message': 'All alerts acknowledged'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan-logs', methods=['GET'])
def get_scan_logs():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('''
            SELECT scan_timestamp, target, ips_found, domains_found,
                   urls_found, hashes_found, total_iocs, scan_status
            FROM scan_logs
            ORDER BY scan_timestamp DESC
            LIMIT 50
        ''')

        logs = []
        for row in cursor.fetchall():
            logs.append({
                'timestamp': row[0],
                'target': row[1],
                'ips_found': row[2],
                'domains_found': row[3],
                'urls_found': row[4],
                'hashes_found': row[5],
                'total_iocs': row[6],
                'status': row[7]
            })

        conn.close()
        return jsonify(logs)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/trigger/scan', methods=['POST'])
def trigger_scan():
    try:
        from scripts.dvwa_scanner import run_automated_scan

        iocs = run_automated_scan()

        return jsonify({
            'success': True,
            'message': 'DVWA scan completed',
            'iocs': {
                'ips': len(iocs['ips']),
                'domains': len(iocs['domains']),
                'urls': len(iocs['urls']),
                'hashes': len(iocs['hashes'])
            }
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/trigger/alert-check', methods=['POST'])
def trigger_alert_check():
    try:
        from scripts.alert_system import run_alert_check

        run_alert_check()

        return jsonify({
            'success': True,
            'message': 'Alert check completed'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/trigger/report', methods=['POST'])
def trigger_report():
    try:
        from scripts.daily_report import generate_daily_report

        pdf_path = generate_daily_report()

        return jsonify({
            'success': True,
            'message': 'Daily report generated',
            'report_path': pdf_path
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/ingestion/start', methods=['POST'])
def start_ingestion():
    data = request.get_json() or {}
    interval = int(data.get('interval', 30))
    interval = max(10, min(interval, 3600))

    with _ingestion_lock:
        if _ingestion_state['running']:
            return jsonify({'success': False, 'message': 'Already running'})
        _ingestion_state['running'] = True
        _ingestion_state['interval'] = interval
        t = threading.Thread(target=_continuous_ingestion_worker, args=(interval,), daemon=True)
        _ingestion_state['thread'] = t
        t.start()

    return jsonify({'success': True, 'message': f'Continuous ingestion started (every {interval}s)'})


@app.route('/api/ingestion/stop', methods=['POST'])
def stop_ingestion():
    with _ingestion_lock:
        if not _ingestion_state['running']:
            return jsonify({'success': False, 'message': 'Not running'})
        _ingestion_state['running'] = False

    return jsonify({'success': True, 'message': 'Continuous ingestion stopped'})


@app.route('/api/ingestion/status', methods=['GET'])
def ingestion_status():
    with _ingestion_lock:
        return jsonify({
            'running': _ingestion_state['running'],
            'interval': _ingestion_state['interval'],
            'last_scan': _ingestion_state['last_scan'],
            'scan_count': _ingestion_state['scan_count'],
            'log': _ingestion_state['log'][:20]
        })


@app.route('/api/ingestion/stream')
def ingestion_stream():
    def event_stream():
        last_count = -1
        while True:
            with _ingestion_lock:
                current_count = len(_ingestion_state['log'])
                running = _ingestion_state['running']
                payload = {
                    'running': running,
                    'interval': _ingestion_state['interval'],
                    'last_scan': _ingestion_state['last_scan'],
                    'scan_count': _ingestion_state['scan_count'],
                    'log': _ingestion_state['log'][:20]
                }
            if current_count != last_count:
                last_count = current_count
                yield f"data: {json.dumps(payload)}\n\n"
            time.sleep(1)
    return Response(event_stream(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})


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
