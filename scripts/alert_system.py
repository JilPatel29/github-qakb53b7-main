import sqlite3
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
import json
import os

DB_PATH = 'data/threat_intel.db'

class AlertSystem:

    def __init__(self):
        self.conn = sqlite3.connect(DB_PATH)
        self.cursor = self.conn.cursor()
        self.init_alert_tables()

    def close(self):
        if self.conn:
            self.conn.close()

    def init_alert_tables(self):
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                indicator TEXT,
                risk_level TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                acknowledged BOOLEAN DEFAULT 0
            )
        ''')

        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS alert_config (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_enabled BOOLEAN DEFAULT 1,
                email_alerts BOOLEAN DEFAULT 0,
                console_alerts BOOLEAN DEFAULT 1,
                high_risk_threshold INTEGER DEFAULT 80,
                medium_risk_threshold INTEGER DEFAULT 50,
                alert_email TEXT
            )
        ''')

        self.cursor.execute('SELECT COUNT(*) FROM alert_config')
        if self.cursor.fetchone()[0] == 0:
            self.cursor.execute('''
                INSERT INTO alert_config (alert_enabled, email_alerts, console_alerts)
                VALUES (1, 0, 1)
            ''')

        self.conn.commit()

    def check_for_suspicious_activity(self):
        print("[ALERT] Checking for suspicious activity...")

        alerts_generated = []

        self.cursor.execute('''
            SELECT indicator, type, risk_score, risk_level, threat_category, country
            FROM risk_scores
            WHERE risk_level = 'High'
            AND created_at >= datetime('now', '-1 hour')
        ''')

        high_risk_indicators = self.cursor.fetchall()

        for indicator in high_risk_indicators:
            alert = self.create_alert(
                alert_type='HIGH_RISK_INDICATOR',
                severity='CRITICAL',
                title=f'High Risk {indicator[1].upper()} Detected',
                description=f'Indicator: {indicator[0]}\nCategory: {indicator[4]}\nCountry: {indicator[5]}\nRisk Score: {indicator[2]}',
                indicator=indicator[0],
                risk_level='High'
            )
            alerts_generated.append(alert)

        self.cursor.execute('''
            SELECT COUNT(*)
            FROM log_correlations
            WHERE risk_level = 'High'
            AND created_at >= datetime('now', '-1 hour')
        ''')

        critical_matches = self.cursor.fetchone()[0]

        if critical_matches > 0:
            alert = self.create_alert(
                alert_type='LOG_CORRELATION',
                severity='CRITICAL',
                title=f'{critical_matches} Critical Log Matches Detected',
                description=f'Network logs matched {critical_matches} high-risk indicators in the past hour',
                indicator='Multiple',
                risk_level='High'
            )
            alerts_generated.append(alert)

        self.cursor.execute('''
            SELECT mitre_technique, COUNT(*) as count
            FROM mitre_mapping
            WHERE created_at >= datetime('now', '-1 hour')
            GROUP BY mitre_technique
            HAVING count >= 3
        ''')

        mitre_detections = self.cursor.fetchall()

        for technique, count in mitre_detections:
            alert = self.create_alert(
                alert_type='MITRE_DETECTION',
                severity='HIGH',
                title=f'Multiple Detections of {technique}',
                description=f'MITRE ATT&CK technique "{technique}" detected {count} times in the past hour',
                indicator=technique,
                risk_level='Medium'
            )
            alerts_generated.append(alert)

        self.cursor.execute('''
            SELECT COUNT(DISTINCT source_ip)
            FROM log_correlations
            WHERE created_at >= datetime('now', '-1 hour')
        ''')

        unique_sources = self.cursor.fetchone()[0]

        if unique_sources >= 5:
            alert = self.create_alert(
                alert_type='MULTIPLE_SOURCES',
                severity='HIGH',
                title=f'Activity from {unique_sources} Different Sources',
                description=f'Detected suspicious activity from {unique_sources} unique source IPs',
                indicator='Multiple',
                risk_level='High'
            )
            alerts_generated.append(alert)

        print(f"[ALERT] Generated {len(alerts_generated)} new alerts")

        return alerts_generated

    def create_alert(self, alert_type, severity, title, description, indicator, risk_level):
        self.cursor.execute('''
            INSERT INTO alerts
            (alert_type, severity, title, description, indicator, risk_level)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (alert_type, severity, title, description, indicator, risk_level))

        self.conn.commit()

        alert = {
            'id': self.cursor.lastrowid,
            'type': alert_type,
            'severity': severity,
            'title': title,
            'description': description,
            'indicator': indicator,
            'risk_level': risk_level,
            'timestamp': datetime.now().isoformat()
        }

        self.send_alert(alert)

        return alert

    def send_alert(self, alert):
        self.cursor.execute('SELECT console_alerts, email_alerts FROM alert_config')
        config = self.cursor.fetchone()

        if config and config[0]:
            self.send_console_alert(alert)

        if config and config[1]:
            self.send_email_alert(alert)

    def send_console_alert(self, alert):
        severity_colors = {
            'CRITICAL': '\033[91m',
            'HIGH': '\033[93m',
            'MEDIUM': '\033[94m',
            'LOW': '\033[92m'
        }

        color = severity_colors.get(alert['severity'], '\033[0m')
        reset = '\033[0m'

        print(f"\n{'='*70}")
        print(f"{color}[{alert['severity']}] SECURITY ALERT{reset}")
        print(f"{'='*70}")
        print(f"Title: {alert['title']}")
        print(f"Type: {alert['type']}")
        print(f"Indicator: {alert['indicator']}")
        print(f"Time: {alert['timestamp']}")
        print(f"\nDescription:")
        print(f"{alert['description']}")
        print(f"{'='*70}\n")

    def send_email_alert(self, alert):
        try:
            self.cursor.execute('SELECT alert_email FROM alert_config')
            email = self.cursor.fetchone()

            if not email or not email[0]:
                return

            msg = MIMEMultipart()
            msg['From'] = 'threatintel@security.local'
            msg['To'] = email[0]
            msg['Subject'] = f"[{alert['severity']}] {alert['title']}"

            body = f"""
Threat Intelligence Platform Alert

Severity: {alert['severity']}
Type: {alert['type']}
Indicator: {alert['indicator']}
Risk Level: {alert['risk_level']}
Time: {alert['timestamp']}

Description:
{alert['description']}

This is an automated alert from your Threat Intelligence Platform.
            """

            msg.attach(MIMEText(body, 'plain'))

            print(f"[ALERT] Email alert would be sent to {email[0]}")

        except Exception as e:
            print(f"[ALERT] Failed to send email alert: {e}")

    def get_active_alerts(self, acknowledged=False):
        self.cursor.execute('''
            SELECT id, alert_type, severity, title, description,
                   indicator, risk_level, created_at, acknowledged
            FROM alerts
            WHERE acknowledged = ?
            ORDER BY created_at DESC
        ''', (1 if acknowledged else 0,))

        alerts = []
        for row in self.cursor.fetchall():
            alerts.append({
                'id': row[0],
                'type': row[1],
                'severity': row[2],
                'title': row[3],
                'description': row[4],
                'indicator': row[5],
                'risk_level': row[6],
                'created_at': row[7],
                'acknowledged': row[8]
            })

        return alerts

    def acknowledge_alert(self, alert_id):
        self.cursor.execute('''
            UPDATE alerts
            SET acknowledged = 1
            WHERE id = ?
        ''', (alert_id,))

        self.conn.commit()
        print(f"[ALERT] Alert {alert_id} acknowledged")

    def get_alert_statistics(self):
        self.cursor.execute('''
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical,
                SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END) as high,
                SUM(CASE WHEN acknowledged = 0 THEN 1 ELSE 0 END) as unacknowledged
            FROM alerts
            WHERE created_at >= datetime('now', '-24 hours')
        ''')

        result = self.cursor.fetchone()

        return {
            'total_alerts_24h': result[0],
            'critical_alerts': result[1],
            'high_alerts': result[2],
            'unacknowledged': result[3]
        }

def run_alert_check():
    print("="*70)
    print("ALERT SYSTEM - CHECKING FOR SUSPICIOUS ACTIVITY")
    print("="*70)

    alert_system = AlertSystem()

    alerts = alert_system.check_for_suspicious_activity()

    stats = alert_system.get_alert_statistics()
    print(f"\n[STATS] Alert Statistics (Last 24h):")
    print(f"  - Total Alerts: {stats['total_alerts_24h']}")
    print(f"  - Critical: {stats['critical_alerts']}")
    print(f"  - High: {stats['high_alerts']}")
    print(f"  - Unacknowledged: {stats['unacknowledged']}")

    alert_system.close()

    print("\n[COMPLETE] Alert check completed")
    print("="*70)

if __name__ == '__main__':
    run_alert_check()
