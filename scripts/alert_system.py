import sqlite3
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
import json
import os
from dotenv import load_dotenv

load_dotenv()

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
                alert_email TEXT,
                gmail_sender TEXT,
                gmail_app_password TEXT
            )
        ''')

        self.cursor.execute('SELECT COUNT(*) FROM alert_config')
        if self.cursor.fetchone()[0] == 0:
            self.cursor.execute('''
                INSERT INTO alert_config (alert_enabled, email_alerts, console_alerts, alert_email, gmail_sender, gmail_app_password)
                VALUES (1, 0, 1, ?, ?, ?)
            ''', (
                os.getenv('ALERT_RECIPIENT_EMAIL', ''),
                os.getenv('GMAIL_SENDER_EMAIL', ''),
                os.getenv('GMAIL_APP_PASSWORD', '')
            ))
        else:
            env_recipient = os.getenv('ALERT_RECIPIENT_EMAIL', '')
            env_sender = os.getenv('GMAIL_SENDER_EMAIL', '')
            env_password = os.getenv('GMAIL_APP_PASSWORD', '')
            if env_recipient or env_sender or env_password:
                self.cursor.execute('''
                    UPDATE alert_config SET
                        alert_email = CASE WHEN alert_email = '' OR alert_email IS NULL THEN ? ELSE alert_email END,
                        gmail_sender = CASE WHEN gmail_sender = '' OR gmail_sender IS NULL THEN ? ELSE gmail_sender END,
                        gmail_app_password = CASE WHEN gmail_app_password = '' OR gmail_app_password IS NULL THEN ? ELSE gmail_app_password END
                    WHERE id = 1
                ''', (env_recipient, env_sender, env_password))

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

    def get_email_config(self):
        self.cursor.execute('''
            SELECT alert_email, gmail_sender, gmail_app_password, email_alerts
            FROM alert_config WHERE id = 1
        ''')
        row = self.cursor.fetchone()
        if row:
            return {
                'recipient': row[0] or os.getenv('ALERT_RECIPIENT_EMAIL', ''),
                'sender': row[1] or os.getenv('GMAIL_SENDER_EMAIL', ''),
                'password': row[2] or os.getenv('GMAIL_APP_PASSWORD', ''),
                'enabled': bool(row[3])
            }
        return {'recipient': '', 'sender': '', 'password': '', 'enabled': False}

    def update_email_config(self, recipient_email, sender_email, app_password, enable_email):
        self.cursor.execute('''
            UPDATE alert_config SET
                alert_email = ?,
                gmail_sender = ?,
                gmail_app_password = ?,
                email_alerts = ?
            WHERE id = 1
        ''', (recipient_email, sender_email, app_password, 1 if enable_email else 0))
        self.conn.commit()

    def test_gmail_connection(self):
        config = self.get_email_config()
        if not config['sender'] or not config['password']:
            return {'success': False, 'message': 'Gmail sender email and app password are required'}

        try:
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as server:
                server.login(config['sender'], config['password'])
            return {'success': True, 'message': 'Gmail connection successful'}
        except smtplib.SMTPAuthenticationError:
            return {'success': False, 'message': 'Authentication failed. Check your Gmail and App Password.'}
        except Exception as e:
            return {'success': False, 'message': f'Connection error: {str(e)}'}

    def send_email_alert(self, alert):
        try:
            config = self.get_email_config()

            sender = config['sender']
            recipient = config['recipient']
            password = config['password']

            if not sender or not recipient or not password:
                print(f"[ALERT] Email not configured - skipping email for: {alert['title']}")
                return False

            if 'your_gmail' in sender or 'your_16_char' in password:
                print(f"[ALERT] Email credentials are placeholder values - skipping email")
                return False

            severity_emoji = {
                'CRITICAL': '[!!]',
                'HIGH': '[!]',
                'MEDIUM': '[*]',
                'LOW': '[i]'
            }.get(alert['severity'], '[?]')

            subject = f"{severity_emoji} ThreatIntel Alert [{alert['severity']}]: {alert['title']}"

            html_body = f"""
<!DOCTYPE html>
<html>
<head>
<style>
  body {{ font-family: Arial, sans-serif; background: #f4f4f4; margin: 0; padding: 20px; }}
  .container {{ max-width: 600px; margin: 0 auto; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
  .header {{ background: {'#dc2626' if alert['severity'] == 'CRITICAL' else '#f59e0b' if alert['severity'] == 'HIGH' else '#3b82f6'}; color: white; padding: 24px; }}
  .header h1 {{ margin: 0; font-size: 20px; }}
  .badge {{ display: inline-block; background: rgba(255,255,255,0.2); padding: 4px 12px; border-radius: 20px; font-size: 13px; margin-bottom: 8px; }}
  .body {{ padding: 24px; }}
  .detail-row {{ display: flex; margin-bottom: 12px; border-bottom: 1px solid #f0f0f0; padding-bottom: 12px; }}
  .detail-label {{ font-weight: bold; color: #666; width: 130px; flex-shrink: 0; }}
  .detail-value {{ color: #333; }}
  .description-box {{ background: #f8f9fa; border-left: 4px solid {'#dc2626' if alert['severity'] == 'CRITICAL' else '#f59e0b'}; padding: 16px; border-radius: 4px; margin-top: 16px; white-space: pre-line; font-family: monospace; font-size: 13px; }}
  .footer {{ background: #f8f9fa; padding: 16px 24px; font-size: 12px; color: #999; text-align: center; }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div class="badge">{alert['severity']}</div>
    <h1>{alert['title']}</h1>
  </div>
  <div class="body">
    <div class="detail-row">
      <span class="detail-label">Alert Type:</span>
      <span class="detail-value">{alert['type'].replace('_', ' ').title()}</span>
    </div>
    <div class="detail-row">
      <span class="detail-label">Indicator:</span>
      <span class="detail-value"><code>{alert['indicator']}</code></span>
    </div>
    <div class="detail-row">
      <span class="detail-label">Risk Level:</span>
      <span class="detail-value">{alert['risk_level']}</span>
    </div>
    <div class="detail-row">
      <span class="detail-label">Detected At:</span>
      <span class="detail-value">{alert['timestamp']}</span>
    </div>
    <div class="description-box">{alert['description']}</div>
  </div>
  <div class="footer">
    This is an automated security alert from your Threat Intelligence Platform.<br>
    Log in to your dashboard to acknowledge and investigate this alert.
  </div>
</div>
</body>
</html>
"""

            msg = MIMEMultipart('alternative')
            msg['From'] = f"ThreatIntel Platform <{sender}>"
            msg['To'] = recipient
            msg['Subject'] = subject

            text_body = f"""
THREAT INTELLIGENCE PLATFORM - SECURITY ALERT

Severity: {alert['severity']}
Title: {alert['title']}
Type: {alert['type']}
Indicator: {alert['indicator']}
Risk Level: {alert['risk_level']}
Detected At: {alert['timestamp']}

Description:
{alert['description']}

---
This is an automated alert. Log in to your dashboard to acknowledge this alert.
"""
            msg.attach(MIMEText(text_body, 'plain'))
            msg.attach(MIMEText(html_body, 'html'))

            context = ssl.create_default_context()
            with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as server:
                server.login(sender, password)
                server.sendmail(sender, recipient, msg.as_string())

            print(f"[ALERT] Email sent successfully to {recipient} for: {alert['title']}")
            return True

        except smtplib.SMTPAuthenticationError:
            print(f"[ALERT] Gmail authentication failed. Check your App Password.")
            return False
        except smtplib.SMTPException as e:
            print(f"[ALERT] SMTP error sending email: {e}")
            return False
        except Exception as e:
            print(f"[ALERT] Failed to send email alert: {e}")
            return False

    def send_test_email(self):
        config = self.get_email_config()
        if not config['sender'] or not config['recipient'] or not config['password']:
            return {'success': False, 'message': 'Email not fully configured'}

        test_alert = {
            'id': 0,
            'type': 'TEST',
            'severity': 'HIGH',
            'title': 'Test Alert - ThreatIntel Platform',
            'description': 'This is a test alert to verify your email configuration is working correctly.',
            'indicator': 'test',
            'risk_level': 'Test',
            'timestamp': datetime.now().isoformat()
        }

        success = self.send_email_alert(test_alert)
        if success:
            return {'success': True, 'message': f'Test email sent to {config["recipient"]}'}
        else:
            return {'success': False, 'message': 'Failed to send test email. Check credentials and try again.'}

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

        self.cursor.execute('SELECT COUNT(*) FROM alerts WHERE acknowledged = 0')
        total_unack = self.cursor.fetchone()[0]

        return {
            'total_alerts_24h': result[0] or 0,
            'critical_alerts': result[1] or 0,
            'high_alerts': result[2] or 0,
            'unacknowledged': result[3] or 0,
            'total_unacknowledged': total_unack
        }

    def acknowledge_all_alerts(self):
        self.cursor.execute('UPDATE alerts SET acknowledged = 1 WHERE acknowledged = 0')
        self.conn.commit()
        print(f"[ALERT] All alerts acknowledged")

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
