import sqlite3
import re
from datetime import datetime

DB_PATH = 'data/threat_intel.db'
LOG_PATH = 'logs/sample_logs.txt'

class LogCorrelator:
    @staticmethod
    def parse_log_line(line):
        """Parse log line to extract timestamp, source IP, and destination"""
        pattern = r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+(\d+\.\d+\.\d+\.\d+)\s+->\s+(\d+\.\d+\.\d+\.\d+|[a-zA-Z0-9.-]+)'
        match = re.match(pattern, line.strip())
        if match:
            return {
                'timestamp': match.group(1),
                'source_ip': match.group(2),
                'destination': match.group(3)
            }
        return None

    @staticmethod
    def is_ip(value):
        """Check if value is an IP address"""
        pattern = r'^(\d+\.\d+\.\d+\.\d+)$'
        return bool(re.match(pattern, value))

    @staticmethod
    def correlate_logs():
        """Correlate network logs with threat indicators"""
        import os

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute('DELETE FROM log_correlations')

        cursor.execute('SELECT indicator, type FROM enriched_indicators')
        indicators = cursor.fetchall()

        indicator_dict = {ind[0]: ind[1] for ind in indicators}

        all_logs = []

        log_files = [LOG_PATH, 'logs/uploaded_logs.txt']
        for log_file in log_files:
            if os.path.exists(log_file):
                try:
                    with open(log_file, 'r') as f:
                        all_logs.extend(f.readlines())
                except Exception as e:
                    print(f"Error reading {log_file}: {e}")

        if not all_logs:
            print("No log files found")
            conn.close()
            return

        matches = []
        for log_line in all_logs:
            parsed = LogCorrelator.parse_log_line(log_line)
            if not parsed:
                continue

            destination = parsed['destination']

            if destination in indicator_dict:
                cursor.execute('''
                    SELECT risk_level FROM risk_scores
                    WHERE indicator = ?
                ''', (destination,))
                risk_result = cursor.fetchone()
                risk_level = risk_result[0] if risk_result else 'Medium'

                dest_ip = destination if LogCorrelator.is_ip(destination) else None
                dest_domain = destination if not LogCorrelator.is_ip(destination) else None

                matches.append((
                    parsed['timestamp'],
                    parsed['source_ip'],
                    dest_ip,
                    dest_domain,
                    destination,
                    indicator_dict[destination],
                    risk_level
                ))

        for match in matches:
            cursor.execute('''
                INSERT INTO log_correlations
                (timestamp, source_ip, destination_ip, destination_domain, matched_indicator, indicator_type, risk_level)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', match)

        conn.commit()
        conn.close()

        print(f"Log correlation completed: {len(matches)} matches found")

if __name__ == '__main__':
    correlator = LogCorrelator()
    correlator.correlate_logs()
