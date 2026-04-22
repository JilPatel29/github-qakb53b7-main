import sqlite3
import re
import os

DB_PATH = 'data/threat_intel.db'
LOG_PATH = 'logs/sample_logs.txt'

MAX_LOG_SIZE_BYTES = 5 * 1024 * 1024
MAX_LOG_LINES = 10000


class LogCorrelator:
    @staticmethod
    def parse_log_line(line):
        pattern = r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+(\d+\.\d+\.\d+\.\d+)\s*->\s*(\d+\.\d+\.\d+\.\d+|[a-zA-Z0-9.-]+)'
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
        return bool(re.match(r'^(\d+\.\d+\.\d+\.\d+)$', value))

    @staticmethod
    def correlate_logs():
        conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=30000")
        cursor = conn.cursor()

        cursor.execute('SELECT indicator, type FROM enriched_indicators')
        indicator_dict = {row[0]: row[1] for row in cursor.fetchall()}

        cursor.execute('SELECT indicator, risk_level FROM risk_scores')
        risk_dict = {row[0]: row[1] for row in cursor.fetchall()}

        cursor.execute('SELECT timestamp, source_ip, matched_indicator FROM log_correlations')
        existing_correlations = {(r[0], r[1], r[2]) for r in cursor.fetchall()}

        all_logs = []
        log_files = [LOG_PATH, 'logs/uploaded_logs.txt']
        for log_file in log_files:
            if os.path.exists(log_file):
                try:
                    file_size = os.path.getsize(log_file)
                    if file_size > MAX_LOG_SIZE_BYTES:
                        print(f"[CORRELATE] Skipping {log_file}: too large ({file_size} bytes)")
                        continue
                    with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.readlines()
                        all_logs.extend(lines[:MAX_LOG_LINES])
                except Exception as e:
                    print(f"Error reading {log_file}: {e}")

        if not all_logs:
            print("No log files found")
            conn.close()
            return

        new_matches = []
        for log_line in all_logs:
            parsed = LogCorrelator.parse_log_line(log_line)
            if not parsed:
                continue

            destination = parsed['destination']

            if destination in indicator_dict:
                dedup_key = (parsed['timestamp'], parsed['source_ip'], destination)
                if dedup_key in existing_correlations:
                    continue

                risk_level = risk_dict.get(destination, 'Medium')
                dest_ip = destination if LogCorrelator.is_ip(destination) else None
                dest_domain = destination if not LogCorrelator.is_ip(destination) else None

                new_matches.append((
                    parsed['timestamp'],
                    parsed['source_ip'],
                    dest_ip,
                    dest_domain,
                    destination,
                    indicator_dict[destination],
                    risk_level
                ))
                existing_correlations.add(dedup_key)

        if new_matches:
            chunk_size = 500
            for i in range(0, len(new_matches), chunk_size):
                cursor.executemany('''
                    INSERT INTO log_correlations
                    (timestamp, source_ip, destination_ip, destination_domain, matched_indicator, indicator_type, risk_level)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', new_matches[i:i + chunk_size])
                conn.commit()

        conn.close()

        print(f"Log correlation completed: {len(new_matches)} new matches found")


if __name__ == '__main__':
    LogCorrelator.correlate_logs()
