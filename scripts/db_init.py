import sqlite3
import os

DB_PATH = 'data/threat_intel.db'

def init_database():
    os.makedirs('data', exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS indicators (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator TEXT UNIQUE NOT NULL,
            type TEXT NOT NULL,
            source TEXT,
            reputation_score INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS enriched_indicators (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator_id INTEGER NOT NULL,
            indicator TEXT NOT NULL,
            type TEXT,
            country TEXT,
            reputation_score INTEGER,
            threat_category TEXT,
            is_malicious BOOLEAN DEFAULT 0,
            FOREIGN KEY (indicator_id) REFERENCES indicators(id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS risk_scores (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator_id INTEGER NOT NULL,
            indicator TEXT NOT NULL,
            type TEXT,
            risk_score REAL,
            risk_level TEXT,
            threat_category TEXT,
            country TEXT,
            FOREIGN KEY (indicator_id) REFERENCES indicators(id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS log_correlations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source_ip TEXT,
            destination_ip TEXT,
            destination_domain TEXT,
            matched_indicator TEXT,
            indicator_type TEXT,
            risk_level TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS mitre_mapping (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator TEXT NOT NULL,
            type TEXT,
            mitre_technique TEXT,
            mitre_tactic TEXT,
            risk_level TEXT,
            confidence REAL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    conn.commit()
    conn.close()
    print("Database initialized successfully")

if __name__ == '__main__':
    init_database()
