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
            indicator_id INTEGER NOT NULL UNIQUE,
            indicator TEXT NOT NULL UNIQUE,
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
            indicator_id INTEGER NOT NULL UNIQUE,
            indicator TEXT NOT NULL UNIQUE,
            type TEXT,
            risk_score REAL,
            risk_level TEXT,
            threat_category TEXT,
            country TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
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
            indicator TEXT NOT NULL UNIQUE,
            type TEXT,
            mitre_technique TEXT,
            mitre_tactic TEXT,
            risk_level TEXT,
            confidence REAL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS uploaded_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            content TEXT NOT NULL,
            uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    conn.commit()
    conn.close()
    print("Database initialized successfully")


def migrate_add_unique_constraints():
    """Add UNIQUE constraints to existing database by recreating tables."""
    if not os.path.exists(DB_PATH):
        return

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("PRAGMA table_info(enriched_indicators)")
    cols = [row[1] for row in cursor.fetchall()]

    cursor.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='enriched_indicators'")
    row = cursor.fetchone()
    has_unique = row and 'UNIQUE' in row[0] if row else False

    if not has_unique and 'indicator' in cols:
        print("[MIGRATE] Adding UNIQUE constraints to enriched_indicators, risk_scores, mitre_mapping...")

        cursor.executescript('''
            BEGIN;

            CREATE TABLE IF NOT EXISTS enriched_indicators_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                indicator_id INTEGER NOT NULL UNIQUE,
                indicator TEXT NOT NULL UNIQUE,
                type TEXT,
                country TEXT,
                reputation_score INTEGER,
                threat_category TEXT,
                is_malicious BOOLEAN DEFAULT 0,
                FOREIGN KEY (indicator_id) REFERENCES indicators(id)
            );

            INSERT OR IGNORE INTO enriched_indicators_new
                (indicator_id, indicator, type, country, reputation_score, threat_category, is_malicious)
            SELECT indicator_id, indicator, type, country, reputation_score, threat_category, is_malicious
            FROM enriched_indicators
            GROUP BY indicator;

            DROP TABLE enriched_indicators;
            ALTER TABLE enriched_indicators_new RENAME TO enriched_indicators;

            CREATE TABLE IF NOT EXISTS risk_scores_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                indicator_id INTEGER NOT NULL UNIQUE,
                indicator TEXT NOT NULL UNIQUE,
                type TEXT,
                risk_score REAL,
                risk_level TEXT,
                threat_category TEXT,
                country TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (indicator_id) REFERENCES indicators(id)
            );

            INSERT OR IGNORE INTO risk_scores_new
                (indicator_id, indicator, type, risk_score, risk_level, threat_category, country)
            SELECT indicator_id, indicator, type, risk_score, risk_level, threat_category, country
            FROM risk_scores
            GROUP BY indicator;

            DROP TABLE risk_scores;
            ALTER TABLE risk_scores_new RENAME TO risk_scores;

            CREATE TABLE IF NOT EXISTS mitre_mapping_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                indicator TEXT NOT NULL UNIQUE,
                type TEXT,
                mitre_technique TEXT,
                mitre_tactic TEXT,
                risk_level TEXT,
                confidence REAL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            INSERT OR IGNORE INTO mitre_mapping_new
                (indicator, type, mitre_technique, mitre_tactic, risk_level, confidence)
            SELECT indicator, type, mitre_technique, mitre_tactic, risk_level, confidence
            FROM mitre_mapping
            GROUP BY indicator;

            DROP TABLE mitre_mapping;
            ALTER TABLE mitre_mapping_new RENAME TO mitre_mapping;

            COMMIT;
        ''')

        print("[MIGRATE] Migration complete.")
    else:
        print("[MIGRATE] UNIQUE constraints already present, skipping migration.")

    conn.close()


if __name__ == '__main__':
    init_database()
