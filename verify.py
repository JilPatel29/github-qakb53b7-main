#!/usr/bin/env python3
import os
import sys
import sqlite3

def verify_project():
    print("=" * 70)
    print("THREAT INTELLIGENCE PLATFORM - VERIFICATION")
    print("=" * 70)
    print()

    errors = []
    warnings = []

    print("[1/6] Checking project structure...")
    required_files = [
        'app.py',
        'requirements.txt',
        'scripts/db_init.py',
        'scripts/api_ingest.py',
        'scripts/correlate_logs.py',
        'static/app.js',
        'static/styles.css',
        'templates/dashboard.html',
        'logs/sample_logs.txt'
    ]

    for file in required_files:
        if not os.path.exists(file):
            errors.append(f"Missing required file: {file}")
        else:
            print(f"  ✓ {file}")

    print()
    print("[2/6] Checking database...")
    if not os.path.exists('data/threat_intel.db'):
        warnings.append("Database not initialized. Will be created on first run.")
        print("  ⚠ Database will be created on first run")
    else:
        try:
            conn = sqlite3.connect('data/threat_intel.db')
            cursor = conn.cursor()

            tables = cursor.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name != 'sqlite_sequence'"
            ).fetchall()

            expected_tables = ['indicators', 'enriched_indicators', 'risk_scores',
                             'log_correlations', 'mitre_mapping']

            found_tables = [t[0] for t in tables]

            for table in expected_tables:
                if table in found_tables:
                    print(f"  ✓ Table: {table}")
                else:
                    errors.append(f"Missing table: {table}")

            conn.close()
        except Exception as e:
            errors.append(f"Database error: {e}")

    print()
    print("[3/6] Checking Python modules...")
    required_modules = ['flask', 'flask_cors', 'requests', 'sqlite3']

    for module in required_modules:
        module_name = module.replace('_', '-')
        try:
            if module == 'flask_cors':
                __import__('flask_cors')
            else:
                __import__(module)
            print(f"  ✓ {module_name}")
        except ImportError:
            if module != 'sqlite3':
                warnings.append(f"Module {module_name} not installed. Run: pip install -r requirements.txt")
                print(f"  ⚠ {module_name} (run pip install)")
            else:
                errors.append(f"Module {module} not available (should be built-in)")

    print()
    print("[4/6] Checking templates...")
    templates = ['dashboard.html', 'threats.html', 'logs.html', 'mitre.html', 'reports.html']
    for template in templates:
        path = f'templates/{template}'
        if os.path.exists(path):
            print(f"  ✓ {template}")
        else:
            errors.append(f"Missing template: {template}")

    print()
    print("[5/6] Checking static files...")
    static_files = ['app.js', 'styles.css']
    for static_file in static_files:
        path = f'static/{static_file}'
        if os.path.exists(path):
            print(f"  ✓ {static_file}")
        else:
            errors.append(f"Missing static file: {static_file}")

    print()
    print("[6/6] Checking environment...")
    if os.path.exists('.env'):
        print("  ✓ Environment file found (.env)")
    else:
        print("  ℹ No .env file (optional - will use mock data)")

    print()
    print("=" * 70)
    print("VERIFICATION RESULTS")
    print("=" * 70)
    print()

    if errors:
        print("❌ ERRORS:")
        for error in errors:
            print(f"  • {error}")
        print()

    if warnings:
        print("⚠️  WARNINGS:")
        for warning in warnings:
            print(f"  • {warning}")
        print()

    if not errors and not warnings:
        print("✓ All checks passed!")
        print()
        print("Ready to run:")
        print("  python app.py")
        print()
        print("Then open: http://localhost:5000")
        return 0
    elif not errors:
        print("✓ Project structure is valid")
        print()
        print("Address warnings above, then run:")
        print("  python app.py")
        return 0
    else:
        print("❌ Please fix the errors above before running")
        return 1

    print()
    print("=" * 70)

if __name__ == '__main__':
    sys.exit(verify_project())
