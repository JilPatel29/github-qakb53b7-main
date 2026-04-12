#!/usr/bin/env python3

import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from scripts.automation_scheduler import main

if __name__ == '__main__':
    print("\n" + "="*70)
    print("THREAT INTELLIGENCE PLATFORM - AUTOMATION MODE")
    print("="*70)
    print("\nThis will run automated tasks:")
    print("  • DVWA Scanning every 4 hours")
    print("  • Alert checks every 15 minutes")
    print("  • Daily reports at 8:00 AM")
    print("\n" + "="*70 + "\n")

    main()
