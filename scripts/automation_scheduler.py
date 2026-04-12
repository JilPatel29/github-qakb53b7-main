import schedule
import time
from datetime import datetime
import threading
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from scripts.dvwa_scanner import run_automated_scan
from scripts.alert_system import run_alert_check
from scripts.daily_report import generate_daily_report

class AutomationScheduler:

    def __init__(self):
        self.running = False
        self.scheduler_thread = None

    def job_dvwa_scan(self):
        print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Starting scheduled DVWA scan...")
        try:
            run_automated_scan()
        except Exception as e:
            print(f"[ERROR] DVWA scan failed: {e}")

    def job_alert_check(self):
        print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Starting scheduled alert check...")
        try:
            run_alert_check()
        except Exception as e:
            print(f"[ERROR] Alert check failed: {e}")

    def job_daily_report(self):
        print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Starting scheduled daily report...")
        try:
            generate_daily_report()
        except Exception as e:
            print(f"[ERROR] Daily report failed: {e}")

    def setup_schedules(self):
        schedule.clear()

        schedule.every(4).hours.do(self.job_dvwa_scan)

        schedule.every(15).minutes.do(self.job_alert_check)

        schedule.every().day.at("08:00").do(self.job_daily_report)

        print("\n" + "="*70)
        print("AUTOMATION SCHEDULER - CONFIGURED")
        print("="*70)
        print("\nScheduled Tasks:")
        print("  • DVWA Scan: Every 4 hours")
        print("  • Alert Check: Every 15 minutes")
        print("  • Daily Report: Every day at 08:00 AM")
        print("\nPress Ctrl+C to stop the scheduler")
        print("="*70 + "\n")

    def run_scheduler(self):
        self.running = True

        while self.running:
            schedule.run_pending()
            time.sleep(1)

    def start(self):
        self.setup_schedules()

        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Running initial scan and alert check...")
        self.job_dvwa_scan()
        self.job_alert_check()

        self.scheduler_thread = threading.Thread(target=self.run_scheduler, daemon=True)
        self.scheduler_thread.start()

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n\n[SHUTDOWN] Stopping automation scheduler...")
            self.running = False
            if self.scheduler_thread:
                self.scheduler_thread.join(timeout=5)
            print("[SHUTDOWN] Scheduler stopped")

    def stop(self):
        self.running = False

def main():
    scheduler = AutomationScheduler()
    scheduler.start()

if __name__ == '__main__':
    main()
