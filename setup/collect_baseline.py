"""
collect_baseline.py
Runs silently for 7 days and records behavioral baselines for the current user.
After 7 days, saves a baseline profile JSON that the agent uses for anomaly detection.

Run this FIRST on any machine you want to monitor:
    python collect_baseline.py

It will exit automatically after 7 days and produce: data/baseline_profile.json
"""
import psutil
import win32evtlog
import win32api
import win32clipboard
import json
import logging
import os
import time
from datetime import datetime, timedelta

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - BASELINE - %(message)s',
    handlers=[
        logging.FileHandler('../data/baseline_collector.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

BASELINE_DAYS = 7
OUTPUT_PATH = '../data/baseline_profile.json'
SAMPLE_INTERVAL = 60  # seconds between samples

class BaselineCollector:
    def __init__(self):
        self.login_hours = []
        self.daily_bytes_sent = []
        self.daily_clipboard_bytes = []
        self.daily_file_accesses = []
        self.start_time = datetime.now()
        self.current_day_data = self._new_day_data()

    def _new_day_data(self):
        return {
            'date': datetime.now().date().isoformat(),
            'login_hours': [],
            'bytes_sent': 0,
            'clipboard_bytes': 0,
            'file_accesses': 0,
        }

    def _collect_sample(self):
        """Collect a single data point."""
        now = datetime.now()

        # Track current hour (are we actively using computer?)
        hour = now.hour
        if hour not in self.current_day_data['login_hours']:
            self.current_day_data['login_hours'].append(hour)

        # Network bytes sent today
        net = psutil.net_io_counters()
        self.current_day_data['bytes_sent'] = net.bytes_sent

        # Clipboard size
        try:
            win32clipboard.OpenClipboard()
            clip_size = 0
            for fmt in [1, 13]:
                try:
                    data = win32clipboard.GetClipboardData(fmt)
                    clip_size = max(clip_size, len(data.encode('utf-8') if isinstance(data, str) else data))
                except Exception:
                    pass
            win32clipboard.CloseClipboard()
            self.current_day_data['clipboard_bytes'] = max(
                self.current_day_data['clipboard_bytes'], clip_size
            )
        except Exception:
            try:
                win32clipboard.CloseClipboard()
            except Exception:
                pass

    def _save_day(self):
        """Archive current day and start a new one."""
        logger.info(f"Day complete: {self.current_day_data}")
        self.login_hours.append(self.current_day_data['login_hours'])
        self.daily_bytes_sent.append(self.current_day_data['bytes_sent'])
        self.daily_clipboard_bytes.append(self.current_day_data['clipboard_bytes'])
        self.daily_file_accesses.append(self.current_day_data['file_accesses'])
        self.current_day_data = self._new_day_data()

    def _build_profile(self):
        """Compute statistics from 7 days of data."""
        all_hours = [h for day in self.login_hours for h in day]
        hour_counts = {}
        for h in all_hours:
            hour_counts[h] = hour_counts.get(h, 0) + 1

        normal_hours = [h for h, count in hour_counts.items() if count >= 2]

        avg_upload_mb = (sum(self.daily_bytes_sent) / len(self.daily_bytes_sent)) / (1024 * 1024) if self.daily_bytes_sent else 100
        avg_clipboard_mb = (sum(self.daily_clipboard_bytes) / len(self.daily_clipboard_bytes)) / (1024 * 1024) if self.daily_clipboard_bytes else 5
        avg_file_accesses = sum(self.daily_file_accesses) / len(self.daily_file_accesses) if self.daily_file_accesses else 50

        profile = {
            'generated_at': datetime.now().isoformat(),
            'days_monitored': BASELINE_DAYS,
            'normal_login_hours': sorted(normal_hours),
            'avg_daily_upload_mb': round(avg_upload_mb, 2),
            'avg_daily_clipboard_mb': round(avg_clipboard_mb, 2),
            'avg_daily_file_accesses': round(avg_file_accesses, 1),
            # Alert thresholds = 3x the normal baseline
            'thresholds': {
                'max_upload_mb_per_day': round(avg_upload_mb * 3, 2),
                'max_upload_mb_per_min': round(max(avg_upload_mb * 0.1, 50), 2),
                'max_clipboard_mb_per_day': round(avg_clipboard_mb * 3, 2),
                'max_single_clipboard_mb': round(max(avg_clipboard_mb * 0.5, 10), 2),
                'max_files_per_min': max(int(avg_file_accesses * 3), 30),
                'alert_outside_hours': True
            }
        }
        return profile

    def run(self):
        logger.info(f"Baseline collection started. Will run for {BASELINE_DAYS} days.")
        logger.info("Do NOT close this window. It runs silently in the background.")

        end_time = self.start_time + timedelta(days=BASELINE_DAYS)
        last_day = self.start_time.date()

        os.makedirs('../data', exist_ok=True)

        while datetime.now() < end_time:
            try:
                self._collect_sample()

                today = datetime.now().date()
                if today != last_day:
                    self._save_day()
                    last_day = today
                    logger.info(f"Day {(datetime.now() - self.start_time).days + 1}/{BASELINE_DAYS} complete.")

            except Exception as e:
                logger.error(f"Baseline sample error: {e}")

            time.sleep(SAMPLE_INTERVAL)

        # Save final day
        self._save_day()

        # Build and save profile
        profile = self._build_profile()
        with open(OUTPUT_PATH, 'w') as f:
            json.dump(profile, f, indent=2)

        logger.info(f"Baseline collection COMPLETE! Profile saved to {OUTPUT_PATH}")
        logger.info(f"Normal hours: {profile['normal_login_hours']}")
        logger.info(f"Avg upload: {profile['avg_daily_upload_mb']:.1f} MB/day")
        return profile

if __name__ == "__main__":
    collector = BaselineCollector()
    collector.run()
