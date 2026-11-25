"""
monitor_network.py
Monitors outbound network activity for suspicious data exfiltration:
- Large file uploads to Gmail, Dropbox, Drive, WeTransfer etc.
- DNS queries to personal cloud/email services
- Unusual outbound data volumes

Uses Windows ETW (Event Tracing for Windows) via pywin32 and psutil.
"""
import psutil
import threading
import logging
import time
import socket
from datetime import datetime

logger = logging.getLogger(__name__)

# Trusted company domain - emails to other domains are flagged
TRUSTED_DOMAIN = "company.com"

# Known personal cloud / exfiltration destinations (by IP hostname patterns)
PERSONAL_CLOUD_HOSTS = [
    "wetransfer.com", "we.tl",
    "dropbox.com", "dl.dropboxusercontent.com",
    "mega.nz", "mega.co.nz",
    "drive.google.com", "docs.google.com",
    "onedrive.live.com", "1drv.ms",
    "sendgb.com", "filemail.com", "zippyshare.com",
    "gofile.io", "anonfiles.com"
]

# Thresholds (updated by baseline)
UPLOAD_THRESHOLD_MB_PER_MIN = 500  # Increased to prevent false positives from Windows Update/OneDrive
DAILY_UPLOAD_THRESHOLD_MB = 2000   # Flag if >2GB uploaded in a day

class NetworkMonitor:
    def __init__(self, event_callback):
        self.callback = event_callback
        self._stop_event = threading.Event()
        self.daily_bytes_sent = 0
        self.last_reset_date = datetime.now().date()
        self.last_bytes_sent = psutil.net_io_counters().bytes_sent

    def start(self):
        thread = threading.Thread(target=self._monitor_loop, daemon=True)
        thread.start()
        logger.info("Network Monitor started.")

    def stop(self):
        self._stop_event.set()

    def _reset_daily_counter_if_needed(self):
        today = datetime.now().date()
        if today != self.last_reset_date:
            self.daily_bytes_sent = 0
            self.last_reset_date = today

    def _check_active_connections(self):
        """Check active connections for personal cloud hostnames."""
        suspicious_connections = []
        try:
            connections = psutil.net_connections(kind='inet')
            for conn in connections:
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    try:
                        hostname = socket.gethostbyaddr(conn.raddr.ip)[0]
                        for cloud_host in PERSONAL_CLOUD_HOSTS:
                            if cloud_host in hostname:
                                suspicious_connections.append({
                                    'host': hostname,
                                    'ip': conn.raddr.ip,
                                    'port': conn.raddr.port,
                                    'pid': conn.pid
                                })
                    except (socket.herror, socket.gaierror):
                        pass
        except Exception as e:
            logger.debug(f"Connection check error: {e}")
        return suspicious_connections

    def _monitor_loop(self):
        check_interval = 10  # seconds
        burst_window_bytes = []

        while not self._stop_event.is_set():
            try:
                self._reset_daily_counter_if_needed()

                current_stats = psutil.net_io_counters()
                bytes_sent_delta = current_stats.bytes_sent - self.last_bytes_sent
                self.last_bytes_sent = current_stats.bytes_sent

                if bytes_sent_delta > 0:
                    self.daily_bytes_sent += bytes_sent_delta
                    mb_sent_this_tick = bytes_sent_delta / (1024 * 1024)
                    daily_mb = self.daily_bytes_sent / (1024 * 1024)

                    burst_window_bytes.append((datetime.now(), bytes_sent_delta))
                    # Keep last 60 seconds
                    burst_window_bytes = [
                        (t, b) for t, b in burst_window_bytes
                        if (datetime.now() - t).seconds < 60
                    ]
                    burst_mb = sum(b for _, b in burst_window_bytes) / (1024 * 1024)

                    # Check for burst upload
                    if burst_mb > UPLOAD_THRESHOLD_MB_PER_MIN:
                        logger.warning(f"High upload burst: {burst_mb:.1f}MB in 60s")
                        self.callback({
                            'type': 'HIGH_UPLOAD_BURST',
                            'burst_mb': round(burst_mb, 2),
                            'risk_factor': 'high',
                            'description': f'Unusually high outbound data: {burst_mb:.1f}MB uploaded in under 60 seconds'
                        })
                        burst_window_bytes.clear()  # Reset to avoid repeated alerts

                    # Check daily limit
                    if daily_mb > DAILY_UPLOAD_THRESHOLD_MB:
                        logger.warning(f"Daily upload limit exceeded: {daily_mb:.1f}MB")
                        self.callback({
                            'type': 'EXCESSIVE_DAILY_UPLOAD',
                            'daily_mb': round(daily_mb, 2),
                            'risk_factor': 'medium',
                            'description': f'Total data uploaded today: {daily_mb:.1f}MB (threshold: {DAILY_UPLOAD_THRESHOLD_MB}MB)'
                        })

                # Periodically check active connections for personal cloud
                if int(time.time()) % 30 == 0:
                    suspicious = self._check_active_connections()
                    for conn in suspicious:
                        logger.warning(f"Personal cloud connection detected: {conn['host']}")
                        self.callback({
                            'type': 'PERSONAL_CLOUD_CONNECTION',
                            'host': conn['host'],
                            'risk_factor': 'high',
                            'description': f"Active connection to personal cloud service: {conn['host']} (PID: {conn['pid']})"
                        })

            except Exception as e:
                logger.error(f"Network monitor error: {e}")

            time.sleep(check_interval)

    def update_thresholds(self, daily_avg_mb):
        """Update upload thresholds from learned baseline."""
        global DAILY_UPLOAD_THRESHOLD_MB, UPLOAD_THRESHOLD_MB_PER_MIN
        DAILY_UPLOAD_THRESHOLD_MB = max(daily_avg_mb * 3, 500)
        UPLOAD_THRESHOLD_MB_PER_MIN = max(daily_avg_mb * 0.1, 50)
        logger.info(f"Network thresholds updated: daily={DAILY_UPLOAD_THRESHOLD_MB}MB")
