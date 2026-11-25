"""
monitor_clipboard.py
Tracks clipboard usage volume per session.
Flags if unusually large amounts of data are copied (potential bulk exfiltration).
Runs as a background thread inside the unified agent.
"""
import win32clipboard
import threading
import logging
import time
import os
from datetime import datetime

logger = logging.getLogger(__name__)

# Thresholds (will be overridden by baseline after 7 days)
DEFAULT_DAILY_LIMIT_MB = 100     # Flag if >100MB copied in a single day
DEFAULT_SINGLE_COPY_MB = 1       # Flag if a single copy operation is >1MB
SESSION_WINDOW_SECONDS = 300     # 5-minute window for burst detection

class ClipboardMonitor:
    def __init__(self, event_callback):
        self.callback = event_callback
        self._stop_event = threading.Event()
        self.daily_total_bytes = 0
        self.session_copies = []
        self.last_reset_date = datetime.now().date()

    def start(self):
        thread = threading.Thread(target=self._monitor_loop, daemon=True)
        thread.start()
        logger.info("Clipboard Monitor started.")

    def stop(self):
        self._stop_event.set()

    def _get_clipboard_size(self):
        """Returns size of clipboard content in bytes.
        Handles both text (CF_TEXT) and file copies (CF_HDROP)."""
        total_size = 0
        try:
            win32clipboard.OpenClipboard()

            # CF_HDROP = 15: Files copied in Windows Explorer (Ctrl+C)
            if win32clipboard.IsClipboardFormatAvailable(15):
                try:
                    file_list = win32clipboard.GetClipboardData(15)
                    if isinstance(file_list, tuple):
                        for path in file_list:
                            try:
                                if os.path.isfile(path):
                                    total_size += os.path.getsize(path)
                                elif os.path.isdir(path):
                                    for dirpath, dirs, files in os.walk(path):
                                        # Limit depth to 3 levels for speed
                                        depth = dirpath.replace(path, '').count(os.sep)
                                        if depth >= 3:
                                            dirs.clear()
                                        for f in files:
                                            try:
                                                total_size += os.path.getsize(
                                                    os.path.join(dirpath, f))
                                            except Exception:
                                                pass
                            except Exception:
                                pass
                except Exception:
                    pass

            # CF_UNICODETEXT = 13 / CF_TEXT = 1: Plain text copied
            if total_size == 0:
                for fmt in [1, 13]:
                    try:
                        if win32clipboard.IsClipboardFormatAvailable(fmt):
                            data = win32clipboard.GetClipboardData(fmt)
                            if isinstance(data, (str, bytes)):
                                total_size = max(total_size, len(
                                    data.encode('utf-8') if isinstance(data, str) else data
                                ))
                    except Exception:
                        pass

            win32clipboard.CloseClipboard()
        except Exception:
            try:
                win32clipboard.CloseClipboard()
            except Exception:
                pass
        return total_size

    def _reset_daily_counter_if_needed(self):
        today = datetime.now().date()
        if today != self.last_reset_date:
            self.daily_total_bytes = 0
            self.last_reset_date = today

    def _monitor_loop(self):
        last_size = 0
        while not self._stop_event.is_set():
            try:
                self._reset_daily_counter_if_needed()
                current_size = self._get_clipboard_size()

                if current_size > 0 and current_size != last_size:
                    size_mb = current_size / (1024 * 1024)
                    self.daily_total_bytes += current_size
                    daily_mb = self.daily_total_bytes / (1024 * 1024)

                    now = datetime.now()
                    self.session_copies.append((now, current_size))
                    self.session_copies = [
                        (t, s) for t, s in self.session_copies
                        if (now - t).seconds < SESSION_WINDOW_SECONDS
                    ]
                    burst_mb = sum(s for _, s in self.session_copies) / (1024 * 1024)

                    if size_mb > DEFAULT_SINGLE_COPY_MB:
                        logger.warning(f"Large single copy detected: {size_mb:.1f}MB")
                        self.callback({
                            'type': 'LARGE_CLIPBOARD_COPY',
                            'size_mb': round(size_mb, 2),
                            'risk_factor': 'high',
                            'description': f'Single clipboard copy of {size_mb:.1f}MB detected (threshold: {DEFAULT_SINGLE_COPY_MB}MB)'
                        })
                    elif daily_mb > DEFAULT_DAILY_LIMIT_MB:
                        logger.warning(f"Daily clipboard limit exceeded: {daily_mb:.1f}MB")
                        self.callback({
                            'type': 'EXCESSIVE_DAILY_CLIPBOARD',
                            'daily_mb': round(daily_mb, 2),
                            'risk_factor': 'medium',
                            'description': f'Total clipboard usage today: {daily_mb:.1f}MB'
                        })
                    elif burst_mb > DEFAULT_SINGLE_COPY_MB * 2:
                        logger.warning(f"Clipboard burst: {burst_mb:.1f}MB in 5 mins")
                        self.callback({
                            'type': 'CLIPBOARD_BURST',
                            'burst_mb': round(burst_mb, 2),
                            'risk_factor': 'medium',
                            'description': f'Rapid clipboard activity: {burst_mb:.1f}MB in 5 minutes'
                        })

                    last_size = current_size

            except Exception as e:
                logger.error(f"Clipboard monitor error: {e}")

            time.sleep(0.5)

    def update_thresholds(self, daily_limit_mb, single_copy_mb):
        global DEFAULT_DAILY_LIMIT_MB, DEFAULT_SINGLE_COPY_MB
        DEFAULT_DAILY_LIMIT_MB = daily_limit_mb * 3
        DEFAULT_SINGLE_COPY_MB = single_copy_mb * 3
        logger.info(f"Clipboard thresholds updated: daily={DEFAULT_DAILY_LIMIT_MB}MB, single={DEFAULT_SINGLE_COPY_MB}MB")
