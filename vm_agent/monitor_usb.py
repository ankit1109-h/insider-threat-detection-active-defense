"""
monitor_usb.py
Detects USB/Removable drive insertions using polling fallback.
Also monitors data written TO the USB drive to catch data exfiltration.
"""
import threading
import logging
import time
import string
import os
import psutil

logger = logging.getLogger(__name__)

WRITE_THRESHOLD_MB = 50
WRITE_WINDOW_SECONDS = 120
CHECK_INTERVAL = 5

class USBMonitor:
    def __init__(self, event_callback):
        self.callback = event_callback
        self._stop_event = threading.Event()
        self.active_usb_drives = {}

    def start(self):
        thread = threading.Thread(target=self._monitor_loop, daemon=True)
        thread.start()
        logger.info("USB Monitor started.")

    def stop(self):
        self._stop_event.set()

    def _get_removable_drives(self):
        removable = set()
        try:
            import win32file
            all_drives = [f"{d}:\\" for d in string.ascii_uppercase]
            for drive in all_drives:
                try:
                    if win32file.GetDriveType(drive) == 2:
                        removable.add(drive)
                except Exception:
                    pass
        except Exception as e:
            logger.error(f"Drive scan error: {e}")
        return removable

    def _get_drive_label(self, drive):
        try:
            import win32api
            info = win32api.GetVolumeInformation(drive)
            return info[0] if info[0] else drive
        except Exception:
            return drive

    def _monitor_loop(self):
        seen_drives = self._get_removable_drives()
        for drive in seen_drives:
            self._start_write_monitor(drive)

        while not self._stop_event.is_set():
            try:
                current_drives = self._get_removable_drives()

                # Newly inserted drives
                for drive in current_drives - seen_drives:
                    label = self._get_drive_label(drive)
                    logger.warning(f"USB inserted: {drive} ({label})")
                    self.callback({
                        'type': 'USB_INSERTED',
                        'drive': drive,
                        'label': label,
                        'risk_factor': 'high',
                        'description': f'Removable drive inserted: {label} ({drive})'
                    })
                    self._start_write_monitor(drive)

                # Removed drives
                for drive in seen_drives - current_drives:
                    logger.info(f"USB removed: {drive}")
                    self._stop_write_monitor(drive)

                seen_drives = current_drives
            except Exception as e:
                logger.error(f"USB monitor error: {e}")

            time.sleep(CHECK_INTERVAL)

    def _start_write_monitor(self, drive):
        if drive not in self.active_usb_drives:
            monitor = USBWriteMonitor(drive, self.callback, self._stop_event)
            monitor.start()
            self.active_usb_drives[drive] = monitor

    def _stop_write_monitor(self, drive):
        if drive in self.active_usb_drives:
            self.active_usb_drives[drive].stop()
            del self.active_usb_drives[drive]


class USBWriteMonitor:
    """Monitors bytes written to a USB drive to detect data exfiltration."""
    def __init__(self, drive, event_callback, stop_event):
        self.drive = drive
        self.callback = event_callback
        self._stop_event = stop_event
        self._local_stop = threading.Event()

    def start(self):
        thread = threading.Thread(target=self._watch_loop, daemon=True)
        thread.start()

    def stop(self):
        self._local_stop.set()

    def _get_drive_used_bytes(self):
        try:
            return psutil.disk_usage(self.drive).used
        except Exception:
            return 0

    def _watch_loop(self):
        start_time = time.time()
        last_used = self._get_drive_used_bytes()
        write_history = []
        alerted = False

        while not self._local_stop.is_set() and not self._stop_event.is_set():
            try:
                current_used = self._get_drive_used_bytes()
                delta = current_used - last_used

                if delta > 0:
                    last_used = current_used
                    now_t = time.time()
                    write_history.append((now_t, delta))
                    write_history = [(t, b) for t, b in write_history
                                     if now_t - t < WRITE_WINDOW_SECONDS]
                    burst_mb = sum(b for _, b in write_history) / (1024 * 1024)

                    if burst_mb >= WRITE_THRESHOLD_MB and not alerted:
                        # Scan new files
                        new_files = []
                        try:
                            for root, _, files in os.walk(self.drive):
                                for fname in files:
                                    fpath = os.path.join(root, fname)
                                    try:
                                        if os.path.getmtime(fpath) >= start_time:
                                            new_files.append(fpath)
                                    except Exception:
                                        pass
                        except Exception:
                            pass

                        logger.warning(f"DATA COPY TO USB: {burst_mb:.1f}MB to {self.drive}")
                        self.callback({
                            'type': 'DATA_COPIED_TO_USB',
                            'drive': self.drive,
                            'burst_mb': round(burst_mb, 2),
                            'file_count': len(new_files),
                            'files_detected': new_files[:5],
                            'risk_factor': 'critical',
                            'description': (
                                f'Data exfiltration: {burst_mb:.1f}MB written to USB {self.drive} '
                                f'in {WRITE_WINDOW_SECONDS}s. {len(new_files)} files copied.'
                            )
                        })
                        alerted = True
                    elif burst_mb < 1:
                        alerted = False

            except Exception as e:
                logger.error(f"USB write monitor error: {e}")

            time.sleep(CHECK_INTERVAL)
