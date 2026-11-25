"""
agent.py - Unified Insider Threat Monitoring Agent
====================================================
Runs 5 monitors simultaneously in parallel threads:
  1. Windows Event Log   — Login (4624), Logoff (4634), File Access (4656/4663)
  2. USB Monitor         — Detects pendrive / removable drive insertions
  3. Clipboard Monitor   — Detects bulk copy-paste (data exfiltration via clipboard)
  4. Network Monitor     — Detects large uploads, personal cloud connections
  5. File Monitor        — Detects bulk file access, cross-department access, bulk deletes

DEPLOYMENT:
  - Edit config/agent_config.json on each machine:
      Set "server_url" to the IP of the machine running central_server.py
  - Run: python agent.py
  - Or install as Windows Service: deploy/install_service.ps1
"""
import win32evtlog
import win32security
import requests
import time
import json
import logging
import threading
import getpass
import socket
import os
import sys
from datetime import datetime

# Import sub-monitors
from monitor_usb import USBMonitor
from monitor_clipboard import ClipboardMonitor
from monitor_network import NetworkMonitor
from monitor_files import FileMonitor, compute_user_restrictions, load_access_policy
from monitor_cmd import CmdMonitor
import offline_buffer

_log_path = os.path.join(os.environ.get('TEMP', ''), 'agent.log')
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(_log_path),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ─── CONFIGURATION LOADER ────────────────────────────────────────────────────
COMPUTER_NAME = socket.gethostname()
CURRENT_USER  = getpass.getuser()

# Default fallback config (used if agent_config.json is unreachable)
_DEFAULT_CONFIG = {
    "server_url": "http://localhost:5000/ingest",
    "agent": {
        "poll_interval_seconds": 5,
        "thresholds": {
            "clipboard_single_copy_mb": 1,
            "clipboard_daily_limit_mb": 100,
            "usb_write_threshold_mb": 50,
            "bulk_file_access_count": 30,
        }
    },
    # No hardcoded employees — agent auto-detects current Windows user
    "restricted_paths": {
        "Finance_Data":     "Finance",
        "HR_Records":       "Human Resources",
        "Engineering_Code": "Engineering"
    }
}

def _load_config():
    """Loads agent_config.json from multiple candidate paths.
    Falls back to _DEFAULT_CONFIG if not found (e.g. on a fresh deployment)."""
    base_dir = getattr(sys, '_MEIPASS', os.path.abspath(os.path.dirname(__file__)))
    
    candidate_paths = [
        # PyInstaller bundled path
        os.path.join(base_dir, 'config', 'agent_config.json'),
        # Relative to this file's location (works on both Main PC and VM)
        os.path.normpath(os.path.join(os.path.abspath(os.path.dirname(__file__)), '..', 'config', 'agent_config.json')),
        # Relative to current working directory
        os.path.normpath(os.path.join(os.getcwd(), '..', 'config', 'agent_config.json')),
        os.path.normpath(os.path.join(os.getcwd(), 'config', 'agent_config.json')),
        # Same directory as agent.py (for standalone deployment)
        os.path.join(os.path.abspath(os.path.dirname(__file__)), 'agent_config.json'),
    ]
    for path in candidate_paths:
        try:
            with open(path, 'r') as f:
                config = json.load(f)
            logger.info(f"Config loaded from: {path}")
            return config
        except Exception:
            continue
    logger.warning("agent_config.json not found — using built-in defaults.")
    return _DEFAULT_CONFIG

CONFIG        = _load_config()

def _resolve_server_url(configured_url):
    """
    Auto-detects active server URL so the same agent binary runs on:
    1. Host PC (where http://localhost:5000 is available)
    2. Guest VM (where Host IP http://10.174.40.60:5000 is available)
    """
    candidates = []
    if configured_url:
        clean = configured_url.rstrip('/').replace('/ingest', '')
        if clean not in candidates:
            candidates.append(clean)
    if 'http://localhost:5000' not in candidates:
        candidates.append('http://localhost:5000')
    if 'http://127.0.0.1:5000' not in candidates:
        candidates.append('http://127.0.0.1:5000')
    if 'http://10.174.40.60:5000' not in candidates:
        candidates.append('http://10.174.40.60:5000')

    for candidate in candidates:
        try:
            res = requests.get(f"{candidate}/status", timeout=0.8)
            if res.status_code == 200:
                logger.info(f"Connected to Central Server at: {candidate}")
                return candidate
        except Exception:
            continue

    fallback = candidates[0] if candidates else 'http://localhost:5000'
    logger.warning(f"Central Server not reachable on any candidate, defaulting to: {fallback}")
    return fallback

SERVER_URL    = _resolve_server_url(CONFIG.get("server_url", "http://localhost:5000"))
API_KEY       = CONFIG.get("api_key", "")
INGEST_URL    = f"{SERVER_URL}/ingest"
UPLOAD_URL    = f"{SERVER_URL}/upload_screenshot"
HEARTBEAT_URL = f"{SERVER_URL}/heartbeat"
POLL_INTERVAL = CONFIG.get("agent", {}).get("poll_interval_seconds", 5)

# ── Maintenance Mode State ───────────────────────────────────────────────────
MAINTENANCE_MODE_ACTIVE = False

def update_maintenance_state(is_maint):
    global MAINTENANCE_MODE_ACTIVE
    if is_maint != MAINTENANCE_MODE_ACTIVE:
        MAINTENANCE_MODE_ACTIVE = is_maint
        if is_maint:
            logger.warning("🛠️ [MAINTENANCE MODE] Active — User lockout and blocking is DISABLED.")
        else:
            logger.info("🔴 [ARMED MODE] Active — Active defense lockout is ENABLED.")

# ── Auto-detect current Windows user & load their role from employee_config.json ──
def _load_user_info(username: str) -> dict:
    """
    Tries to load role & department for the current user from employee_config.json.
    Falls back to Employee/General if not found — no manual list needed.
    """
    emp_config_paths = [
        os.path.normpath(os.path.join(os.path.abspath(os.path.dirname(__file__)),
                                      '..', 'config', 'employee_config.json')),
        os.path.normpath(os.path.join(os.getcwd(), 'config', 'employee_config.json')),
    ]
    for path in emp_config_paths:
        try:
            with open(path, 'r') as f:
                emp_data = json.load(f)
            # employee_config.json has {"employees": [{"username":...,"role":...}]}
            employees = emp_data.get('employees', emp_data)  # handle both formats
            if isinstance(employees, list):
                for emp in employees:
                    if emp.get('username', '').lower() == username.lower():
                        return {'role': emp.get('role','Employee'),
                                'department': emp.get('department','General')}
            elif isinstance(employees, dict):
                if username in employees:
                    return employees[username]
        except Exception:
            continue
    return {'role': 'Employee', 'department': 'General'}

_user_info        = _load_user_info(CURRENT_USER)
CURRENT_USER_ROLE = _user_info.get('role', 'Employee')
CURRENT_USER_DEPT = _user_info.get('department', 'General')
CURRENT_CLEARANCE = _user_info.get('clearance_level', 'medium')

# Compute which paths are RESTRICTED for this user based on role + clearance
_ACCESS_POLICY      = load_access_policy()
USER_RESTRICTED_PATHS = compute_user_restrictions(
    user_role=CURRENT_USER_ROLE,
    clearance_level=CURRENT_CLEARANCE,
    policy=_ACCESS_POLICY
)

logger.info(f"Agent started  : user={CURRENT_USER}  role={CURRENT_USER_ROLE}  dept={CURRENT_USER_DEPT}  clearance={CURRENT_CLEARANCE}  computer={COMPUTER_NAME}")
if USER_RESTRICTED_PATHS:
    logger.info(f"Restricted folders for this user: {list(USER_RESTRICTED_PATHS.keys())}")
else:
    logger.info("No folder restrictions (Administrator / high clearance).")

# -----------------------------------------------------------------------------
# High-risk event types that should trigger a pre-capture screenshot
# BEFORE sending to server (so screenshot shows the actual threat activity,
# not whatever window is open when the server responds)
_HIGH_RISK_EVENT_TYPES = {
    'LARGE_CLIPBOARD_COPY',
    'CLIPBOARD_BURST',
    'EXCESSIVE_DAILY_CLIPBOARD',
    'DATA_COPIED_TO_USB',
    'BULK_FILE_DELETE',
    'UNAUTHORIZED_FILE_ACCESS_ATTEMPT',
    'CROSS_DEPARTMENT_ACCESS',
    'SUSPICIOUS_CMD',
    'HIGH_UPLOAD_BURST',
    'PERSONAL_CLOUD_CONNECTION',
    'BULK_FILE_ACCESS',
}

# Stores pre-captured screenshot bytes at detection time
_pre_captured_screenshot = None

def _grab_screenshot_bytes():
    """Capture current screen and return BytesIO object, or None on failure."""
    try:
        from PIL import ImageGrab
        import io
        img = ImageGrab.grab()
        buf = io.BytesIO()
        img.save(buf, format='PNG', optimize=True)
        buf.seek(0)
        return buf
    except Exception as e:
        logger.error(f"Pre-capture screenshot failed: {e}")
        return None

def capture_and_upload_screenshot():
    """Upload screenshot. Uses pre-captured image if available (taken at detection time),
    otherwise takes a fresh screenshot now."""
    global _pre_captured_screenshot
    try:
        import io
        # Use the pre-captured screenshot if we have one (taken at detection time)
        if _pre_captured_screenshot is not None:
            img_byte_arr = _pre_captured_screenshot
            _pre_captured_screenshot = None  # clear after use
            img_byte_arr.seek(0)
            logger.info("Using pre-captured screenshot (taken at event detection time).")
        else:
            # Fallback: take screenshot now
            from PIL import ImageGrab
            screenshot = ImageGrab.grab()
            img_byte_arr = io.BytesIO()
            screenshot.save(img_byte_arr, format='PNG', optimize=True)
            img_byte_arr.seek(0)
            logger.info("Taking fresh screenshot now (no pre-capture available).")

        files = {'file': ('screenshot.png', img_byte_arr, 'image/png')}
        data = {'user': CURRENT_USER}
        headers = {'X-API-Key': API_KEY}

        res = requests.post(UPLOAD_URL, files=files, data=data, headers=headers, timeout=10)
        if res.status_code == 200:
            logger.info("Screenshot successfully captured and uploaded.")
    except ImportError:
        logger.error("Pillow library not installed. Cannot take screenshot.")
    except Exception as e:
        logger.error(f"Failed to capture/upload screenshot: {e}")

def block_user_action():
    """Takes a final screenshot, then logs off the user to stop the attack."""
    if MAINTENANCE_MODE_ACTIVE:
        logger.warning("BLOCK_USER requested but MAINTENANCE MODE is active. Skipping workstation lock.")
        return
    try:
        logger.warning("BLOCKING USER: Grabbing final screenshot before lock...")
        capture_and_upload_screenshot()
        
        logger.warning("BLOCKING USER: Locking workstation now!")
        import ctypes
        # Lock the workstation (does not close open apps, just requires password to unlock)
        ctypes.windll.user32.LockWorkStation()
    except Exception as e:
        logger.error(f"Failed to block user: {e}")

def send_to_server(payload):
    """Sends a JSON event payload to the Central Server.
    For high-risk event types, captures a screenshot BEFORE sending so the
    image shows the actual threat activity (not whatever window opens later)."""
    global _pre_captured_screenshot, SERVER_URL, INGEST_URL, UPLOAD_URL, HEARTBEAT_URL
    try:
        payload['agent_user'] = CURRENT_USER
        payload['computer']   = COMPUTER_NAME
        headers = {'X-API-Key': API_KEY}

        # Pre-capture screenshot at detection time for high-risk events
        event_type = payload.get('type', '')
        if event_type in _HIGH_RISK_EVENT_TYPES:
            logger.info(f"High-risk event [{event_type}]: pre-capturing screenshot at detection time.")
            _pre_captured_screenshot = _grab_screenshot_bytes()

        response = requests.post(INGEST_URL, json=payload, headers=headers, timeout=5)
        if response.status_code == 200:
            logger.debug(f"Event sent: {payload.get('type', payload.get('event_id', 'unknown'))}")
            
            # Check if server requested an action
            try:
                res_data = response.json()
                if 'maintenance_mode' in res_data:
                    update_maintenance_state(res_data['maintenance_mode'])

                action = res_data.get('action')
                if action == 'block_user':
                    if MAINTENANCE_MODE_ACTIVE:
                        logger.info("Server requested block_user, but MAINTENANCE MODE is active — block suppressed.")
                    else:
                        logger.warning("CRITICAL ALERT! Server requested USER BLOCK!")
                        threading.Thread(target=block_user_action, daemon=True).start()
                elif action == 'take_screenshot':
                    logger.warning("Critical alert triggered! Capturing screenshot...")
                    threading.Thread(target=capture_and_upload_screenshot, daemon=True).start()
            except Exception:
                pass
                
            return True
        else:
            logger.warning(f"Server returned {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        logger.error(f"Cannot reach Central Server, buffering locally: {e}")
        offline_buffer.save_event(payload)
        return False

def _buffer_retry_loop():
    """Background thread that periodically retries sending buffered events."""
    while True:
        try:
            pending_events = offline_buffer.get_pending_events(limit=50)
            if pending_events:
                sent_ids = []
                logger.info(f"Attempting to flush {len(pending_events)} buffered events...")
                for event_id, payload in pending_events:
                    try:
                        headers = {'X-API-Key': API_KEY}
                        response = requests.post(INGEST_URL, json=payload, headers=headers, timeout=3)
                        if response.status_code == 200:
                            sent_ids.append(event_id)
                    except requests.exceptions.RequestException:
                        break # Stop trying if server is still down
                
                if sent_ids:
                    offline_buffer.delete_events(sent_ids)
                    logger.info(f"Successfully flushed {len(sent_ids)} events.")
        except Exception as e:
            logger.error(f"Buffer retry loop error: {e}")
        
        time.sleep(10) # Check every 10 seconds

# ─── MONITOR CALLBACKS ────────────────────────────────────────────────────────
def on_usb_event(event):
    logger.warning(f"[USB] {event['description']}")
    send_to_server({
        'timestamp': datetime.now().isoformat(),
        'event_id': 20001,  # Custom: USB event
        'type': event['type'],
        'user': CURRENT_USER,
        'computer': COMPUTER_NAME,
        'risk_factor': event['risk_factor'],
        'event_data': event
    })

def on_clipboard_event(event):
    logger.warning(f"[CLIPBOARD] {event['description']}")
    send_to_server({
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'event_id': 20002,  # Custom: Clipboard event
        'type': event['type'],
        'user': CURRENT_USER,
        'computer': COMPUTER_NAME,
        'risk_factor': event['risk_factor'],
        'event_data': event
    })

def on_network_event(event):
    logger.warning(f"[NETWORK] {event['description']}")
    send_to_server({
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'event_id': 20003,  # Custom: Network event
        'type': event['type'],
        'user': CURRENT_USER,
        'computer': COMPUTER_NAME,
        'risk_factor': event['risk_factor'],
        'event_data': event
    })

def on_file_event(event):
    logger.warning(f"[FILES] {event['description']}")
    send_to_server({
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'event_id': 20004,  # Custom: File bulk event
        'type': event['type'],
        # Preserve the Security-log account such as HR_User or Finance_User.
        # CURRENT_USER is only the elevated account that runs agent.py.
        'user': event.get('user') or CURRENT_USER,
        'computer': COMPUTER_NAME,
        'risk_factor': event['risk_factor'],
        'event_data': event
    })

def on_cmd_event(event):
    logger.warning(f"[CMD] {event['description']}")
    send_to_server({
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'event_id': 20005,  # Custom: CMD event
        'type': event['type'],
        'user': event.get('user') or CURRENT_USER,
        'computer': COMPUTER_NAME,
        'risk_factor': event['risk_factor'],
        'event_data': event
    })

# ─── WINDOWS EVENT LOG MONITOR ────────────────────────────────────────────────
def parse_event(event):
    """Extracts relevant info from a Windows Security Event Log record."""
    try:
        computer = str(event.ComputerName)
        event_id = int(event.EventID & 0xFFFF)
        # Convert to clean IST 24-hour format: YYYY-MM-DD HH:MM:SS
        try:
            t = event.TimeGenerated
            time_generated = f"{t.year:04d}-{t.month:02d}-{t.day:02d} {t.hour:02d}:{t.minute:02d}:{t.second:02d}"
        except Exception:
            time_generated = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        strings = [str(s) for s in event.StringInserts] if event.StringInserts else []

        # event.Sid resolves to whoever WROTE the audit record (almost always
        # SYSTEM for Security-log entries) - not the actual user involved.
        # For logon events, the real account name is in StringInserts[5].
        user = CURRENT_USER
        if event_id == 4624 and len(strings) > 5:
            user = strings[5]
        elif event_id in (4634, 4647, 4656, 4663, 4660, 4800, 4801) and len(strings) > 1:
            user = strings[1]

        # Filter out machine/system accounts — only track real human users
        SYSTEM_ACCOUNTS = {
            'SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE', 'ANONYMOUS LOGON',
            'WINDOW MANAGER', 'DWM-1', 'DWM-2', 'DWM-3',
            'UMFD-0', 'UMFD-1', 'UMFD-2', 'UMFD-3',
        }
        if user.upper() in SYSTEM_ACCOUNTS or user.endswith('$') or not user:
            return None  # Silently skip — not a real human user

        # Map event ID to human-readable type
        event_types = {
            4624: 'USER_LOGON',
            4801: 'USER_LOGON',    # Unlock treated as Logon
            4800: 'USER_LOGOFF',   # Lock treated as Logoff
            4634: 'USER_LOGOFF',
            4647: 'USER_LOGOFF',
            4656: 'FILE_ACCESS_REQUEST',
            4663: 'FILE_ACCESS',
            4660: 'FILE_DELETED',
        }
        
        # Filter out noisy background services logons/logoffs (Keep only Interactive/Remote/Unlock)
        if event_id == 4624 and len(strings) > 8:
            if strings[8] not in ('2', '7', '10', '11'):
                return None
        elif event_id == 4634 and len(strings) > 4:
            if strings[4] not in ('2', '7', '10', '11'):
                return None

        return {
            'timestamp': time_generated,
            'event_id': event_id,
            'type': event_types.get(event_id, f'WINDOWS_EVENT_{event_id}'),
            'user': user,
            'computer': computer,
            'event_data': {'strings': strings}
        }
    except Exception as e:
        logger.error(f"Error parsing event: {e}")
        return None

def monitor_windows_events():
    """Polls Windows Security Event Log for new login and file access events."""
    server = 'localhost'
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    logger.info("Windows Event Log monitor started... (Fast-forwarding to newest logs)")
    
    last_record_number = None

    while True:
        try:
            handle = win32evtlog.OpenEventLog(server, 'Security')
            events = win32evtlog.ReadEventLog(handle, flags, 0)
            
            if events:
                if last_record_number is None:
                    # First run: just save the latest record number so we only process new events
                    last_record_number = events[0].RecordNumber
                else:
                    new_events = []
                    for event in events:
                        if event.RecordNumber <= last_record_number:
                            break
                        new_events.insert(0, event) # Reverse so they are chronological
                    
                    for event in new_events:
                        event_id = int(event.EventID & 0xFFFF)
                        if event_id in [4624, 4634, 4647, 4656, 4663, 4660, 4800, 4801]:
                            parsed = parse_event(event)
                            if parsed:
                                send_to_server(parsed)
                                
                    if new_events:
                        last_record_number = events[0].RecordNumber
                        
            win32evtlog.CloseEventLog(handle)
            time.sleep(POLL_INTERVAL)
        except Exception as e:
            logger.error(f"Event log monitor error: {e}")
            time.sleep(10)

# ─── MAIN ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    logger.info("=" * 60)
    logger.info(" Insider Threat Monitoring Agent — STARTED")
    logger.info(f" User: {CURRENT_USER} | Role: {CURRENT_USER_ROLE} | Dept: {CURRENT_USER_DEPT} | Machine: {COMPUTER_NAME}")
    logger.info(f" Server: {SERVER_URL}")
    logger.info("=" * 60)

    # Start all sub-monitors as background threads
    usb_monitor = USBMonitor(event_callback=on_usb_event)
    usb_monitor.start()

    clipboard_monitor = ClipboardMonitor(event_callback=on_clipboard_event)
    clipboard_monitor.start()

    network_monitor = NetworkMonitor(event_callback=on_network_event)
    network_monitor.start()

    file_monitor = FileMonitor(
        event_callback=on_file_event,
        user_role=CURRENT_USER_ROLE
    )
    file_monitor.start()

    cmd_monitor = CmdMonitor(event_callback=on_cmd_event)
    cmd_monitor.start()

    # Start buffer retry thread
    buffer_thread = threading.Thread(target=_buffer_retry_loop, daemon=True)
    buffer_thread.start()

    def _heartbeat_loop():
        global SERVER_URL, INGEST_URL, UPLOAD_URL, HEARTBEAT_URL
        while True:
            try:
                res = requests.post(HEARTBEAT_URL, json={'user': CURRENT_USER, 'computer': COMPUTER_NAME}, headers={'X-API-Key': API_KEY}, timeout=5)
                if res.status_code == 200:
                    data = res.json()
                    if 'maintenance_mode' in data:
                        update_maintenance_state(data['maintenance_mode'])
                else:
                    # Current URL failed, try to rediscover
                    new_url = _resolve_server_url(CONFIG.get("server_url"))
                    if new_url != SERVER_URL:
                        SERVER_URL = new_url
                        INGEST_URL = f"{SERVER_URL}/ingest"
                        UPLOAD_URL = f"{SERVER_URL}/upload_screenshot"
                        HEARTBEAT_URL = f"{SERVER_URL}/heartbeat"
            except Exception:
                try:
                    new_url = _resolve_server_url(CONFIG.get("server_url"))
                    if new_url != SERVER_URL:
                        SERVER_URL = new_url
                        INGEST_URL = f"{SERVER_URL}/ingest"
                        UPLOAD_URL = f"{SERVER_URL}/upload_screenshot"
                        HEARTBEAT_URL = f"{SERVER_URL}/heartbeat"
                except Exception:
                    pass
            time.sleep(30)

    heartbeat_thread = threading.Thread(target=_heartbeat_loop, daemon=True)
    heartbeat_thread.start()

    # Run Windows Event Log monitor on main thread
    monitor_windows_events()