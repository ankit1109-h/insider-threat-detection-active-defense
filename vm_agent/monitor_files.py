"""
monitor_files.py
Monitors Windows Security Event Log for bulk file access patterns.
Detects:
- Bulk file access (many files in short time)
- Cross-department folder access
- File deletion sprees
- Large file movements
"""
import win32evtlog
import threading
import logging
import time
import json
import os
from datetime import datetime
from collections import defaultdict, deque

logger = logging.getLogger(__name__)

# Thresholds (updated by baseline)
BULK_FILE_THRESHOLD = 30       # Flag if >30 files accessed in 1 minute
BULK_DELETE_THRESHOLD = 10     # Flag if >10 files deleted in 1 minute
ACCESS_WINDOW_SECONDS = 60     # 1-minute rolling window

# Cross-department folder policy — loaded dynamically from access_policy.json
# Maps folder keyword → allowed role(s)
# This is the DEFAULT fallback if access_policy.json not found
_DEFAULT_RESTRICTED_PATHS = {
    "Finance_Data":     ["Finance"],
    "HR_Records":       ["Human Resources"],
    "Engineering_Code": ["Engineering"],
}

def load_access_policy(policy_path=None):
    """
    Loads access_policy.json and returns a dict:
      { folder_name: [allowed_role1, allowed_role2, ...] }
    """
    candidates = []
    if policy_path:
        candidates.append(policy_path)
    # Auto-discover from common locations
    _here = os.path.dirname(os.path.abspath(__file__))
    candidates += [
        os.path.join(_here, '..', 'config', 'access_policy.json'),
        os.path.join(os.getcwd(), 'config', 'access_policy.json'),
    ]
    for path in candidates:
        try:
            with open(os.path.normpath(path)) as f:
                raw = json.load(f)
            policy = {}
            for folder, info in raw.items():
                roles = info.get('allowed_roles', info) if isinstance(info, dict) else [info]
                policy[folder] = roles
            logger.info(f"Access policy loaded: {len(policy)} folders from {path}")
            return policy
        except Exception:
            continue
    logger.warning("access_policy.json not found — using default restricted paths.")
    return _DEFAULT_RESTRICTED_PATHS


def compute_user_restrictions(user_role: str, clearance_level: str = 'medium',
                               policy: dict = None) -> dict:
    """
    Returns dict of paths that are RESTRICTED for this user.
    Format: { folder_name: [allowed_roles] }

    Logic:
      - Administrator OR clearance_level=='high' → NO restrictions (full access)
      - Others → restricted to paths where their role is NOT in allowed_roles
    """
    if policy is None:
        policy = load_access_policy()

    # Administrator or high clearance → access to everything, skip all monitoring
    if user_role == 'Administrator' or clearance_level == 'high':
        logger.info(f"User role='{user_role}' clearance='{clearance_level}': Full access — no path restrictions.")
        return {}   # Empty dict = no restrictions

    # Compute paths restricted for this user (paths where their role is NOT listed)
    restricted = {}
    for folder, allowed_roles in policy.items():
        if user_role not in allowed_roles:
            restricted[folder] = allowed_roles
            logger.info(f"  Restricted for '{user_role}': {folder} (allowed: {allowed_roles})")

    return restricted

# Default: will be overridden by FileMonitor with per-user restrictions
RESTRICTED_PATHS = _DEFAULT_RESTRICTED_PATHS

# System/machine accounts to IGNORE (not real human users)
# Machine accounts end with '$' (e.g. JERRY$, DESKTOP-ABC$)
IGNORED_USER_SUFFIXES = ('$',)
IGNORED_USERS = {
    'SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE',
    'ANONYMOUS LOGON', 'DWM-1', 'DWM-2', 'DWM-3',
    'UMFD-0', 'UMFD-1', 'UMFD-2', 'WINDOW MANAGER',
}

# System paths to IGNORE — only flag sensitive business folders
SYSTEM_PATH_PREFIXES = (
    'c:\\windows\\',
    'c:\\program files',
    'c:\\programdata',
    'c:\\users\\all users',
    '\\device\\',
    'c:\\system',
)

def _is_ignored_user(username):
    """Returns True if this is a machine/system account, not a human user."""
    if not username:
        return True
    if username.upper() in IGNORED_USERS:
        return True
    if username.endswith('$'):  # Machine accounts like JERRY$, DESKTOP-ABC$
        return True
    return False

def _is_system_path(path):
    """Returns True if this is a Windows system path (not a sensitive business folder)."""
    if not path:
        return True
    path_lower = path.lower()
    for prefix in SYSTEM_PATH_PREFIXES:
        if path_lower.startswith(prefix):
            return True
    return False

# Path to employee_config.json (username -> role), relative to this file
EMPLOYEE_CONFIG_PATH = os.path.join(
    os.path.dirname(__file__), "..", "config", "employee_config.json"
)

class FileMonitor:
    def __init__(self, event_callback, user_role="Unknown",
                 restricted_paths=None):
        self.callback = event_callback
        self.default_user_role = user_role
        # Per-user restricted paths: { folder: [allowed_roles] }
        # Empty dict = no restrictions (Administrator / high clearance)
        self.restricted_paths = restricted_paths if restricted_paths is not None \
                                else load_access_policy()
        self._stop_event = threading.Event()
        self.recent_accesses = defaultdict(deque)
        self.recent_deletes = defaultdict(deque)
        self.last_cross_dept_alert = defaultdict(float)
        self.user_role_map = self._load_user_role_map()
        if self.restricted_paths:
            logger.info(f"FileMonitor: {len(self.restricted_paths)} restricted folder(s) for role '{user_role}'")
        else:
            logger.info(f"FileMonitor: No path restrictions for role '{user_role}' (full access)")

    def _load_user_role_map(self):
        """Loads {username: role} from employee_config.json.
        New users not in config get 'Employee' role (monitored but not blocked)."""
        candidate_paths = [
            os.path.normpath(os.path.join(os.path.abspath(os.path.dirname(__file__)), '..', 'config', 'employee_config.json')),
            os.path.normpath(os.path.join(os.getcwd(), '..', 'config', 'employee_config.json')),
            os.path.normpath(os.path.join(os.getcwd(), 'config', 'employee_config.json')),
        ]
        for config_path in candidate_paths:
            try:
                with open(config_path, 'r') as f:
                    config = json.load(f)
                role_map = {u.lower(): info.get('role', 'Employee') for u, info in config.items()}
                logger.info(f"User role map loaded: {len(role_map)} users from employee_config.json")
                return role_map
            except Exception:
                continue
        logger.warning("employee_config.json not found — all unknown users default to 'Employee' role.")
        return {}

    def _resolve_role(self, event, strings):
        """Resolves the role of the user who actually generated this event.
        Returns (None, None) for machine/system accounts to signal skip."""
        try:
            if len(strings) > 1 and strings[1]:
                username = strings[1]
                # Silently skip machine accounts (JERRY$, SYSTEM, etc.)
                if _is_ignored_user(username):
                    return None, None
                role = self.user_role_map.get(username.lower())
                if role:
                    return role, username
                # Human user but not in config - still track them
                return 'Unknown', username
        except Exception as e:
            logger.error(f"Could not resolve user/role: {e}")
        return self.default_user_role, 'Unknown'

    def start(self):
        thread = threading.Thread(target=self._monitor_loop, daemon=True)
        thread.start()
        logger.info("File Monitor started.")

    def stop(self):
        self._stop_event.set()

    def _purge_old_events(self, username):
        now = datetime.now()
        accesses = self.recent_accesses[username]
        deletes = self.recent_deletes[username]
        while accesses and (now - accesses[0][0]).total_seconds() > ACCESS_WINDOW_SECONDS:
            accesses.popleft()
        while deletes and (now - deletes[0][0]).total_seconds() > ACCESS_WINDOW_SECONDS:
            deletes.popleft()

    def _check_cross_department(self, object_name, role):
        """Returns (folder, allowed_roles) if this user is accessing a restricted path.
        Returns (None, None) if access is allowed or no restrictions configured."""
        if not self.restricted_paths:
            return None, None   # No restrictions for this user (Administrator / high clearance)
        for folder, allowed_roles in self.restricted_paths.items():
            if folder.lower() in object_name.lower():
                # Normalize allowed_roles to always be a list
                roles_list = allowed_roles if isinstance(allowed_roles, list) else [allowed_roles]
                if role not in roles_list and role not in ('Unknown', 'Employee'):
                    return folder, roles_list
        return None, None

    def _monitor_loop(self):
        server = 'localhost'
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

        logger.info("File monitor watching Security event log...")
        
        last_record = None

        while not self._stop_event.is_set():
            try:
                handle = win32evtlog.OpenEventLog(server, 'Security')
                events = win32evtlog.ReadEventLog(handle, flags, 0)
                if events:
                    if last_record is None:
                        last_record = events[0].RecordNumber
                    else:
                        for event in reversed(events):
                            if event.RecordNumber <= last_record:
                                continue
                            last_record = event.RecordNumber
                            
                            event_id = int(event.EventID & 0xFFFF)

                            # 4663 = File access, 4656 = Handle request, 4660 = Object deleted
                            if event_id in [4663, 4656, 4660]:
                                now = datetime.now()
                                strings = list(event.StringInserts) if event.StringInserts else []
                                object_name = strings[6] if len(strings) > 6 else ""

                                # Resolve role from THIS event's actual user
                                role, username = self._resolve_role(event, strings)

                                # Skip machine/system accounts (returns None, None)
                                if username is None:
                                    continue

                                # ── FILTER: skip machine accounts & system paths ──
                                if _is_ignored_user(username):
                                    continue  # JERRY$, SYSTEM, etc. → skip silently
                                if _is_system_path(object_name):
                                    continue  # C:\Windows\... → skip silently
                                # ─────────────────────────────────────────────────

                                if event_id == 4660:
                                    self.recent_deletes[username].append((now, object_name))
                                elif event_id == 4663:
                                    self.recent_accesses[username].append((now, object_name))
                                    self.callback({
                                        'type': 'FILE_COPY_ACCESS_ACTIVITY',
                                        'object': object_name,
                                        'user': username,
                                        'risk_factor': 'low',
                                        'description': f'File access: {username} accessed {object_name}'
                                    })

                                self._purge_old_events(username)

                                # Cross-department check
                                folder, allowed_role = self._check_cross_department(object_name, role)
                                if folder and event_id == 4656:
                                    now_ts = time.time()
                                    alert_key = (username, folder)
                                    if now_ts - self.last_cross_dept_alert[alert_key] > 60:
                                        self.last_cross_dept_alert[alert_key] = now_ts
                                        logger.warning(f"Cross-dept access: {username} ({role}) accessing {folder}")
                                        self.callback({
                                            'type': 'CROSS_DEPARTMENT_ACCESS',
                                            'object': object_name,
                                            'user': username,
                                            'user_role': role,
                                            'restricted_folder': folder,
                                            'risk_factor': 'high',
                                            'description': f'Unauthorized: {username} ({role}) accessed {folder} (only {allowed_role} allowed)'
                                        })

                                # Bulk file access check
                                if len(self.recent_accesses[username]) >= BULK_FILE_THRESHOLD:
                                    logger.warning(f"Bulk file access: {username} accessed {len(self.recent_accesses[username])} files in 1 min")
                                    self.callback({
                                        'type': 'BULK_FILE_ACCESS',
                                        'user': username,
                                        'count': len(self.recent_accesses[username]),
                                        'risk_factor': 'high',
                                        'description': f'Bulk file access: {username} opened {len(self.recent_accesses[username])} files in 60s'
                                    })
                                    self.recent_accesses[username].clear()

                                # Bulk delete check
                                if len(self.recent_deletes[username]) >= BULK_DELETE_THRESHOLD:
                                    logger.warning(f"Bulk delete: {username} deleted {len(self.recent_deletes[username])} files")
                                    self.callback({
                                        'type': 'BULK_FILE_DELETE',
                                        'user': username,
                                        'count': len(self.recent_deletes[username]),
                                        'risk_factor': 'critical',
                                        'description': f'Mass deletion: {username} deleted {len(self.recent_deletes[username])} files in 60s!'
                                    })
                                    self.recent_deletes[username].clear()
                
                win32evtlog.CloseEventLog(handle)
            except Exception as e:
                logger.error(f"File monitor loop error: {e}")

            time.sleep(3)

    def update_thresholds(self, avg_files_per_min):
        global BULK_FILE_THRESHOLD
        BULK_FILE_THRESHOLD = max(int(avg_files_per_min * 3), 30)
        logger.info(f"File threshold updated: {BULK_FILE_THRESHOLD} files/min")