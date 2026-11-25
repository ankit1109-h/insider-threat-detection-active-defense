"""
monitor_cmd.py
Monitors Windows Security Log (Event 4688 - Process Creation) 
and PowerShell Operational Log (Event 4104 - Script Block Logging).
Flags execution of suspicious commands (recon, data staging, powershell).
"""
import win32evtlog
import threading
import logging
import time
from datetime import datetime

logger = logging.getLogger(__name__)

# List of suspicious commands/patterns commonly used by insiders or attackers
SUSPICIOUS_PATTERNS = [
    'cmd.exe',
    'powershell.exe',
    'sc ',         # Catch sc.exe commands
    'sc.exe ',
    'ping ',
    'whoami',
    'net user',
    'net localgroup',
    'vssadmin delete shadows',
    'certutil -urlcache',
    'bitsadmin /transfer',
    'Invoke-Expression',
    'IEX ',
    'powershell -enc',
    'powershell.exe -ExecutionPolicy Bypass',
    'wmic useraccount',
    'fsutil fsinfo',
    'arp -a'
]

class CmdMonitor:
    def __init__(self, event_callback):
        self.callback = event_callback
        self._stop_event = threading.Event()

    def start(self):
        thread = threading.Thread(target=self._monitor_loop, daemon=True)
        thread.start()
        logger.info("CMD & PowerShell Monitor started.")

    def stop(self):
        self._stop_event.set()

    def _is_suspicious(self, command_line):
        if not command_line:
            return None
        cmd_lower = command_line.lower()
        for pattern in SUSPICIOUS_PATTERNS:
            if pattern.lower() in cmd_lower:
                return pattern
        return None

    def _monitor_loop(self):
        server = 'localhost'
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        
        sec_last_record = None
        ps_last_record = None

        while not self._stop_event.is_set():
            # Security Log
            try:
                sec_handle = win32evtlog.OpenEventLog(server, 'Security')
                events = win32evtlog.ReadEventLog(sec_handle, flags, 0)
                if events:
                    if sec_last_record is None:
                        sec_last_record = events[0].RecordNumber
                    else:
                        for event in reversed(events):
                            if event.RecordNumber <= sec_last_record:
                                continue
                            sec_last_record = event.RecordNumber
                            
                            if int(event.EventID & 0xFFFF) == 4688:
                                strings = list(event.StringInserts) if event.StringInserts else []
                                user = strings[1] if len(strings) > 1 else 'Unknown'
                                process_name = strings[5] if len(strings) > 5 else ''
                                cmd_line = strings[8] if len(strings) > 8 else process_name

                                pattern_matched = self._is_suspicious(cmd_line)
                                if pattern_matched:
                                    self._alert_suspicious(user, 'Process Creation', cmd_line, pattern_matched)
                win32evtlog.CloseEventLog(sec_handle)
            except Exception:
                pass

            # PowerShell Log
            try:
                ps_handle = win32evtlog.OpenEventLog(server, 'Microsoft-Windows-PowerShell/Operational')
                events = win32evtlog.ReadEventLog(ps_handle, flags, 0)
                if events:
                    if ps_last_record is None:
                        ps_last_record = events[0].RecordNumber
                    else:
                        for event in reversed(events):
                            if event.RecordNumber <= ps_last_record:
                                continue
                            ps_last_record = event.RecordNumber
                            
                            if int(event.EventID & 0xFFFF) == 4104:
                                strings = list(event.StringInserts) if event.StringInserts else []
                                script_text = strings[2] if len(strings) > 2 else ''
                                
                                pattern_matched = self._is_suspicious(script_text)
                                if pattern_matched:
                                    self._alert_suspicious('Unknown (PS Log)', 'PowerShell Script', script_text, pattern_matched)
                win32evtlog.CloseEventLog(ps_handle)
            except Exception:
                pass

            time.sleep(1)

    def _alert_suspicious(self, user, source, full_command, pattern):
        # Prevent firing alerts for the agent's own execution if any
        if 'vm_agent' in full_command.lower() or 'central_server' in full_command.lower():
            return
            
        # Truncate command if too long
        display_cmd = full_command[:200] + '...' if len(full_command) > 200 else full_command
        logger.warning(f"[SUSPICIOUS CMD] User: {user} | Pattern: {pattern} | Cmd: {display_cmd}")
        
        self.callback({
            'type': 'SUSPICIOUS_CMD',
            'user': user,
            'command': display_cmd,
            'source': source,
            'matched_pattern': pattern,
            'risk_factor': 'critical',
            'description': f"Suspicious command detected: '{pattern}'"
        })
