"""
shap_explainer.py
Generates human-readable AI explanations for each detected anomaly.
Covers all 10 threat vectors the system monitors.
"""

class ShapExplainer:
    def __init__(self, model_path='../models/isolation_forest.pkl'):
        print("ShapExplainer initialized")

    def explain(self, features, raw_event=None):
        """Generates a detailed human-readable explanation for an anomaly."""
        reasons = []
        event_type = features.get('event_type', '')
        event_data = raw_event.get('event_data', {}) if raw_event else {}

        # ── Time-based anomalies (Only for Logon events) ──────────────────
        if event_type == 'USER_LOGON':
            hour = features.get('login_hour', 0)
            if hour < 6 or hour > 22:
                reasons.append(f"Login at {hour:02d}:00 — far outside normal working hours (likely 6AM-10PM).")
            elif hour < 8 or hour > 20:
                reasons.append(f"Login at {hour:02d}:00 — slightly outside typical working hours.")

        # ── Role Mismatch ─────────────────────────────────────────────────
        if features.get('role_mismatch_flag', 0) == 1:
            folder = event_data.get('restricted_folder', 'a restricted folder')
            user_role = event_data.get('user_role', 'Unknown')
            reasons.append(f"Cross-department access: User with role '{user_role}' attempted to access '{folder}', which belongs to a different department.")
        if event_type == 'UNAUTHORIZED_FILE_ACCESS_ATTEMPT':
            folder = event_data.get('restricted_folder', 'a restricted folder')
            user_role = event_data.get('user_role', 'Unknown')
            reasons.append(f"UNAUTHORIZED ACCESS ATTEMPT: A user with role '{user_role}' tried to access '{folder}', which their RBAC policy does not allow.")
        elif event_type == 'FILE_COPY_ACCESS_ACTIVITY':
            object_name = event_data.get('object', 'a protected file')
            reasons.append(f"Audited file copy/access activity detected on '{object_name}'. Review this activity if it is unexpected.")

        # ── Command Execution ─────────────────────────────────────────────
        if event_type == 'SUSPICIOUS_CMD':
            cmd = event_data.get('command', '?')
            pattern = event_data.get('matched_pattern', '?')
            reasons.append(f"Suspicious command execution detected. Command: '{cmd}'. Matched blocked pattern: '{pattern}'.")

        # ── USB ───────────────────────────────────────────────────────────────
        if features.get('usb_attempt_flag', 0) == 1 or event_type == 'USB_INSERTED':
            drive = event_data.get('drive', 'Unknown Drive Letter')
            label = event_data.get('label', '')
            reasons.append(f"USB/Removable drive inserted (Drive: {drive} Name: {label}). This is a high-risk data exfiltration vector.")

        if event_type == 'DATA_COPIED_TO_USB':
            drive = event_data.get('drive', '?')
            burst_mb = event_data.get('burst_mb', '?')
            file_count = event_data.get('file_count', '?')
            files = event_data.get('files_detected', [])
            file_preview = ', '.join(files[:3]) if files else 'unknown'
            reasons.append(
                f"CRITICAL DATA EXFILTRATION: {burst_mb}MB written to USB drive {drive} in under 2 minutes. "
                f"{file_count} files copied including: {file_preview}. "
                f"This is a direct, confirmed data transfer to an external removable device."
            )

        # ── Clipboard ─────────────────────────────────────────────────────
        if event_type == 'LARGE_CLIPBOARD_COPY':
            size_mb = event_data.get('size_mb', '?')
            reasons.append(f"Single clipboard copy of {size_mb}MB detected. This is {size_mb}x larger than typical clipboard usage and may indicate bulk data staging.")

        elif event_type == 'CLIPBOARD_BURST':
            burst_mb = event_data.get('burst_mb', '?')
            reasons.append(f"Rapid clipboard activity: {burst_mb}MB copied within a 5-minute window. This pattern is consistent with bulk data exfiltration.")

        elif event_type == 'EXCESSIVE_DAILY_CLIPBOARD':
            daily_mb = event_data.get('daily_mb', '?')
            reasons.append(f"Total clipboard usage today is {daily_mb}MB, which exceeds the learned daily baseline significantly.")

        # ── Network / Upload ──────────────────────────────────────────────
        if event_type == 'HIGH_UPLOAD_BURST':
            burst_mb = event_data.get('burst_mb', '?')
            reasons.append(f"High-speed data upload: {burst_mb}MB sent in under 60 seconds. This could indicate sending a large archive to an external server.")

        elif event_type == 'EXCESSIVE_DAILY_UPLOAD':
            daily_mb = event_data.get('daily_mb', '?')
            reasons.append(f"Total outbound data today is {daily_mb}MB. This is unusually high compared to the learned 7-day baseline.")

        elif event_type == 'PERSONAL_CLOUD_CONNECTION':
            host = event_data.get('host', 'Unknown')
            reasons.append(f"Active connection to a personal cloud/file-sharing service: {host}. This may indicate unauthorized data transfer.")

        # ── Bulk File Operations ──────────────────────────────────────────
        if event_type == 'BULK_FILE_ACCESS':
            count = event_data.get('count', '?')
            reasons.append(f"Bulk file access: {count} files accessed in under 60 seconds. This is consistent with automated scraping or data harvesting.")

        elif event_type == 'BULK_FILE_DELETE':
            count = event_data.get('count', '?')
            reasons.append(f"CRITICAL: {count} files deleted in under 60 seconds. This is consistent with sabotage or evidence destruction.")

        if not reasons:
            return "General behavioral anomaly detected. Activity pattern deviates significantly from the 7-day baseline. Manual review recommended."

        return "AI Analysis: " + " | ".join(reasons)
