"""
process_cert_data.py
====================
Processes the CERT Insider Threat Dataset v4.2 (pre-extracted per-user CSVs)
+ baseline_logs.csv (normal 9-to-5 behavior)
to produce a single labeled training CSV for the LSTM model.

Output: data/lstm_training_data.csv
Columns: login_hour, login_day_of_week, is_weekend, is_after_hours,
         session_duration_hrs, logins_per_day, label (0=normal, 1=threat)
"""

import glob
import pandas as pd
import os

# ── Paths ──────────────────────────────────────────────────────────────────────
CERT_DIR       = "data/cert_extracted"          # Pre-extracted by PowerShell
BASELINE_CSV   = "data/extracted_baseline/baseline_logs.csv"
OUTPUT_CSV     = "data/lstm_training_data.csv"

OFFICE_START   = 9   # 9 AM
OFFICE_END     = 19  # 7 PM

# ── Helper ─────────────────────────────────────────────────────────────────────
def extract_features_from_sessions(sessions, label):
    """
    sessions: list of dicts with keys: user, login_dt, logoff_dt (optional)
    Returns a DataFrame of feature rows.
    """
    rows = []
    # Group by user + date to compute logins_per_day
    day_counts = {}
    for s in sessions:
        key = (s['user'], s['login_dt'].date())
        day_counts[key] = day_counts.get(key, 0) + 1

    for s in sessions:
        dt = s['login_dt']
        login_hour        = dt.hour
        login_day_of_week = dt.weekday()          # 0=Mon, 6=Sun
        is_weekend        = 1 if login_day_of_week >= 5 else 0
        is_after_hours    = 1 if (login_hour < OFFICE_START or login_hour >= OFFICE_END) else 0

        # Session duration
        if s.get('logoff_dt'):
            delta = (s['logoff_dt'] - dt).total_seconds() / 3600.0
            session_duration_hrs = round(max(0.0, min(delta, 24.0)), 2)
        else:
            session_duration_hrs = 0.0   # unknown

        logins_per_day = day_counts.get((s['user'], dt.date()), 1)

        rows.append({
            'user':                 s['user'],
            'login_hour':           login_hour,
            'login_day_of_week':    login_day_of_week,
            'is_weekend':           is_weekend,
            'is_after_hours':       is_after_hours,
            'session_duration_hrs': session_duration_hrs,
            'logins_per_day':       logins_per_day,
            'label':                label
        })
    return pd.DataFrame(rows)


# ── 1. Process CERT dataset (label = 1 → insider threat) ──────────────────────
def process_cert(cert_dir):
    print(f"\n[CERT] Reading from {cert_dir}...")
    sessions = []

    # Read insiders.csv to get confirmed insider usernames
    insiders_path = os.path.join(cert_dir, "insiders.csv")
    insider_names = set()
    if os.path.exists(insiders_path):
        df_ins = pd.read_csv(insiders_path)
        insider_names = set(df_ins['user'].astype(str).str.strip())
        print(f"[CERT] {len(insider_names)} insider users: {sorted(insider_names)[:5]}...")

    # Process each per-user CSV file
    user_files = glob.glob(os.path.join(cert_dir, "r4.2-*.csv"))
    print(f"[CERT] Processing {len(user_files)} user files...")

    for fpath in sorted(user_files):
        with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        logon_events = []
        for line in content.splitlines():
            parts = line.strip().split(',')
            if len(parts) < 6:
                continue
            if parts[0].strip().lower() != 'logon':
                continue
            try:
                ts     = pd.to_datetime(parts[2].strip(), format='%m/%d/%Y %H:%M:%S')
                user   = parts[3].strip()
                action = parts[5].strip()  # 'Logon' or 'Logoff'
                logon_events.append({'ts': ts, 'user': user, 'action': action})
            except Exception:
                continue

        # Pair Logon → Logoff for session duration
        pending = {}
        for ev in sorted(logon_events, key=lambda x: x['ts']):
            u = ev['user']
            if ev['action'] == 'Logon':
                pending[u] = ev['ts']
            elif ev['action'] == 'Logoff' and u in pending:
                sessions.append({
                    'user': u,
                    'login_dt': pending.pop(u),
                    'logoff_dt': ev['ts']
                })
        # Unpaired logons
        for u, ts in pending.items():
            sessions.append({'user': u, 'login_dt': ts, 'logoff_dt': None})

    print(f"[CERT] Extracted {len(sessions)} insider sessions.")
    return extract_features_from_sessions(sessions, label=1)


# ── 2. Process baseline_logs.csv (label = 0 → normal) ─────────────────────────
def process_baseline(csv_path):
    print(f"\n[BASELINE] Reading {csv_path}...")
    df = pd.read_csv(csv_path)
    df['timestamp'] = pd.to_datetime(df['timestamp'], utc=True, errors='coerce')
    df = df.dropna(subset=['timestamp'])

    # Keep only successful logons and logoffs
    logon_df  = df[df['event_id'] == 4624].copy()
    logoff_df = df[df['event_id'] == 4634].copy()

    print(f"[BASELINE] {len(logon_df)} logon events, {len(logoff_df)} logoff events.")

    # Build sessions: match each logon to nearest logoff for same user
    sessions = []
    logon_df  = logon_df.sort_values('timestamp')
    logoff_df = logoff_df.sort_values('timestamp')

    # Simple approach: pair chronologically per user
    logoff_map = {}
    for _, row in logoff_df.iterrows():
        u = str(row['username']).strip()
        if u not in logoff_map:
            logoff_map[u] = []
        logoff_map[u].append(row['timestamp'].to_pydatetime().replace(tzinfo=None))

    for _, row in logon_df.iterrows():
        u = str(row['username']).strip()
        # Skip system/service accounts
        if u in ('', 'nan', 'SYSTEM') or u.endswith('$'):
            continue
        login_dt = row['timestamp'].to_pydatetime().replace(tzinfo=None)

        # Find the first logoff AFTER this logon for this user
        logoff_dt = None
        if u in logoff_map:
            future = [t for t in logoff_map[u] if t > login_dt]
            if future:
                logoff_dt = min(future)

        sessions.append({'user': u, 'login_dt': login_dt, 'logoff_dt': logoff_dt})

    print(f"[BASELINE] Built {len(sessions)} normal sessions.")
    return extract_features_from_sessions(sessions, label=0)


# ── 3. Combine + Save ──────────────────────────────────────────────────────────
def main():
    os.makedirs('data', exist_ok=True)

    df_cert     = process_cert(CERT_DIR)
    df_baseline = process_baseline(BASELINE_CSV)

    df_all = pd.concat([df_baseline, df_cert], ignore_index=True)
    df_all = df_all.drop(columns=['user'])   # user name is not a feature for LSTM

    print(f"\n[COMBINED] Total records : {len(df_all)}")
    print(f"           Normal (0)    : {(df_all['label'] == 0).sum()}")
    print(f"           Threat (1)    : {(df_all['label'] == 1).sum()}")
    print(f"           Features      : {[c for c in df_all.columns if c != 'label']}")

    df_all.to_csv(OUTPUT_CSV, index=False)
    print(f"\n[DONE] Training data saved to: {OUTPUT_CSV}")
    print("       Next step: run models/train_lstm_autoencoder.py")


if __name__ == "__main__":
    main()
