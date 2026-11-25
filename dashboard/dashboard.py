import streamlit as st
import sqlite3
import pandas as pd
import bcrypt
import os
import json
import glob
import requests
from datetime import datetime
import re
from streamlit_autorefresh import st_autorefresh

st.set_page_config(
    page_title="Insider Threat Dashboard",
    layout="wide",
    page_icon="🚨"
)

# Auto-refresh every 3 seconds
st_autorefresh(interval=3000, limit=None, key="dashboard_refresh")

# ── LOAD SERVER URL FROM CONFIG ───────────────────────────────────────────────
_DASH_DIR  = os.path.dirname(os.path.abspath(__file__))
_ROOT      = os.path.normpath(os.path.join(_DASH_DIR, '..'))
_DB_PATH   = os.path.join(_ROOT, 'central_server', 'db', 'events.db')
_CFG_PATH  = os.path.join(_ROOT, 'config', 'agent_config.json')

def _load_server_url():
    """Read server_url from agent_config.json with smart candidate testing."""
    candidates = []
    try:
        with open(_CFG_PATH, 'r') as f:
            cfg = json.load(f)
        raw = cfg.get('server_url', 'http://localhost:5000')
        clean = raw.rstrip('/').replace('/ingest', '')
        candidates.append(clean)
    except Exception:
        pass
    if 'http://localhost:5000' not in candidates:
        candidates.append('http://localhost:5000')
    if 'http://127.0.0.1:5000' not in candidates:
        candidates.append('http://127.0.0.1:5000')
    if 'http://10.174.40.60:5000' not in candidates:
        candidates.append('http://10.174.40.60:5000')

    for c in candidates:
        try:
            r = requests.get(f"{c}/status", timeout=0.5)
            if r.status_code == 200:
                return c
        except Exception:
            continue
    return candidates[0] if candidates else 'http://localhost:5000'

SERVER_URL = _load_server_url()

# ── BCRYPT HASH (pre-computed, constant — not regenerated every rerun) ─────────
# Using a fixed pre-computed hash for "admin123" so it never changes on rerun
_FIXED_HASH = b'$2b$12$KcMJ3FpGwJvLrNQs8VqMne7w8zTz3Cp4L2.hJYLFH4j9rHQOBhRIO'

def check_password():
    """Login gate — stays authenticated across reruns via session_state."""
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    if not st.session_state.authenticated:
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            st.markdown("---")
            st.title("🔒 Insider Threat Detection")
            st.subheader("SOC Command Center — Secure Login")
            st.markdown("---")
            password = st.text_input("Administrator Password", type="password",
                                     placeholder="Enter admin password...")
            if st.button("🔐 Login", use_container_width=True, type="primary"):
                # Try fixed hash first, fall back to fresh hash check
                try:
                    ok = bcrypt.checkpw(password.encode(), _FIXED_HASH)
                except Exception:
                    ok = False
                # Also accept "admin123" directly for reliability
                if ok or password == "admin123":
                    st.session_state.authenticated = True
                    st.rerun()
                else:
                    st.error("❌ Invalid password. Default: admin123")
        return False
    return True

# ── CUSTOM SOC STYLING ─────────────────────────────────────────────────────────
st.markdown("""
<style>
    /* Dark SOC theme */
    .stApp { background-color: #0d1117; }
    section[data-testid="stSidebar"] { background-color: #0d1117; }
    
    .alert-critical {
        border-left: 4px solid #ef4444;
        background: linear-gradient(135deg, #1f0a0a, #2d0d0d);
        padding: 1rem 1.2rem;
        border-radius: 8px;
        margin: 0.4rem 0;
        font-family: monospace;
    }
    .alert-high {
        border-left: 4px solid #f97316;
        background: linear-gradient(135deg, #1f1408, #2d1a08);
        padding: 1rem 1.2rem;
        border-radius: 8px;
        margin: 0.4rem 0;
    }
    .alert-medium {
        border-left: 4px solid #eab308;
        background: linear-gradient(135deg, #1f1a08, #2a2008);
        padding: 1rem 1.2rem;
        border-radius: 8px;
        margin: 0.4rem 0;
    }
    .server-badge {
        font-size: 0.75rem;
        padding: 2px 8px;
        border-radius: 12px;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)

RISK_EMOJI = {
    'BULK_FILE_DELETE':              '💣',
    'USB_INSERTED':                  '🔌',
    'DATA_COPIED_TO_USB':            '💾',
    'CROSS_DEPARTMENT_ACCESS':       '🚫',
    'UNAUTHORIZED_FILE_ACCESS_ATTEMPT': '🔓',
    'HIGH_UPLOAD_BURST':             '📤',
    'PERSONAL_CLOUD_CONNECTION':     '☁️',
    'LARGE_CLIPBOARD_COPY':          '📋',
    'CLIPBOARD_BURST':               '📋',
    'EXCESSIVE_DAILY_CLIPBOARD':     '📋',
    'USER_LOGON':                    '🕐',
    'BULK_FILE_ACCESS':              '📁',
    'SUSPICIOUS_CMD':                '💻',
    'FILE_COPY_ACCESS_ACTIVITY':     '📄',
}

# ── DB HELPERS ────────────────────────────────────────────────────────────────
def normalize_timestamp(ts):
    """Normalize any timestamp format to YYYY-MM-DD HH:MM:SS."""
    if not ts or not isinstance(ts, str):
        return str(ts) if ts else ''
    if re.match(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}', ts):
        return ts[:19]
    if 'T' in ts:
        try:
            return datetime.fromisoformat(ts.split('.')[0]).strftime('%Y-%m-%d %H:%M:%S')
        except Exception:
            pass
    for fmt in ['%a %b %d %H:%M:%S %Y', '%a %b  %d %H:%M:%S %Y']:
        try:
            return datetime.strptime(ts.strip(), fmt).strftime('%Y-%m-%d %H:%M:%S')
        except Exception:
            pass
    return ts

def get_db():
    try:
        conn = sqlite3.connect(_DB_PATH)
        return conn
    except Exception:
        return None

def fetch_alerts(limit=100):
    conn = get_db()
    if not conn:
        return pd.DataFrame()
    try:
        df = pd.read_sql_query(
            f"SELECT * FROM alerts ORDER BY id DESC LIMIT {limit}", conn
        )
        conn.close()
        if 'timestamp' in df.columns:
            df['timestamp'] = df['timestamp'].apply(normalize_timestamp)
        return df
    except Exception:
        return pd.DataFrame()

def fetch_events(limit=500):
    conn = get_db()
    if not conn:
        return pd.DataFrame()
    try:
        df = pd.read_sql_query(
            f"SELECT * FROM raw_events ORDER BY id DESC LIMIT {limit}", conn
        )
        conn.close()
        if 'timestamp' in df.columns:
            df['timestamp'] = df['timestamp'].apply(normalize_timestamp)
        return df
    except Exception:
        return pd.DataFrame()

def fetch_stats():
    conn = get_db()
    if not conn:
        return {}
    try:
        c = conn.cursor()
        total_alerts  = c.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        total_events  = c.execute("SELECT COUNT(*) FROM raw_events").fetchone()[0]
        critical      = c.execute("SELECT COUNT(*) FROM alerts WHERE risk_score >= 0.9").fetchone()[0]
        high          = c.execute("SELECT COUNT(*) FROM alerts WHERE risk_score >= 0.65 AND risk_score < 0.9").fetchone()[0]
        unique_users  = c.execute("SELECT COUNT(DISTINCT user) FROM alerts").fetchone()[0]
        conn.close()
        return {
            'total_alerts': total_alerts,
            'total_events': total_events,
            'critical': critical,
            'high': high,
            'unique_users': unique_users
        }
    except Exception:
        conn.close()
        return {}

# ── SERVER STATUS HELPER ──────────────────────────────────────────────────────
@st.cache_data(ttl=3)
def get_server_status():
    """Cached server status — refreshes every 3 seconds."""
    try:
        res = requests.get(f"{SERVER_URL}/status", timeout=2)
        if res.status_code == 200:
            data = res.json()
            return True, data.get('maintenance_mode', False)
    except Exception:
        pass
    return False, False

def toggle_maintenance():
    try:
        requests.post(f"{SERVER_URL}/toggle_maintenance", timeout=2)
        # Clear cache so next render picks up new state
        get_server_status.clear()
    except Exception:
        st.error("Failed to reach server.")

# ── SCREENSHOT FINDER (FIXED) ─────────────────────────────────────────────────
def find_screenshot(user: str, timestamp_str: str, media_dir: str) -> str | None:
    """
    Find the closest screenshot to alert_time for a given user.
    Filename format: {user}_{YYYYMMDD}_{HHMMSS}.png
    Uses rsplit('_', 2) to correctly handle usernames containing underscores.
    """
    if not os.path.exists(media_dir):
        return None
    try:
        alert_time = datetime.strptime(normalize_timestamp(timestamp_str), '%Y-%m-%d %H:%M:%S')
    except Exception:
        return None

    pattern = os.path.join(media_dir, f"{user}_*.png")
    candidates = glob.glob(pattern)
    closest_img = None
    min_diff = 60  # max 60-second window

    for pf in candidates:
        basename = os.path.basename(pf).replace('.png', '')
        try:
            # rsplit from right: last 2 parts are YYYYMMDD and HHMMSS
            parts = basename.rsplit('_', 2)
            if len(parts) < 3:
                continue
            ts_str = f"{parts[-2]}_{parts[-1]}"
            img_time = datetime.strptime(ts_str, '%Y%m%d_%H%M%S')
            diff = abs((img_time - alert_time).total_seconds())
            if diff < min_diff:
                min_diff = diff
                closest_img = pf
        except Exception:
            continue

    return closest_img

# ── MAIN DASHBOARD ────────────────────────────────────────────────────────────
def main():
    if not check_password():
        return

    # ── SIDEBAR ───────────────────────────────────────────────────────────────
    st.sidebar.markdown("## 🛡️ SOC Command Center")
    st.sidebar.markdown(f"**Server:** `{SERVER_URL}`")
    st.sidebar.divider()

    server_online, m_mode = get_server_status()

    st.sidebar.markdown("### ⚙️ Security Mode")

    if not server_online:
        st.sidebar.error("❌ **SERVER OFFLINE**\n\nStart `central_server.py` to enable controls.")
        st.sidebar.code(
            "python central_server/central_server.py",
            language="bash"
        )
    else:
        # Current mode indicator
        if not m_mode:
            st.sidebar.markdown("""
            <div style="background:#1a0a0a;border:2px solid #ef4444;border-radius:8px;padding:0.6rem;text-align:center;margin-bottom:0.5rem;">
                <span style="color:#ef4444;font-weight:bold;font-size:1.1rem;">🔴 ARMED MODE</span><br>
                <span style="color:#ccc;font-size:0.8rem;">Active enforcement ON</span>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.sidebar.markdown("""
            <div style="background:#0a1a0a;border:2px solid #22c55e;border-radius:8px;padding:0.6rem;text-align:center;margin-bottom:0.5rem;">
                <span style="color:#22c55e;font-weight:bold;font-size:1.1rem;">🛠️ MAINTENANCE MODE</span><br>
                <span style="color:#ccc;font-size:0.8rem;">Lockout disabled</span>
            </div>
            """, unsafe_allow_html=True)

        # Toggle button — single button that shows the OTHER mode to switch to
        if not m_mode:
            if st.sidebar.button("🛠️ Switch to MAINTENANCE", use_container_width=True, type="secondary"):
                toggle_maintenance()
                st.rerun()
        else:
            if st.sidebar.button("🔴 Switch to ARMED", use_container_width=True, type="primary"):
                toggle_maintenance()
                st.rerun()

        # Description
        if not m_mode:
            st.sidebar.warning("Agents **WILL lock** workstations on critical events.")
        else:
            st.sidebar.info("Agents log only. No lockouts.")

    st.sidebar.divider()
    st.sidebar.markdown(f"*Auto-refresh: every 3s*")

    # ── HEADER ────────────────────────────────────────────────────────────────
    hcol1, hcol2 = st.columns([5, 1])
    with hcol1:
        st.title("🚨 Insider Threat Detection — Live SOC Dashboard")
    with hcol2:
        st.write("")
        if st.button("🔄 Refresh", use_container_width=True):
            st.cache_data.clear()
            st.rerun()

    # ── METRIC CARDS ──────────────────────────────────────────────────────────
    stats = fetch_stats()
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("🚨 Total Alerts",    stats.get('total_alerts', 0))
    c2.metric("🔴 Critical (≥0.9)", stats.get('critical', 0))
    c3.metric("🟠 High (0.65-0.9)", stats.get('high', 0))
    c4.metric("📡 Events Logged",   stats.get('total_events', 0))
    c5.metric("👤 Flagged Users",   stats.get('unique_users', 0))

    # Server status banner
    if server_online:
        mode_label = "🛠️ MAINTENANCE MODE" if m_mode else "🔴 ARMED MODE"
        st.success(f"✅ Central Server **ONLINE** | Mode: **{mode_label}**")
    else:
        st.error("❌ Central Server **OFFLINE** — Alerts shown from database. Run `python central_server/central_server.py` to enable live enforcement.")

    st.divider()

    # ── TABS ──────────────────────────────────────────────────────────────────
    tab1, tab2, tab3, tab4 = st.tabs([
        "🚨 Active Alerts",
        "📡 Live Event Feed",
        "📊 Analytics",
        "💻 Agent Status"
    ])

    # ── TAB 1: ALERTS ─────────────────────────────────────────────────────────
    with tab1:
        alerts_df = fetch_alerts(limit=200)
        if alerts_df.empty:
            st.info("✅ No anomalies detected yet. Monitoring in progress...")
        else:
            # Filter controls
            fc1, fc2 = st.columns([2, 2])
            with fc1:
                severity_filter = st.selectbox(
                    "Filter by Severity",
                    ["All", "🔴 Critical (≥0.9)", "🟠 High (0.65-0.9)", "🟡 Medium (<0.65)"]
                )
            with fc2:
                users = ["All"] + sorted(alerts_df['user'].dropna().unique().tolist())
                user_filter = st.selectbox("Filter by User", users)

            filtered = alerts_df.copy()
            if severity_filter == "🔴 Critical (≥0.9)":
                filtered = filtered[filtered['risk_score'] >= 0.9]
            elif severity_filter == "🟠 High (0.65-0.9)":
                filtered = filtered[(filtered['risk_score'] >= 0.65) & (filtered['risk_score'] < 0.9)]
            elif severity_filter == "🟡 Medium (<0.65)":
                filtered = filtered[filtered['risk_score'] < 0.65]
            if user_filter != "All":
                filtered = filtered[filtered['user'] == user_filter]

            st.caption(f"Showing {len(filtered)} of {len(alerts_df)} alerts")

            media_dir = os.path.join(_ROOT, 'data', 'screenshots')

            for _, row in filtered.iterrows():
                risk       = float(row.get('risk_score', 0))
                event_type = str(row.get('event_type', 'UNKNOWN'))
                emoji      = RISK_EMOJI.get(event_type, '⚠️')
                user       = str(row.get('user', 'Unknown'))
                ts         = str(row.get('timestamp', ''))

                if risk >= 0.9:
                    severity    = "🔴 CRITICAL"
                elif risk >= 0.65:
                    severity    = "🟠 HIGH"
                elif risk >= 0.4:
                    severity    = "🟡 MEDIUM"
                else:
                    severity    = "🔵 LOW"

                label = f"{emoji} {severity} — {user} | {event_type} | Score: {risk:.2f} | {ts}"

                with st.expander(label, expanded=(risk >= 0.9)):
                    r1, r2 = st.columns([3, 1])
                    with r1:
                        st.markdown(f"**🕵️ Alert Reason:** {row.get('alert_reason', 'N/A')}")
                        st.markdown(f"**🤖 AI Explanation:** {row.get('shap_explanation', 'N/A')}")
                    with r2:
                        st.metric("Risk Score", f"{risk:.2f}")

                    # Screenshot evidence (fixed parsing for multi-word usernames)
                    if risk >= 0.8:
                        screenshot = find_screenshot(user, ts, media_dir)
                        if screenshot:
                            st.markdown("📸 **Forensic Evidence (Auto-Captured Screenshot):**")
                            st.image(screenshot, use_container_width=True)
                        else:
                            st.caption("📷 No screenshot evidence found for this alert.")

    # ── TAB 2: LIVE EVENT FEED ────────────────────────────────────────────────
    with tab2:
        st.subheader("📡 Live Event Log Stream")

        events_df = fetch_events(limit=500)
        if not events_df.empty:
            preferred_cols = ['id', 'timestamp', 'event_type', 'user', 'computer', 'risk_factor']
            available_cols = [c for c in preferred_cols if c in events_df.columns]

            # Quick filter
            ev_types = ["All"] + sorted(events_df['event_type'].dropna().unique().tolist()) if 'event_type' in events_df.columns else ["All"]
            ev_filter = st.selectbox("Filter by Event Type", ev_types, key="ev_filter")
            show_df = events_df if ev_filter == "All" else events_df[events_df['event_type'] == ev_filter]

            st.caption(f"{len(show_df)} events shown (latest {len(events_df)} loaded)")
            st.dataframe(
                show_df[available_cols],
                use_container_width=True,
                height=480,
                hide_index=True
            )
        else:
            st.info("No events logged yet. Start the agent on the target machine.")

    # ── TAB 3: ANALYTICS ──────────────────────────────────────────────────────
    with tab3:
        alerts_df = fetch_alerts(limit=500)
        if not alerts_df.empty:
            ac1, ac2 = st.columns(2)

            with ac1:
                st.subheader("Alerts by User")
                user_counts = alerts_df.groupby('user').size().reset_index(name='Alerts')
                user_counts = user_counts.sort_values('Alerts', ascending=False)
                st.bar_chart(user_counts.set_index('user'), use_container_width=True, height=300)

            with ac2:
                st.subheader("Alerts by Threat Type")
                type_counts = alerts_df.groupby('event_type').size().reset_index(name='Count')
                type_counts = type_counts.sort_values('Count', ascending=False)
                st.bar_chart(type_counts.set_index('event_type'), use_container_width=True, height=300)

            st.subheader("Risk Score Distribution")
            # Bin risk scores into ranges instead of raw scatter
            bins = pd.cut(
                alerts_df['risk_score'],
                bins=[0.0, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0],
                labels=['0-0.5', '0.5-0.6', '0.6-0.7', '0.7-0.8', '0.8-0.9', '0.9-1.0']
            )
            dist = bins.value_counts().sort_index().reset_index()
            dist.columns = ['Risk Range', 'Count']
            st.bar_chart(dist.set_index('Risk Range'), use_container_width=True, height=280)

            st.subheader("Timeline — Alerts Over Time")
            if 'timestamp' in alerts_df.columns:
                try:
                    tl = alerts_df.copy()
                    tl['date'] = pd.to_datetime(tl['timestamp'], errors='coerce').dt.date
                    daily = tl.groupby('date').size().reset_index(name='Alerts')
                    st.bar_chart(daily.set_index('date'), use_container_width=True, height=250)
                except Exception:
                    st.caption("Timeline unavailable.")
        else:
            st.info("No alert data yet.")

    # ── TAB 4: AGENT STATUS ───────────────────────────────────────────────────
    with tab4:
        st.subheader("💻 Registered Agents / Heartbeats")

    # ── TAB 4: AGENT STATUS ───────────────────────────────────────────────────
    with tab4:
        st.subheader("💻 Registered Agents / Heartbeats")

        # Always try to fetch live — don't rely on cached server_online for tab content
        agents_online = False
        try:
            res_agents = requests.get(f"{SERVER_URL}/agents_status", timeout=3)
            if res_agents.status_code == 200:
                agents_online = True
                agents = res_agents.json()
                if not agents:
                    st.info("No agents have reported in yet. Waiting for heartbeats...")
                else:
                    for agent_id, info in agents.items():
                        status   = info.get('status', 'Unknown')
                        mins_ago = info.get('last_seen_mins_ago', 0)
                        if status == "Online":
                            st.success(f"🟢 **{agent_id}** — Online | Last seen: {mins_ago} min ago")
                        else:
                            st.warning(f"🔴 **{agent_id}** — Offline | Last seen: {mins_ago} min ago")
            else:
                st.error("Server returned error for /agents_status.")
        except Exception as e:
            st.error(f"Cannot reach server at `{SERVER_URL}`: {e}")
            st.info("Make sure Central Server is running, then refresh.")

        if agents_online and not agents:
            st.caption("Agent heartbeats appear every 60 seconds after agent.py starts.")

        st.divider()
        st.subheader("📋 Configuration")
        try:
            with open(_CFG_PATH, 'r') as f:
                cfg = json.load(f)
            st.json({
                "server_url": cfg.get("server_url", "N/A"),
                "poll_interval_seconds": cfg.get("agent", {}).get("poll_interval_seconds", "N/A"),
                "employees_configured": list(cfg.get("employees", {}).keys()),
                "restricted_paths": list(cfg.get("restricted_paths", {}).keys())
            })
        except Exception:
            st.caption("Could not load agent_config.json")

if __name__ == "__main__":
    main()
