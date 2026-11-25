import sqlite3
import json
import logging
from flask import Flask, request, jsonify
from datetime import datetime
from threading import Thread
import queue
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from feature_engineering import FeatureExtractor
from ensemble_scorer import EnsembleScorer
from shap_explainer import ShapExplainer
from baseline_scorer import BaselineScorer

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

_SERVER_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(_SERVER_DIR, 'db', 'events.db')
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
event_queue = queue.Queue()

# Absolute root of the project (one level up from central_server/)
_ROOT = os.path.dirname(_SERVER_DIR)

# Initialize ML components
feature_extractor = FeatureExtractor(
    config_path=os.path.join(_ROOT, 'config', 'employee_config.json'),
    policy_path=os.path.join(_ROOT, 'config', 'access_policy.json')
)
baseline_scorer = BaselineScorer(
    baseline_path=os.path.join(_ROOT, 'data', 'baseline_profile.json'),
    lstm_model_path=os.path.join(_ROOT, 'models', 'lstm_model.pth'),
    lstm_scaler_path=os.path.join(_ROOT, 'models', 'lstm_scaler.pkl')
)
scorer = EnsembleScorer(
    iso_model_path=os.path.join(_ROOT, 'models', 'isolation_forest.pkl'),
    baseline_scorer=baseline_scorer
)
explainer = ShapExplainer()

# Load API Key
_config_path = os.path.join(_ROOT, 'config', 'agent_config.json')
try:
    with open(_config_path, 'r') as f:
        _agent_config = json.load(f)
        API_KEY = _agent_config.get('api_key', 'secr3t_auth_k3y_for_insider_threat')
except Exception:
    API_KEY = 'secr3t_auth_k3y_for_insider_threat'

# Store agent heartbeats: {'user_computer': last_seen_datetime}
agents_status = {}

MAINTENANCE_MODE = False

def verify_api_key(req):
    return req.headers.get('X-API-Key') == API_KEY

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS raw_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            event_id INTEGER,
            event_type TEXT,
            user TEXT,
            computer TEXT,
            risk_factor TEXT,
            event_data TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            user TEXT,
            event_type TEXT,
            risk_score REAL,
            alert_reason TEXT,
            shap_explanation TEXT
        )
    ''')
    # Migrate: add missing columns to existing DB without losing data
    existing = [row[1] for row in cursor.execute("PRAGMA table_info(raw_events)").fetchall()]
    for col, coltype in [('event_type', 'TEXT'), ('risk_factor', 'TEXT')]:
        if col not in existing:
            cursor.execute(f"ALTER TABLE raw_events ADD COLUMN {col} {coltype}")
            logging.info(f"Migrated DB: added column '{col}' to raw_events")
    existing_alerts = [row[1] for row in cursor.execute("PRAGMA table_info(alerts)").fetchall()]
    if 'event_type' not in existing_alerts:
        cursor.execute("ALTER TABLE alerts ADD COLUMN event_type TEXT")
        logging.info("Migrated DB: added column 'event_type' to alerts")
    conn.commit()
    conn.close()
    logging.info("Database initialized.")

def process_single_event(event):
    """Processes a single event synchronously and returns the risk score."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        event_type = event.get('type', f"WIN_{event.get('event_id', 'UNKNOWN')}")
        risk_factor = event.get('risk_factor', 'unknown')

        # Store raw event
        cursor.execute('''
            INSERT INTO raw_events (timestamp, event_id, event_type, user, computer, risk_factor, event_data)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            event.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
            event.get('event_id'),
            event_type,
            event.get('user', event.get('agent_user', 'Unknown')),
            event.get('computer', 'Unknown'),
            risk_factor,
            json.dumps(event.get('event_data', {}))
        ))
        conn.commit()

        # Run Inference Pipeline
        user = event.get('user', event.get('agent_user', 'Unknown'))
        static_features = feature_extractor.extract_static_features(event)
        static_features['event_type'] = event_type
        sequence_features = feature_extractor.update_session_sequence(user, static_features)

        risk_score, is_anomaly = scorer.score(static_features, sequence_features, raw_event=event)

        if is_anomaly:
            explanation = explainer.explain(static_features, event)
            alert_reason = _build_alert_reason(event, event_type, risk_factor)
            logging.warning(f"🚨 ANOMALY [{risk_score:.2f}] user={user} type={event_type}: {explanation}")

            cursor.execute('''
                INSERT INTO alerts (timestamp, user, event_type, risk_score, alert_reason, shap_explanation)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                event.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
                user,
                event_type,
                risk_score,
                alert_reason,
                explanation
            ))
            conn.commit()
            
        conn.close()
        return risk_score
        
    except Exception as e:
        logging.error(f"Error processing event: {e}", exc_info=True)
        return 0.0

def _build_alert_reason(event, event_type, risk_factor):
    """Builds a human-readable alert reason based on event type."""
    reasons = {
        'CROSS_DEPARTMENT_ACCESS': f"Role Violation: {event.get('agent_user','User')} accessed restricted department folder",
        'UNAUTHORIZED_FILE_ACCESS_ATTEMPT': f"UNAUTHORIZED ACCESS ATTEMPT: {event.get('user', event.get('agent_user', 'User'))} tried to access {event.get('event_data', {}).get('restricted_folder', 'a restricted folder')}",
        'FILE_COPY_ACCESS_ACTIVITY': f"File Copy/Access Activity: {event.get('user', event.get('agent_user', 'User'))} accessed {event.get('event_data', {}).get('object', 'a protected file')}",
        'USB_INSERTED':            f"USB Device Inserted: {event.get('event_data', {}).get('label', '')} {event.get('event_data', {}).get('drive', 'Unknown drive')}",
        'DATA_COPIED_TO_USB':      f"DATA EXFILTRATION: {event.get('event_data', {}).get('burst_mb', '?')}MB copied to USB {event.get('event_data', {}).get('drive', '?')} — {event.get('event_data', {}).get('file_count', '?')} files transferred",
        'BULK_FILE_ACCESS':        f"Bulk File Access: {event.get('event_data', {}).get('count', '?')} files in 60s",
        'BULK_FILE_DELETE':        f"CRITICAL: Mass File Deletion — {event.get('event_data', {}).get('count', '?')} files deleted",
        'LARGE_CLIPBOARD_COPY':    f"Large Clipboard Copy: {event.get('event_data', {}).get('size_mb', '?')}MB",
        'CLIPBOARD_BURST':         f"Clipboard Burst: {event.get('event_data', {}).get('burst_mb', '?')}MB in 5 minutes",
        'HIGH_UPLOAD_BURST':       f"High Upload Detected: {event.get('event_data', {}).get('burst_mb', '?')}MB in 60s",
        'PERSONAL_CLOUD_CONNECTION': f"Personal Cloud Access: {event.get('event_data', {}).get('host', 'Unknown')}",
        'USER_LOGON':              f"Login at unusual hour: {datetime.now().hour}:00",
    }
    return reasons.get(event_type, f"High-risk activity detected: {event_type} (risk_factor={risk_factor})")

@app.route('/ingest', methods=['POST'])
def ingest():
    """Endpoint for agent to send raw events."""
    if not verify_api_key(request):
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    try:
        data = request.json
        if not data:
            return jsonify({"status": "error", "message": "Invalid JSON"}), 400
        
        # Process synchronously to return actions
        risk_score = process_single_event(data)
        
        # Determine the action based on risk score
        if risk_score >= 0.9 and not MAINTENANCE_MODE:
            return jsonify({"status": "success", "action": "block_user", "maintenance_mode": MAINTENANCE_MODE}), 200
        elif risk_score >= 0.65 or (risk_score >= 0.9 and MAINTENANCE_MODE):
            return jsonify({"status": "success", "action": "take_screenshot", "maintenance_mode": MAINTENANCE_MODE}), 200
            
        return jsonify({"status": "success", "maintenance_mode": MAINTENANCE_MODE}), 200
    except Exception as e:
        logging.error(f"Ingest error: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/upload_screenshot', methods=['POST'])
def upload_screenshot():
    """Endpoint to receive agent screenshots for critical alerts."""
    if not verify_api_key(request):
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    try:
        if 'file' not in request.files:
            return jsonify({"error": "No file part"}), 400
        file = request.files['file']
        if file.filename == '':
            return jsonify({"error": "No selected file"}), 400
            
        # Save to dashboard assets or data folder
        media_dir = os.path.join(_ROOT, 'data', 'screenshots')
        os.makedirs(media_dir, exist_ok=True)
        
        user = request.form.get('user', 'unknown')
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{user}_{timestamp}.png"
        filepath = os.path.join(media_dir, filename)
        
        file.save(filepath)
        logging.info(f"Screenshot saved: {filepath}")
        return jsonify({"status": "success"}), 200
    except Exception as e:
        logging.error(f"Screenshot upload error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/status', methods=['GET'])
def status():
    return jsonify({
        "status": "running",
        "baseline_active": baseline_scorer.baseline_active,
        "maintenance_mode": MAINTENANCE_MODE
    }), 200

@app.route('/toggle_maintenance', methods=['POST'])
def toggle_maintenance():
    global MAINTENANCE_MODE
    MAINTENANCE_MODE = not MAINTENANCE_MODE
    logging.info(f"Maintenance Mode changed to: {MAINTENANCE_MODE}")
    return jsonify({"maintenance_mode": MAINTENANCE_MODE}), 200

@app.route('/heartbeat', methods=['POST'])
def heartbeat():
    if not verify_api_key(request):
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    try:
        data = request.json
        user = data.get('user', 'unknown')
        computer = data.get('computer', 'unknown')
        agent_id = f"{user}@{computer}"
        agents_status[agent_id] = datetime.now()
        return jsonify({"status": "success", "maintenance_mode": MAINTENANCE_MODE}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/agents_status', methods=['GET'])
def get_agents_status():
    status_dict = {}
    now = datetime.now()
    for agent_id, last_seen in agents_status.items():
        mins_ago = int((now - last_seen).total_seconds() / 60)
        status_dict[agent_id] = {
            "last_seen_mins_ago": mins_ago,
            "status": "Online" if mins_ago < 5 else "Offline"
        }
    return jsonify(status_dict), 200

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000)