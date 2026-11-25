"""
ensemble_scorer.py
Combines Isolation Forest + Baseline Scorer to produce a unified risk score.
Loads the real trained Isolation Forest model from disk.
"""
import pickle
import logging
import os
import numpy as np

logger = logging.getLogger(__name__)

# Risk factor weights for different event types
RISK_WEIGHTS = {
    'critical': 1.0,
    'high':     0.8,
    'medium':   0.5,
    'low':      0.2,
}

# Risk score additions per event type
EVENT_RISK_SCORES = {
    'SUSPICIOUS_CMD':          0.9,  # Critical: recon or potential malware
    'CROSS_DEPARTMENT_ACCESS': 0.7,
    'UNAUTHORIZED_FILE_ACCESS_ATTEMPT': 0.95,
    'USB_INSERTED':            0.8,
    'DATA_COPIED_TO_USB':      1.0,  # Critical: direct exfiltration to USB
    'BULK_FILE_ACCESS':        0.7,
    'FILE_COPY_ACCESS_ACTIVITY': -100.0,
    'BULK_FILE_DELETE':        1.0,
    'LARGE_CLIPBOARD_COPY':    0.6,
    'EXCESSIVE_DAILY_CLIPBOARD': 0.5,
    'CLIPBOARD_BURST':         0.55,
    'HIGH_UPLOAD_BURST':       0.8,
    'EXCESSIVE_DAILY_UPLOAD':  0.6,
    'PERSONAL_CLOUD_CONNECTION': 0.75,
    'USER_LOGON':              0.05,
    'USER_LOGOFF':             0.0,
    'FILE_ACCESS':             0.05,
    'FILE_ACCESS_REQUEST':     0.05,
    'FILE_DELETED':            0.15,
}

class EnsembleScorer:
    def __init__(self,
                 iso_model_path='../models/isolation_forest.pkl',
                 lstm_model_path='../models/lstm_autoencoder.h5',
                 baseline_scorer=None):
        self.iso_model = None
        self.baseline_scorer = baseline_scorer

        # Try to load the real trained Isolation Forest model
        try:
            if os.path.exists(iso_model_path):
                with open(iso_model_path, 'rb') as f:
                    self.iso_model = pickle.load(f)
                logger.info(f"Isolation Forest model loaded from {iso_model_path}")
            else:
                logger.warning(f"Isolation Forest model not found at {iso_model_path}. Using rule-based scoring.")
        except Exception as e:
            logger.error(f"Failed to load Isolation Forest model: {e}")

    def _isolation_forest_score(self, static_features):
        """Returns anomaly score from the trained Isolation Forest (0=normal, 1=anomaly)."""
        if self.iso_model is None:
            return 0.0
        try:
            feature_vector = np.array([[
                static_features.get('login_hour', 12),
                static_features.get('login_day_of_week', 0),
                static_features.get('role_mismatch_flag', 0),
                static_features.get('usb_attempt_flag', 0)
            ]])
            # Isolation Forest returns -1 for anomaly, 1 for normal
            prediction = self.iso_model.predict(feature_vector)[0]
            # score_samples gives raw anomaly score (more negative = more anomalous)
            raw_score = self.iso_model.score_samples(feature_vector)[0]
            # Normalize to 0-1 where 1 is most anomalous
            normalized = max(0.0, min(1.0, (-raw_score - 0.1) / 0.5))
            return normalized if prediction == -1 else normalized * 0.3
        except Exception as e:
            logger.error(f"Isolation Forest scoring error: {e}")
            return 0.0

    def score(self, static_features, sequence_features, raw_event=None):
        """
        Returns (risk_score 0-1, is_anomaly bool).
        Combines: event type weight + Isolation Forest + baseline deviation.
        """
        risk_score = 0.0
        event_type = static_features.get('event_type', 'UNKNOWN')

        # 1. Event type base score
        base_score = EVENT_RISK_SCORES.get(event_type, 0.1)
        if event_type == 'LARGE_CLIPBOARD_COPY' and raw_event:
            ev_data = raw_event.get('event_data', {})
            size_mb = ev_data.get('size_mb', 0) if isinstance(ev_data, dict) else 0
            if size_mb >= 100:
                base_score = 0.95
            elif size_mb >= 10:
                base_score = 0.75
        risk_score += base_score

        # 2. Isolation Forest score (trained on CERT data)
        iso_score = self._isolation_forest_score(static_features)
        risk_score += iso_score * 0.3  # weight: 30%

        # 3. Role mismatch flag (from feature_engineering)
        if static_features.get('role_mismatch_flag', 0) == 1:
            risk_score += 0.5

        # 4. USB flag
        if static_features.get('usb_attempt_flag', 0) == 1:
            risk_score += 0.7

        # 5. LSTM-based login anomaly scoring (for USER_LOGON events only)
        if self.baseline_scorer and event_type == 'USER_LOGON':
            event_payload = raw_event or {}
            lstm_score, lstm_reason = self.baseline_scorer.score_login_with_lstm(event_payload)
            # Increase weight: If LSTM flags a high anomaly (score > 0.5), make sure it pushes total >= 0.5
            risk_score += lstm_score * 0.8   # weight: 80%
            logger.debug(f"LSTM login score: {lstm_score:.3f} — {lstm_reason}")
        # Legacy: baseline deviation for non-login events
        elif self.baseline_scorer and event_type not in ('USER_LOGON', 'USER_LOGOFF'):
            if self.baseline_scorer.is_unusual_login_time():
                baseline_risk, _ = self.baseline_scorer.score_event('LOGIN')
                risk_score += baseline_risk * 0.2

        # Cap at 1.0
        risk_score = min(risk_score, 1.0)
        is_anomaly = risk_score >= 0.5

        return round(risk_score, 3), is_anomaly
