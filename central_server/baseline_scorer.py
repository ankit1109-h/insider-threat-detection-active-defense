"""
baseline_scorer.py
==================
Loads the 7-day baseline profile AND the trained PyTorch LSTM model
to score incoming events. Provides unified risk scoring for login events.

Usage:
    scorer = BaselineScorer()
    risk, reason = scorer.score_login_event(event_dict)
"""
import json
import logging
import os
import pickle
import numpy as np
from datetime import datetime

logger = logging.getLogger(__name__)

# -- Paths --------------------------------------------------------------------
_BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
BASELINE_PATH = os.path.join(_BASE_DIR, '..', 'data', 'baseline_profile.json')
LSTM_MODEL    = os.path.join(_BASE_DIR, '..', 'models', 'lstm_model.pth')
LSTM_SCALER   = os.path.join(_BASE_DIR, '..', 'models', 'lstm_scaler.pkl')

FEATURES = ["login_hour", "login_day_of_week", "is_weekend", "is_after_hours"]

OFFICE_START = 9   # 9 AM
OFFICE_END   = 19  # 7 PM


# -- LSTM Model definition (must match train_lstm_autoencoder.py) -------------
def _get_lstm_class():
    """Lazy import PyTorch to avoid crash if torch not installed."""
    try:
        import torch
        import torch.nn as nn

        class LoginLSTM(nn.Module):
            def __init__(self, input_size=4, hidden_size=64,
                         num_layers=2, dropout=0.3):
                super().__init__()
                self.lstm = nn.LSTM(
                    input_size  = input_size,
                    hidden_size = hidden_size,
                    num_layers  = num_layers,
                    batch_first = True,
                    dropout     = dropout if num_layers > 1 else 0.0
                )
                self.dropout = nn.Dropout(dropout)
                self.fc = nn.Sequential(
                    nn.Linear(hidden_size, 32),
                    nn.ReLU(),
                    nn.Dropout(dropout),
                    nn.Linear(32, 1)
                )

            def forward(self, x):
                out, _ = self.lstm(x)
                out = out[:, -1, :]
                out = self.dropout(out)
                return self.fc(out)

        return torch, nn, LoginLSTM
    except ImportError:
        return None, None, None


# =============================================================================
class BaselineScorer:
    """
    Unified scorer that combines:
    1. Rule-based thresholds (from baseline_profile.json)
    2. PyTorch LSTM model (from models/lstm_model.pth)
    """

    def __init__(self,
                 baseline_path=BASELINE_PATH,
                 lstm_model_path=LSTM_MODEL,
                 lstm_scaler_path=LSTM_SCALER):

        # -- Load baseline profile (optional) ---------------------------------
        self.profile        = None
        self.baseline_active = False
        self._load_baseline(baseline_path)

        # -- Load LSTM model --------------------------------------------------
        self.lstm_model  = None
        self.lstm_scaler = None
        self.lstm_active = False
        self._load_lstm(lstm_model_path, lstm_scaler_path)

    # ── Baseline profile ─────────────────────────────────────────────────────
    def _load_baseline(self, path):
        if os.path.exists(path):
            try:
                with open(path, 'r') as f:
                    self.profile = json.load(f)
                self.baseline_active = True
                logger.info(f"Baseline profile loaded.")
            except Exception as e:
                logger.warning(f"Could not load baseline profile: {e}")
        else:
            logger.warning("No baseline_profile.json found. Using LSTM + default rules.")

    # ── LSTM model ────────────────────────────────────────────────────────────
    def _load_lstm(self, model_path, scaler_path):
        torch, nn, LoginLSTM = _get_lstm_class()
        if torch is None:
            logger.warning("PyTorch not installed. LSTM scoring disabled.")
            return

        try:
            if not os.path.exists(model_path):
                logger.warning(f"LSTM model not found at {model_path}. Run train_lstm_autoencoder.py first.")
                return
            if not os.path.exists(scaler_path):
                logger.warning(f"LSTM scaler not found at {scaler_path}.")
                return

            model = LoginLSTM()
            model.load_state_dict(torch.load(model_path, map_location='cpu'))
            model.eval()
            self.lstm_model = model

            with open(scaler_path, 'rb') as f:
                self.lstm_scaler = pickle.load(f)

            self.lstm_active = True
            logger.info("LSTM model loaded successfully. Login anomaly detection active.")

        except Exception as e:
            logger.error(f"Failed to load LSTM model: {e}")

    # ── Feature extraction ────────────────────────────────────────────────────
    def _extract_login_features(self, event: dict) -> dict:
        """
        Extracts the 6 LSTM features from a raw event dict.
        event keys expected: 'timestamp', and optionally 'session_duration_hrs', 'logins_per_day'
        """
        try:
            ts = datetime.fromisoformat(event.get('timestamp', datetime.now().isoformat()))
        except Exception:
            ts = datetime.now()

        hour    = ts.hour
        dow     = ts.weekday()   # 0=Mon, 6=Sun
        weekend = 1 if dow >= 5 else 0
        after_h = 1 if (hour < OFFICE_START or hour >= OFFICE_END) else 0

        return {
            "login_hour":           hour,
            "login_day_of_week":    dow,
            "is_weekend":           weekend,
            "is_after_hours":       after_h,
            "session_duration_hrs": float(event.get('session_duration_hrs', 0.0)),
            "logins_per_day":       int(event.get('logins_per_day', 1)),
        }

    # ── LSTM Score ────────────────────────────────────────────────────────────
    def score_login_with_lstm(self, event: dict) -> tuple:
        """
        Returns (risk_score 0.0-1.0, reason_str) using the LSTM model.
        Falls back to rule-based if LSTM not available.
        """
        if not self.lstm_active:
            return self._rule_based_login_score(event)

        try:
            import torch
            features = self._extract_login_features(event)
            fvec     = np.array([[features[f] for f in FEATURES]], dtype=np.float32)
            fvec_sc  = self.lstm_scaler.transform(fvec)
            # Shape: (1, seq_len=1, num_features)
            tensor   = torch.tensor(fvec_sc.reshape(1, 1, len(FEATURES)),
                                    dtype=torch.float32)

            with torch.no_grad():
                logit = self.lstm_model(tensor)
                prob  = torch.sigmoid(logit).item()

            # Build human-readable reason
            f = features
            if prob >= 0.7:
                if f['is_after_hours']:
                    reason = (f"LSTM flagged off-hours login at {f['login_hour']:02d}:xx "
                              f"(after-hours={'Yes'}, weekend={'Yes' if f['is_weekend'] else 'No'}) "
                              f"— threat probability {prob:.0%}")
                else:
                    reason = (f"LSTM flagged unusual session pattern "
                              f"(logins_per_day={f['logins_per_day']}, "
                              f"session={f['session_duration_hrs']:.1f}h) "
                              f"— threat probability {prob:.0%}")
            else:
                reason = f"LSTM: normal login pattern (threat prob {prob:.0%})"

            return round(prob, 3), reason

        except Exception as e:
            logger.error(f"LSTM scoring error: {e}")
            return self._rule_based_login_score(event)

    # ── Rule-based fallback ───────────────────────────────────────────────────
    def _rule_based_login_score(self, event: dict) -> tuple:
        """Simple rule-based scoring when LSTM is unavailable."""
        try:
            ts   = datetime.fromisoformat(event.get('timestamp', datetime.now().isoformat()))
        except Exception:
            ts   = datetime.now()

        hour    = ts.hour
        dow     = ts.weekday()
        weekend = dow >= 5
        after_h = (hour < OFFICE_START or hour >= OFFICE_END)

        if weekend and after_h:
            return 0.85, f"Weekend + off-hours login at {hour:02d}:xx"
        if after_h:
            return 0.65, f"Off-hours login at {hour:02d}:xx (outside {OFFICE_START}:00-{OFFICE_END}:00)"
        if weekend:
            return 0.55, f"Weekend login (day {dow})"
        return 0.10, f"Normal login at {hour:02d}:xx"

    # ── Legacy compatibility (used by ensemble_scorer.py) ─────────────────────
    def is_unusual_login_time(self) -> bool:
        current_hour = datetime.now().hour
        if self.baseline_active:
            normal_hours = self.profile.get('normal_login_hours', list(range(OFFICE_START, OFFICE_END)))
            return current_hour not in normal_hours
        return (current_hour < OFFICE_START or current_hour >= OFFICE_END)

    def score_event(self, event_type: str, value=None) -> tuple:
        """Legacy scorer kept for backwards compatibility with ensemble_scorer.py."""
        if not self.baseline_active:
            return 0.5, "No baseline available, using default rules"

        thresholds   = self.profile.get('thresholds', {})
        hour         = datetime.now().hour
        normal_hours = self.profile.get('normal_login_hours', list(range(OFFICE_START, OFFICE_END)))

        if event_type == 'LOGIN':
            if hour not in normal_hours:
                deviation = min(abs(hour - min(normal_hours, key=lambda h: abs(h - hour))), 12)
                risk = min(0.5 + deviation * 0.04, 1.0)
                return risk, f"Login at {hour}:00 outside normal hours"
            return 0.1, "Login within normal hours"

        elif event_type == 'UPLOAD_MB' and value is not None:
            max_daily = thresholds.get('max_upload_mb_per_day', 500)
            if value > max_daily:
                return min(0.5 + (value / max_daily) * 0.1, 1.0), \
                       f"Upload {value:.1f}MB exceeds baseline {max_daily:.1f}MB"
            return 0.1, "Upload within normal range"

        elif event_type == 'CLIPBOARD_MB' and value is not None:
            max_clip = thresholds.get('max_clipboard_mb_per_day', 50)
            if value > max_clip:
                return min(0.5 + (value / max_clip) * 0.1, 1.0), \
                       f"Clipboard {value:.1f}MB exceeds baseline {max_clip:.1f}MB"
            return 0.1, "Clipboard within normal range"

        elif event_type == 'FILE_ACCESS_COUNT' and value is not None:
            max_files = thresholds.get('max_files_per_min', 30)
            if value > max_files:
                return min(0.5 + (value / max_files) * 0.05, 1.0), \
                       f"Bulk file access: {int(value)} files/min vs baseline {max_files}/min"
            return 0.1, "File access rate normal"

        return 0.3, f"Unknown event type: {event_type}"

    def get_thresholds(self) -> dict:
        if self.baseline_active:
            return self.profile.get('thresholds', {})
        return {}
