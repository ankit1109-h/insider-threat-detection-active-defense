import json
import logging
from datetime import datetime

class FeatureExtractor:
    def __init__(self, config_path='../config/employee_config.json', policy_path='../config/access_policy.json'):
        try:
            with open(config_path, 'r') as f:
                self.employee_config = json.load(f)
            with open(policy_path, 'r') as f:
                self.access_policy = json.load(f)
        except Exception as e:
            logging.error(f"Failed to load config files for feature engineering: {e}")
            self.employee_config = {}
            self.access_policy = {}
            
        # Session state for sequence modeling
        self.user_sessions = {}
        
    def extract_static_features(self, raw_event):
        """Extracts point-in-time features for Isolation Forest."""
        features = {}
        
        # Time-based features
        try:
            dt = datetime.fromisoformat(raw_event['timestamp'])
            features['login_hour'] = dt.hour
            features['login_day_of_week'] = dt.weekday()
        except:
            features['login_hour'] = 0
            features['login_day_of_week'] = 0
            
        user = raw_event.get('user', '')
        # Extract base username (remove domain if present)
        base_user = user.split('\\\\')[-1] if '\\\\' in user else user
        
        # Role config
        user_info = self.employee_config.get(base_user, {})
        role = user_info.get('role', 'Unknown')
        
        # Mismatch flagging
        event_id = raw_event.get('event_id')
        event_data = raw_event.get('event_data', {})
        strings = event_data.get('strings', [])
        
        features['role_mismatch_flag'] = 0
        features['usb_attempt_flag'] = 1 if event_id == 20001 else 0
        
        # File access sensitivity check
        if event_id in [4656, 4663] and len(strings) > 6:
            object_name = strings[6]  # Usually the file path in these events
            # Simple check against policy
            for path, policy in self.access_policy.items():
                if path in object_name:
                    if role not in policy.get('allowed_roles', []):
                        features['role_mismatch_flag'] = 1
                    break
                    
        return features

    def update_session_sequence(self, user, features):
        """Maintains a rolling window of recent actions for LSTM input."""
        if user not in self.user_sessions:
            self.user_sessions[user] = []
            
        # Append numerical features to sequence
        # Convert to list [login_hour, day, role_mismatch, usb_attempt]
        feature_vector = [
            features.get('login_hour', 0),
            features.get('login_day_of_week', 0),
            features.get('role_mismatch_flag', 0),
            features.get('usb_attempt_flag', 0)
        ]
        
        self.user_sessions[user].append(feature_vector)
        
        # Keep last 10 actions
        if len(self.user_sessions[user]) > 10:
            self.user_sessions[user].pop(0)
            
        return self.user_sessions[user]
