import pandas as pd
from sklearn.ensemble import IsolationForest
import pickle
import os

def train_isolation_forest(data_path, model_output_path):
    """Trains an Isolation Forest on static features."""
    print(f"Loading data from {data_path}...")
    try:
        df = pd.read_csv(data_path)
    except Exception as e:
        print(f"Failed to load data: {e}. Creating dummy model for now.")
        # Dummy data for scaffolding if CSV isn't ready
        df = pd.DataFrame({
            'login_hour': [9, 10, 8, 17, 3, 14, 15, 2],
            'login_day_of_week': [0, 1, 2, 3, 4, 1, 2, 6],
            'role_mismatch_flag': [0, 0, 0, 0, 1, 0, 0, 1],
            'usb_attempt_flag': [0, 0, 0, 0, 1, 0, 0, 1]
        })
    
    features = ['login_hour', 'login_day_of_week', 'role_mismatch_flag', 'usb_attempt_flag']
    X = df[features]
    
    print("Training Isolation Forest...")
    clf = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    clf.fit(X)
    
    os.makedirs(os.path.dirname(model_output_path), exist_ok=True)
    with open(model_output_path, 'wb') as f:
        pickle.dump(clf, f)
        
    print(f"Model saved to {model_output_path}")

if __name__ == "__main__":
    train_isolation_forest('data/collected_events.csv', 'models/isolation_forest.pkl')
