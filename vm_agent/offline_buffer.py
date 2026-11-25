"""
offline_buffer.py
Stores events locally in an SQLite database if the central server is unreachable.
Events are sent and deleted once the connection is restored.
"""
import sqlite3
import json
import logging
import os
import threading

logger = logging.getLogger(__name__)

DB_PATH = os.path.join(os.path.dirname(__file__), 'offline_buffer.db')
_lock = threading.Lock()

def _init_db():
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS pending_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_data TEXT NOT NULL
            )
        ''')
        conn.commit()
        conn.close()

# Initialize on import
_init_db()

def save_event(event_dict):
    """Saves a single event to the local database."""
    try:
        with _lock:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute('INSERT INTO pending_events (event_data) VALUES (?)', (json.dumps(event_dict),))
            conn.commit()
            conn.close()
    except Exception as e:
        logger.error(f"OfflineBuffer: Error saving event: {e}")

def get_pending_events(limit=50):
    """Retrieves up to `limit` pending events. Returns a list of tuples (id, event_dict)."""
    events = []
    try:
        with _lock:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute('SELECT id, event_data FROM pending_events ORDER BY id ASC LIMIT ?', (limit,))
            rows = cursor.fetchall()
            for row in rows:
                events.append((row[0], json.loads(row[1])))
            conn.close()
    except Exception as e:
        logger.error(f"OfflineBuffer: Error reading events: {e}")
    return events

def delete_events(event_ids):
    """Deletes events by their IDs after successful transmission."""
    if not event_ids:
        return
    try:
        with _lock:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            placeholders = ','.join('?' for _ in event_ids)
            cursor.execute(f'DELETE FROM pending_events WHERE id IN ({placeholders})', event_ids)
            conn.commit()
            conn.close()
    except Exception as e:
        logger.error(f"OfflineBuffer: Error deleting events: {e}")
