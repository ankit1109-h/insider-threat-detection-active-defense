import sqlite3

for p in ['central_server/db/events.db', 'db/events.db']:
    print(f'\n=== {p} ===')
    conn = sqlite3.connect(p)
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [r[0] for r in cur.fetchall()]
    print(f'Tables: {tables}')
    for t in tables:
        cur.execute(f'SELECT COUNT(*) FROM {t}')
        count = cur.fetchone()[0]
        print(f'  [{t}] {count} rows')
        cur.execute(f'PRAGMA table_info({t})')
        cols = [r[1] for r in cur.fetchall()]
        print(f'  Columns: {cols}')
        cur.execute(f'SELECT * FROM {t} ORDER BY rowid DESC LIMIT 5')
        for r in cur.fetchall():
            print(f'    {r}')
    conn.close()
