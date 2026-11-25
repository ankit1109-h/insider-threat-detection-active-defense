import sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
sys.path.insert(0, 'central_server')
from baseline_scorer import BaselineScorer
from datetime import datetime

scorer = BaselineScorer()

# Sept 2026 real weekdays: Mon=15, Tue=16, Wed=17, Thu=18
# Sat=19, Sun=20
tests = [
    ('Mon  9AM  (office)',    '2026-09-15T09:00:00'),
    ('Mon 10AM  (office)',    '2026-09-15T10:30:00'),
    ('Mon  2PM  (office)',    '2026-09-15T14:00:00'),
    ('Mon  6PM  (office)',    '2026-09-15T18:00:00'),  # Should be OK now
    ('Mon  7PM  (boundary)', '2026-09-15T19:00:00'),  # Boundary 19:00
    ('Mon  8PM  (late)',      '2026-09-15T20:00:00'),  # Should ALERT
    ('Mon  2AM  (night)',     '2026-09-15T02:00:00'),
    ('Sat 11AM  (weekend)',   '2026-09-19T11:00:00'),
    ('Sat  2AM  (wknd ngt)', '2026-09-19T02:00:00'),
]

print('Test                        Score   Category')
print('-'*65)
for label, ts in tests:
    score, reason = scorer.score_login_with_lstm({'timestamp': ts})
    status = 'ALERT' if score >= 0.5 else 'OK   '
    print(f'[{status}] {label:<27} {score:.3f}   {reason[:40]}')
