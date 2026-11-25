#!/usr/bin/env python3
"""
Synthetic Windows Active Directory authentication log generator.
Produces a "normal 9-to-5" baseline for insider-threat / UEBA model training.

Outputs:
  1. baseline_logs.json   -> Winlogbeat/ELK-style structured JSON (one doc per line, NDJSON)
  2. baseline_logs.evtx.log -> Windows Security Event Log style text (key=value, per-event block)
  3. baseline_logs.csv    -> flat CSV for quick loading into pandas / Excel

Covers standard Windows Security Event IDs:
  4624 - An account was successfully logged on
  4634 - An account was logged off
  4625 - An account failed to log on
  4723 - An attempt was made to change an account's password (self-service)
  4724 - An attempt was made to reset an account's password (admin/helpdesk reset,
         used here to represent "forgot password" flows)
  4740 - A user account was locked out
  4767 - A user account was unlocked

Design notes for the baseline (normal behaviour), so anomalies injected later
stand out:
  - Logons cluster 08:45-09:15, logoffs cluster 17:00-18:15, Mon-Fri only.
  - Each user logs on from ONE consistent workstation >90% of the time.
  - Small, realistic noise: occasional mistyped password (4625) followed by a
    successful 4624 seconds later; rare lockouts (4740->4767); a monthly
    password reset per user (mix of self-service 4723 and helpdesk 4724).
  - No logons outside business hours, no weekend activity, no logons from
    multiple workstations at once, no impossible travel - by construction.
    (That's exactly what you'll want to violate when you generate the
    "insider threat" anomaly set later.)
"""

import json
import csv
import random
from datetime import datetime, timedelta, date

random.seed(42)  # reproducible baseline

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
NUM_USERS = 35
DAYS_BACK = 30
DOMAIN = "CORP"
LOGON_TYPE_INTERACTIVE = 2
LOGON_TYPE_RDP = 10

DEPARTMENTS = ["Finance", "HR", "Engineering", "Sales", "IT", "Legal", "Operations"]
FIRST_NAMES = ["arjun","priya","rohan","sneha","kabir","isha","dev","meera","aman","riya",
               "vikram","tanya","yash","neha","raj","pooja","aditya","sana","karan","divya",
               "manav","alia","rahul","kavya","siddharth","juhi","varun","simran","nikhil","priyanka",
               "harsh","ananya","gaurav","shreya","abhay"]
LAST_INITIALS = list("abcdefghijklmnopqrstuvwxyz")

FAIL_REASONS = [
    ("0xC000006A", "The specified account's password is incorrect."),
    ("0xC0000064", "The specified user account does not exist."),
    ("0xC0000234", "The user account has been automatically locked."),
]

# ---------------------------------------------------------------------------
# Build synthetic user population
# ---------------------------------------------------------------------------
def build_users(n):
    users = []
    for i in range(n):
        fname = FIRST_NAMES[i % len(FIRST_NAMES)]
        uname = f"{fname}.{random.choice(LAST_INITIALS)}{i:02d}"
        users.append({
            "username": uname,
            "sam": f"{DOMAIN}\\{uname}",
            "sid": f"S-1-5-21-3623811015-3361044348-30300820-{1100+i}",
            "department": random.choice(DEPARTMENTS),
            "workstation": f"WKS-{random.choice(['FIN','HR','ENG','SLS','IT','LEG','OPS'])}-{100+i:03d}",
            "src_ip": f"10.{random.randint(10,20)}.{random.randint(0,20)}.{random.randint(10,250)}",
            # each user has their own personal "usual" arrival/departure jitter
            "arrival_mean_min": random.randint(-10, 20),   # offset from 09:00 in minutes
            "departure_mean_min": random.randint(-20, 75), # offset from 17:00 in minutes
        })
    return users

USERS = build_users(NUM_USERS)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def business_days(days_back):
    end = date.today()
    d = end - timedelta(days=days_back)
    out = []
    while d <= end:
        if d.weekday() < 5:  # Mon-Fri
            out.append(d)
        d += timedelta(days=1)
    return out

def jitter_time(base_hour, base_minute, mean_offset_min, spread_min=8):
    total_min = base_hour * 60 + base_minute + mean_offset_min + random.gauss(0, spread_min)
    total_min = max(0, min(23 * 60 + 59, total_min))
    h, m = divmod(int(total_min), 60)
    return h, m

DAYS = business_days(DAYS_BACK)
events = []  # each: dict of normalized fields

def add_event(dt, event_id, event_name, user, logon_type=None, extra=None):
    e = {
        "timestamp": dt.isoformat() + "Z",
        "event_id": event_id,
        "event_name": event_name,
        "domain": DOMAIN,
        "username": user["username"],
        "account_sid": user["sid"],
        "workstation": user["workstation"],
        "src_ip": user["src_ip"],
        "department": user["department"],
        "logon_type": logon_type,
    }
    if extra:
        e.update(extra)
    events.append(e)

# ---------------------------------------------------------------------------
# Generate baseline event stream
# ---------------------------------------------------------------------------
for d in DAYS:
    for user in USERS:
        # ~3% chance a user is on leave / absent that day -> no events at all
        if random.random() < 0.03:
            continue

        logon_type = LOGON_TYPE_RDP if random.random() < 0.08 else LOGON_TYPE_INTERACTIVE

        # --- occasional mistyped password before the real logon (~4% of days) ---
        h, m = jitter_time(9, 0, user["arrival_mean_min"])
        logon_dt = datetime.combine(d, datetime.min.time()).replace(hour=h, minute=m,
                                                                       second=random.randint(0, 59))
        if random.random() < 0.04:
            fail_code, fail_reason = ("0xC000006A", "The specified account's password is incorrect.")
            fail_dt = logon_dt - timedelta(minutes=random.randint(1, 4))
            add_event(fail_dt, 4625, "An account failed to log on", user, logon_type,
                       extra={"failure_code": fail_code, "failure_reason": fail_reason,
                              "logon_process": "User32"})

        # --- successful logon ---
        logon_id = f"0x{random.randint(0x10000,0xFFFFF):X}"
        add_event(logon_dt, 4624, "An account was successfully logged on", user, logon_type,
                   extra={"logon_id": logon_id, "authentication_package": "Negotiate"})

        # --- rare account lockout -> unlock (~0.3% of user-days) ---
        if random.random() < 0.003:
            lock_dt = logon_dt + timedelta(minutes=random.randint(10, 120))
            add_event(lock_dt, 4740, "A user account was locked out", user,
                       extra={"caller_computer": user["workstation"]})
            unlock_dt = lock_dt + timedelta(minutes=random.randint(15, 90))
            add_event(unlock_dt, 4767, "A user account was unlocked", user,
                       extra={"caller_computer": "DC01"})

        # --- logoff, clustered around 17:00 ---
        h2, m2 = jitter_time(17, 0, user["departure_mean_min"])
        logoff_dt = datetime.combine(d, datetime.min.time()).replace(hour=h2, minute=m2,
                                                                        second=random.randint(0, 59))
        if logoff_dt <= logon_dt:
            logoff_dt = logon_dt + timedelta(hours=8)
        add_event(logoff_dt, 4634, "An account was logged off", user, logon_type,
                   extra={"logon_id": logon_id})

    # --- monthly-ish password resets/changes: pick a handful of users per day ---
    if random.random() < 0.15:
        for user in random.sample(USERS, k=random.randint(1, 2)):
            reset_h, reset_m = jitter_time(10, 30, random.randint(-60, 240))
            reset_dt = datetime.combine(d, datetime.min.time()).replace(hour=max(8, min(18, reset_h)),
                                                                          minute=reset_m)
            if random.random() < 0.5:
                # self-service change ("forgot password" -> reset via portal), 4723
                add_event(reset_dt, 4723, "An attempt was made to change an account's password", user,
                           extra={"initiated_by": "self-service portal"})
            else:
                # helpdesk-assisted reset ("forgot password" -> IT resets it), 4724
                add_event(reset_dt, 4724, "An attempt was made to reset an account's password", user,
                           extra={"initiated_by": "helpdesk", "target_account": user["username"]})

events.sort(key=lambda e: e["timestamp"])
print(f"Generated {len(events)} events across {len(DAYS)} business days for {NUM_USERS} users.")

# ---------------------------------------------------------------------------
# Output 1: NDJSON, ELK/Winlogbeat-style
# ---------------------------------------------------------------------------
with open("baseline_logs.json", "w") as f:
    for e in events:
        doc = {
            "@timestamp": e["timestamp"],
            "event": {"code": e["event_id"], "action": e["event_name"], "category": "authentication",
                       "outcome": "success" if e["event_id"] not in (4625, 4740) else "failure"},
            "winlog": {
                "event_id": e["event_id"],
                "channel": "Security",
                "computer_name": f"{e['workstation']}.{DOMAIN.lower()}.local",
                "logon": {"type": e.get("logon_type")},
            },
            "user": {"name": e["username"], "domain": DOMAIN, "id": e["account_sid"]},
            "source": {"ip": e["src_ip"]},
            "host": {"name": e["workstation"]},
            "department": e["department"],
        }
        for k in ("failure_code", "failure_reason", "logon_process", "logon_id",
                  "authentication_package", "caller_computer", "initiated_by", "target_account"):
            if k in e:
                doc.setdefault("extra", {})[k] = e[k]
        f.write(json.dumps(doc) + "\n")

# ---------------------------------------------------------------------------
# Output 2: Windows Security Event Log style text blocks
# ---------------------------------------------------------------------------
with open("baseline_logs.evtx.log", "w") as f:
    for e in events:
        f.write("-" * 70 + "\n")
        f.write(f"Log Name:      Security\n")
        f.write(f"Source:        Microsoft-Windows-Security-Auditing\n")
        f.write(f"Event ID:      {e['event_id']}\n")
        f.write(f"Task Category: {e['event_name']}\n")
        f.write(f"Level:         Information\n")
        f.write(f"Date/Time:     {e['timestamp']}\n")
        f.write(f"Computer:      {e['workstation']}.{DOMAIN.lower()}.local\n")
        f.write("Details:\n")
        f.write(f"    Account Name:      {e['username']}\n")
        f.write(f"    Account Domain:    {DOMAIN}\n")
        f.write(f"    Security ID:       {e['account_sid']}\n")
        if e.get("logon_type") is not None:
            f.write(f"    Logon Type:        {e['logon_type']}\n")
        f.write(f"    Source Network Address: {e['src_ip']}\n")
        if "logon_id" in e:
            f.write(f"    Logon ID:          {e['logon_id']}\n")
        if "failure_code" in e:
            f.write(f"    Failure Code:      {e['failure_code']}\n")
            f.write(f"    Failure Reason:    {e['failure_reason']}\n")
        if "initiated_by" in e:
            f.write(f"    Initiated By:      {e['initiated_by']}\n")
        if "caller_computer" in e:
            f.write(f"    Caller Computer:   {e['caller_computer']}\n")
        f.write("\n")

# ---------------------------------------------------------------------------
# Output 3: flat CSV
# ---------------------------------------------------------------------------
fieldnames = ["timestamp", "event_id", "event_name", "domain", "username", "account_sid",
              "workstation", "src_ip", "department", "logon_type", "logon_id",
              "failure_code", "failure_reason", "initiated_by", "caller_computer"]
with open("baseline_logs.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
    w.writeheader()
    for e in events:
        w.writerow(e)

print("Wrote baseline_logs.json, baseline_logs.evtx.log, baseline_logs.csv")
