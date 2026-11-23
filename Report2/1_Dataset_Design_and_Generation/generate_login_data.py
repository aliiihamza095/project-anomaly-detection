"""
Starter generator: synthetic login dataset for "Login Behavior Anomaly Detection"
(CS-507 Information Security, Group 10).

DRAFT FOR THE GROUP TO READ, CHANGE AND OWN. The brief says all code must be written
by the group and borrowed code or ideas must be cited, so treat this as a starting
point: understand every line, adjust the design, and disclose AI assistance in the
report. Everything here is fictional: users are U001..U060 and IPs come only from
the documentation ranges 192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24.

Outputs (in ./data):
  login_data.csv          the dataset (the last 3 columns are evaluation-only labels)
  user_ground_truth.csv   how each user was generated (never given to the detector)
"""
import os
from datetime import datetime, timedelta

import numpy as np
import pandas as pd

SEED = 42
N_DAYS = 45
START = datetime(2026, 9, 1)
rng = np.random.default_rng(SEED)

# ---------------------------------------------------------------- design knobs
USER_TYPES = {"day_shift": 25, "evening": 15, "night_shift": 10, "remote_mixed": 10}
LOCATIONS = ["campus", "home_city", "other_city", "foreign_unknown",
             "branch_office", "public_wifi", "vpn"]
LOC_WEIGHTS = {                       # normal location mix per user type (same order as LOCATIONS)
    "day_shift":    [0.78, 0.12, 0.00, 0.00, 0.04, 0.02, 0.04],
    "evening":      [0.10, 0.80, 0.00, 0.00, 0.00, 0.06, 0.04],
    "night_shift":  [0.00, 0.92, 0.00, 0.00, 0.00, 0.02, 0.06],
    "remote_mixed": [0.00, 0.50, 0.30, 0.00, 0.00, 0.12, 0.08],
}
BASE_RTT_MS = {"campus": 20, "home_city": 45, "other_city": 70, "foreign_unknown": 190,
               "branch_office": 35, "public_wifi": 90, "vpn": 140}   # typical round-trip time
BROWSERS = {"Windows": ["Chrome", "Edge", "Firefox"], "macOS": ["Safari", "Chrome"],
            "Linux": ["Firefox", "Chrome"], "Android": ["Chrome", "Samsung Internet"],
            "iOS": ["Safari"]}
MEAN_LOGINS = {"day_shift": 9, "evening": 7, "night_shift": 7, "remote_mixed": 6}
DEVICE_CATALOG = [("laptop", "Windows"), ("laptop", "macOS"), ("laptop", "Linux"),
                  ("phone", "Android"), ("phone", "iOS"), ("tablet", "Android")]
# hours that are clearly / subtly unusual for each user type
OBVIOUS_HOURS = {"day_shift": [1, 2, 3, 4], "evening": [2, 3, 4, 5, 6],
                 "night_shift": [11, 12, 13, 14, 15], "remote_mixed": [3, 4]}
SUBTLE_HOURS = {"day_shift": [6, 19, 20], "evening": [13, 14, 1],
                "night_shift": [8, 9, 19, 20], "remote_mixed": [1, 2]}
N_EVENTS = {"unusual_hour": 120, "new_device": 120, "location_change": 100,
            "combined": 80, "failed_burst": 25}
N_TRIPS, N_NEW_PHONES, N_LATE_NIGHTS = 8, 6, 12      # harmless unusual events

_new_dev_counter = 0


# ---------------------------------------------------------------- helpers
IP_RANGES = {   # documentation ranges only, split by location category
    "campus": ("192.0.2", 1, 200), "branch_office": ("192.0.2", 200, 255),
    "home_city": ("198.51.100", 1, 200), "public_wifi": ("198.51.100", 200, 255),
    "other_city": ("203.0.113", 1, 100), "vpn": ("203.0.113", 100, 170),
    "foreign_unknown": ("203.0.113", 170, 255),
}


def make_ip(loc):
    prefix, lo, hi = IP_RANGES[loc]
    return f"{prefix}.{rng.integers(lo, hi)}"


def make_rtt(loc):
    return int(BASE_RTT_MS[loc] * rng.lognormal(0, 0.25))


def active_prob(utype, weekday):
    if utype == "day_shift":
        return 1.0 if weekday < 5 else 0.08
    return {"evening": 0.9, "night_shift": 0.85, "remote_mixed": 0.7}[utype]


def normal_hour(utype):
    if utype == "day_shift":
        return float(np.clip(rng.normal(12.5, 2.3), 8, 17.5))
    if utype == "evening":
        return float(np.clip(rng.normal(19.5, 1.8), 16, 23.5))
    if utype == "night_shift":
        return (22 + float(np.clip(rng.normal(4, 2.2), 0, 8))) % 24
    return float(rng.uniform(7, 23))


def at_hour(day, hour):
    return day + timedelta(hours=float(hour))


def new_device():
    global _new_dev_counter
    _new_dev_counter += 1
    t, o = DEVICE_CATALOG[rng.integers(len(DEVICE_CATALOG))]
    return {"device_id": f"DEV-NEW-{_new_dev_counter:04d}", "type": t, "os": o,
            "browser": str(rng.choice(BROWSERS[o]))}


def pick_device(u):
    if len(u["devices"]) == 1 or rng.random() < 0.8:
        return u["devices"][0]
    return u["devices"][rng.integers(1, len(u["devices"]))]


def normal_outcome():
    r = rng.random()
    if r < 0.012:
        return "failure", 1
    if r < 0.06:
        return "success", int(rng.integers(1, 3))
    return "success", 0


def row(u, ts, loc, dev, result, fails, is_anom=0, atype="none", benign="none"):
    return {"user_id": u["user_id"], "timestamp": ts, "device_id": dev["device_id"],
            "device_type": dev["type"], "os": dev["os"], "browser": dev["browser"],
            "location_category": loc, "ip_address": make_ip(loc),
            "round_trip_time_ms": make_rtt(loc), "login_result": result, "failed_attempts": fails,
            "is_anomaly": is_anom, "anomaly_type": atype, "benign_event": benign}


# ---------------------------------------------------------------- users
users = []
n = 0
for utype, count in USER_TYPES.items():
    for _ in range(count):
        n += 1
        k = int(rng.integers(2, 4)) if utype == "remote_mixed" else int(rng.integers(1, 3))
        picks = rng.choice(len(DEVICE_CATALOG), size=k, replace=False)
        devices = [{"device_id": f"DEV-{n:03d}-{j + 1}",
                    "type": DEVICE_CATALOG[p][0], "os": DEVICE_CATALOG[p][1],
                    "browser": str(rng.choice(BROWSERS[DEVICE_CATALOG[p][1]]))}
                   for j, p in enumerate(picks)]
        users.append({"user_id": f"U{n:03d}", "type": utype, "devices": devices})


def random_day():
    return START + timedelta(days=int(rng.integers(0, N_DAYS)))


rows = []

# ---------------------------------------------------------------- normal behaviour
for u in users:
    for d in range(N_DAYS):
        day = START + timedelta(days=d)
        if rng.random() > active_prob(u["type"], day.weekday()):
            continue
        for _ in range(max(1, int(rng.poisson(MEAN_LOGINS[u["type"]])))):
            loc = rng.choice(LOCATIONS, p=LOC_WEIGHTS[u["type"]])
            result, fails = normal_outcome()
            rows.append(row(u, at_hour(day, normal_hour(u["type"])), loc,
                            pick_device(u), result, fails))

# ---------------------------------------------------------------- harmless unusual events (label = normal)
for _ in range(N_TRIPS):                      # user travelling for 2-4 days, new device
    u = users[rng.integers(len(users))]
    start = START + timedelta(days=int(rng.integers(3, N_DAYS - 5)))
    loc = rng.choice(["other_city", "foreign_unknown"])
    dev = new_device() if rng.random() < 0.5 else u["devices"][0]
    for d in range(int(rng.integers(2, 5))):
        for _ in range(int(rng.integers(2, 5))):
            rows.append(row(u, at_hour(start + timedelta(days=d), normal_hour(u["type"])),
                            loc, dev, "success", 0, benign="benign_travel"))
for _ in range(N_NEW_PHONES):                 # user buys a new phone, normal time and place
    u = users[rng.integers(len(users))]
    dev, day = new_device(), random_day()
    dev["type"], dev["os"] = "phone", str(rng.choice(["Android", "iOS"]))
    dev["browser"] = str(rng.choice(BROWSERS[dev["os"]]))
    for _ in range(int(rng.integers(2, 4))):
        loc = rng.choice(LOCATIONS, p=LOC_WEIGHTS[u["type"]])
        rows.append(row(u, at_hour(day, normal_hour(u["type"])), loc, dev,
                        "success", 0, benign="benign_new_phone"))
for _ in range(N_LATE_NIGHTS):                # one-off late session (e.g. a deadline)
    u = users[rng.integers(len(users))]
    h = rng.choice(OBVIOUS_HOURS[u["type"]])
    loc = rng.choice(LOCATIONS, p=LOC_WEIGHTS[u["type"]])
    rows.append(row(u, at_hour(random_day(), h + rng.random()), loc, u["devices"][0],
                    "success", 0, benign="benign_late_night"))

# ---------------------------------------------------------------- injected anomalies (label = 1)
def odd_hour(u):
    pool = SUBTLE_HOURS if rng.random() < 0.5 else OBVIOUS_HOURS   # half subtle
    return rng.choice(pool[u["type"]]) + rng.random()


def odd_location(u):
    return rng.choice(["foreign_unknown", "vpn"]) if u["type"] == "remote_mixed" else \
        rng.choice(["other_city", "foreign_unknown", "vpn"])


for _ in range(N_EVENTS["unusual_hour"]):
    u = users[rng.integers(len(users))]
    loc = rng.choice(LOCATIONS, p=LOC_WEIGHTS[u["type"]])
    rows.append(row(u, at_hour(random_day(), odd_hour(u)), loc, pick_device(u),
                    "success", 0, 1, "unusual_hour"))
for _ in range(N_EVENTS["new_device"]):
    u = users[rng.integers(len(users))]
    loc = rng.choice(LOCATIONS, p=LOC_WEIGHTS[u["type"]])
    rows.append(row(u, at_hour(random_day(), normal_hour(u["type"])), loc, new_device(),
                    "success", 0, 1, "new_device"))
for _ in range(N_EVENTS["location_change"]):
    u = users[rng.integers(len(users))]
    rows.append(row(u, at_hour(random_day(), normal_hour(u["type"])), odd_location(u),
                    pick_device(u), "success", 0, 1, "location_change"))
for _ in range(N_EVENTS["combined"]):
    u = users[rng.integers(len(users))]
    rows.append(row(u, at_hour(random_day(), odd_hour(u)), "foreign_unknown", new_device(),
                    "success", 0, 1, "combined"))
for _ in range(N_EVENTS["failed_burst"]):     # brute force, sometimes ending in a takeover
    u = users[rng.integers(len(users))]
    ts = at_hour(random_day(), rng.uniform(0, 24))
    loc, dev, k = odd_location(u), new_device(), int(rng.integers(5, 16))
    for i in range(1, k + 1):
        ts += timedelta(seconds=int(rng.integers(5, 40)))
        rows.append(row(u, ts, loc, dev, "failure", i, 1, "failed_burst"))
    if rng.random() < 0.5:
        ts += timedelta(seconds=int(rng.integers(5, 40)))
        rows.append(row(u, ts, loc, dev, "success", k, 1, "takeover_after_burst"))

# ---------------------------------------------------------------- save
df = pd.DataFrame(rows).sort_values("timestamp").reset_index(drop=True)
df.insert(0, "login_id", [f"L{i + 1:06d}" for i in range(len(df))])
df["timestamp"] = df["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")
os.makedirs("data", exist_ok=True)
df.to_csv("data/login_data.csv", index=False)
pd.DataFrame([{"user_id": u["user_id"], "user_type": u["type"],
               "devices": ";".join(d["device_id"] for d in u["devices"])}
              for u in users]).to_csv("data/user_ground_truth.csv", index=False)

print(f"rows={len(df)}  users={df.user_id.nunique()}  "
      f"anomaly share={df.is_anomaly.mean():.2%}")
print(df.anomaly_type.value_counts().to_string())
print(df.benign_event.value_counts().to_string())
