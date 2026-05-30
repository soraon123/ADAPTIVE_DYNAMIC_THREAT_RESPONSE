# analytics_service/analytics.py
# Aggregation and trend computation for the DTRS Analytics Service.
# Reads from the shared logs.json written by the Detection Engine.

import json
import os
from collections import defaultdict
from datetime import datetime, timedelta

DATA_DIR  = os.environ.get("DATA_DIR", ".")
LOGS_FILE = os.path.join(DATA_DIR, "logs.json")

# ── Log Loader ────────────────────────────────────────────────────────────────
def load_logs() -> list:
    if not os.path.exists(LOGS_FILE):
        return []
    try:
        with open(LOGS_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return []


# ── Summary Stats ─────────────────────────────────────────────────────────────
def compute_summary() -> dict:
    """
    Returns overall threat stats:
      - total_events, total_alerts, total_terminated, total_ignored
      - alert_rate (alerts / total)
      - last_event_at
    """
    logs = load_logs()
    total        = len(logs)
    alerts       = sum(1 for e in logs if e.get("action") == "alert")
    terminated   = sum(1 for e in logs if e.get("action") == "terminated")
    ignored      = sum(1 for e in logs if e.get("action") == "ignored")
    logged_med   = sum(1 for e in logs if e.get("action") == "logged")
    access_denied = sum(1 for e in logs if e.get("action") == "access-denied")
    refused      = sum(1 for e in logs if e.get("action") == "refused-system-critical")

    last_event = logs[-1].get("timestamp") if logs else None

    return {
        "total_events":    total,
        "total_alerts":    alerts,
        "total_terminated": terminated,
        "total_ignored":   ignored,
        "total_logged":    logged_med,
        "total_access_denied": access_denied,
        "total_refused":   refused,
        "alert_rate":      round(alerts / total * 100, 1) if total else 0,
        "last_event_at":   last_event,
    }


# ── Top Offending Processes ───────────────────────────────────────────────────
def compute_top_processes(limit: int = 10) -> list:
    """
    Returns the top N processes by alert + termination count,
    including average CPU and most recent sighting.
    """
    logs = load_logs()

    stats: dict = defaultdict(lambda: {
        "name": "",
        "alert_count": 0,
        "terminated_count": 0,
        "ignored_count": 0,
        "total_cpu": 0.0,
        "event_count": 0,
        "last_seen": None,
    })

    for entry in logs:
        name   = entry.get("process", "unknown")
        action = entry.get("action", "")
        cpu    = float(entry.get("cpu", 0.0))
        ts     = entry.get("timestamp")

        row = stats[name]
        row["name"] = name
        row["event_count"] += 1
        row["total_cpu"]   += cpu

        if action == "alert":
            row["alert_count"] += 1
        elif action == "terminated":
            row["terminated_count"] += 1
        elif action == "ignored":
            row["ignored_count"] += 1

        if ts and (row["last_seen"] is None or ts > row["last_seen"]):
            row["last_seen"] = ts

    result = []
    for name, row in stats.items():
        ec = row["event_count"]
        result.append({
            "name":             name,
            "alert_count":      row["alert_count"],
            "terminated_count": row["terminated_count"],
            "ignored_count":    row["ignored_count"],
            "event_count":      ec,
            "avg_cpu":          round(row["total_cpu"] / ec, 1) if ec else 0.0,
            "last_seen":        row["last_seen"],
            "threat_score":     row["alert_count"] * 3 + row["terminated_count"] * 2,
        })

    result.sort(key=lambda x: x["threat_score"], reverse=True)
    return result[:limit]


# ── CPU Trend (time-series buckets) ──────────────────────────────────────────
def compute_cpu_trends(hours: int = 24, bucket_minutes: int = 30) -> list:
    """
    Returns a list of time-bucket dicts: { bucket, avg_cpu, max_cpu, event_count }
    for the last `hours` hours in `bucket_minutes`-sized windows.
    """
    logs = load_logs()
    now  = datetime.now()
    cutoff = now - timedelta(hours=hours)

    # Build buckets
    total_buckets = (hours * 60) // bucket_minutes
    buckets: dict = {}
    for i in range(total_buckets):
        t = cutoff + timedelta(minutes=i * bucket_minutes)
        label = t.strftime("%H:%M")
        buckets[label] = {"bucket": label, "avg_cpu": 0.0, "max_cpu": 0.0, "event_count": 0, "_total_cpu": 0.0}

    for entry in logs:
        ts_str = entry.get("timestamp")
        if not ts_str:
            continue
        try:
            ts = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
        if ts < cutoff:
            continue

        # Find which bucket this entry falls into
        delta_min = (ts - cutoff).total_seconds() / 60
        bucket_idx = int(delta_min // bucket_minutes)
        if 0 <= bucket_idx < total_buckets:
            t = cutoff + timedelta(minutes=bucket_idx * bucket_minutes)
            label = t.strftime("%H:%M")
            if label in buckets:
                cpu = float(entry.get("cpu", 0.0))
                b   = buckets[label]
                b["event_count"] += 1
                b["_total_cpu"]  += cpu
                b["max_cpu"] = max(b["max_cpu"], cpu)

    # Finalize averages
    result = []
    for label in sorted(buckets.keys()):
        b = buckets[label]
        ec = b["event_count"]
        result.append({
            "bucket":      label,
            "avg_cpu":     round(b["_total_cpu"] / ec, 1) if ec else 0.0,
            "max_cpu":     round(b["max_cpu"], 1),
            "event_count": ec,
        })

    return result


# ── Alert Heatmap (hour-of-day × day-of-week) ─────────────────────────────────
def compute_heatmap() -> dict:
    """
    Returns a 7×24 heatmap of alert counts by day-of-week and hour-of-day.
    days: 0=Mon … 6=Sun, hours: 0–23
    """
    logs = load_logs()
    grid: dict = defaultdict(int)  # (day, hour) -> count

    for entry in logs:
        if entry.get("action") not in ("alert", "terminated"):
            continue
        ts_str = entry.get("timestamp")
        if not ts_str:
            continue
        try:
            ts = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
            grid[(ts.weekday(), ts.hour)] += 1
        except ValueError:
            continue

    days  = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    hours = list(range(24))

    cells = []
    for day_idx in range(7):
        for hour in hours:
            cells.append({
                "day":   days[day_idx],
                "hour":  hour,
                "count": grid.get((day_idx, hour), 0),
            })

    max_count = max((c["count"] for c in cells), default=1)

    return {
        "days":      days,
        "hours":     hours,
        "cells":     cells,
        "max_count": max_count,
    }


# ── Risk Distribution ─────────────────────────────────────────────────────────
def compute_risk_distribution() -> dict:
    """Count events broken down by risk level."""
    logs = load_logs()
    dist: dict = defaultdict(int)
    for entry in logs:
        dist[entry.get("risk", "UNKNOWN")] += 1
    return {
        "HIGH":    dist.get("HIGH",    0),
        "MEDIUM":  dist.get("MEDIUM",  0),
        "LOW":     dist.get("LOW",     0),
        "UNKNOWN": dist.get("UNKNOWN", 0),
    }
