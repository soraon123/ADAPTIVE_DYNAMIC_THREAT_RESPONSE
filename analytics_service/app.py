# analytics_service/app.py
# Analytics Service Microservice — threat intelligence & reporting for DTRS.
# Reads shared log data and exposes aggregated endpoints for the Dashboard.

import os
from flask import Flask, jsonify, request
import analytics

app = Flask(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/api/analytics/summary")
def summary():
    """Overall stats: total events, alerts, terminations, alert rate, etc."""
    return jsonify(analytics.compute_summary())


# ─────────────────────────────────────────────────────────────────────────────
# TOP PROCESSES
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/api/analytics/top-processes")
def top_processes():
    """Top threat actors ranked by threat score (alerts × 3 + terminations × 2)."""
    limit = int(request.args.get("limit", 10))
    return jsonify(processes=analytics.compute_top_processes(limit=limit))


# ─────────────────────────────────────────────────────────────────────────────
# CPU TRENDS
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/api/analytics/trends")
def trends():
    """
    Time-bucketed CPU averages and event counts.
    Query params: hours (default 24), bucket_minutes (default 30)
    """
    hours          = int(request.args.get("hours", 24))
    bucket_minutes = int(request.args.get("bucket_minutes", 30))
    data = analytics.compute_cpu_trends(hours=hours, bucket_minutes=bucket_minutes)
    return jsonify(trends=data, hours=hours, bucket_minutes=bucket_minutes)


# ─────────────────────────────────────────────────────────────────────────────
# HEATMAP
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/api/analytics/heatmap")
def heatmap():
    """Alert frequency by hour-of-day × day-of-week (7×24 grid)."""
    return jsonify(analytics.compute_heatmap())


# ─────────────────────────────────────────────────────────────────────────────
# RISK DISTRIBUTION
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/api/analytics/risk-distribution")
def risk_distribution():
    """Count of log events broken down by risk level (HIGH / MEDIUM / LOW)."""
    return jsonify(analytics.compute_risk_distribution())


# ─────────────────────────────────────────────────────────────────────────────
# HEALTH
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/health")
def health():
    summary = analytics.compute_summary()
    return jsonify(
        status="ok",
        service="analytics-service",
        total_events=summary.get("total_events", 0),
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5003))
    app.run(debug=False, host="0.0.0.0", port=port)
