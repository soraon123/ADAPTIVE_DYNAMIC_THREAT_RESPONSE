# dashboard/app.py
# Web Dashboard Microservice – completely stateless Flask frontend.
# All data is fetched from the Detection Engine, Analytics, Policy Engine,
# and Notification Service via HTTP.

import os
import requests
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "dtrs-dashboard-secret-2025")

# ── Service URLs ──────────────────────────────────────────────────────────────
DE_URL   = os.environ.get("DETECTION_ENGINE_URL",   "http://localhost:5001").rstrip("/")
AN_URL   = os.environ.get("ANALYTICS_SERVICE_URL",  "http://localhost:5003").rstrip("/")
PE_URL   = os.environ.get("POLICY_ENGINE_URL",       "http://localhost:5004").rstrip("/")
NS_URL   = os.environ.get("NOTIFICATION_SERVICE_URL","http://localhost:5002").rstrip("/")


def _call(base: str, path: str, method: str = "GET", json_body: dict = None, timeout: int = 8):
    """Generic service call helper. Returns parsed JSON or None on error."""
    url = f"{base}{path}"
    try:
        if method == "POST":
            resp = requests.post(url, json=json_body or {}, timeout=timeout)
        elif method == "PATCH":
            resp = requests.patch(url, json=json_body or {}, timeout=timeout)
        elif method == "DELETE":
            resp = requests.delete(url, timeout=timeout)
        else:
            resp = requests.get(url, timeout=timeout)
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        print(f"[dashboard] {method} {url} failed: {exc}")
        return None


def _de(path, method="GET", json_body=None):
    return _call(DE_URL, path, method, json_body)

def _an(path, method="GET", json_body=None):
    return _call(AN_URL, path, method, json_body)

def _pe(path, method="GET", json_body=None):
    return _call(PE_URL, path, method, json_body)

def _ns(path, method="GET", json_body=None):
    return _call(NS_URL, path, method, json_body)


# ─────────────────────────────────────────────────────────────────────────────
# HOME – Live process table
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/")
def home():
    data        = _de("/api/internal/processes") or {"processes": [], "alert_count": 0}
    processes   = data.get("processes", [])
    alert_count = data.get("alert_count", 0)
    return render_template("home.html", processes=processes, alert_count=alert_count)


@app.route("/api/processes")
def api_processes():
    data = _de("/api/internal/processes") or {"processes": [], "alert_count": 0}
    return jsonify(processes=data.get("processes", []), alert_count=data.get("alert_count", 0))


# ─────────────────────────────────────────────────────────────────────────────
# ALERTS
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/alerts")
def alerts():
    data   = _de("/api/internal/alerts") or {"alerts": []}
    return render_template("alerts.html", alerts=data.get("alerts", []))


@app.route("/api/alerts")
def api_alerts():
    data = _de("/api/internal/alerts") or {"alerts": []}
    return jsonify(alerts=data.get("alerts", []))


# ─────────────────────────────────────────────────────────────────────────────
# ACTION
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/action", methods=["POST"])
def action():
    body   = request.get_json(silent=True) or {}
    result = _de("/api/internal/queue-action", method="POST", json_body=body)
    if result:
        return jsonify(success=result.get("success", False), message=result.get("message", ""))
    return jsonify(success=False, message="Detection Engine unreachable."), 502


@app.route("/quick-action/<int:pid>/<action_name>/<name>/<float:cpu>")
def quick_action(pid: int, action_name: str, name: str, cpu: float):
    body   = {"pid": pid, "action": action_name, "name": name, "cpu": cpu}
    result = _de("/api/internal/queue-action", method="POST", json_body=body)
    if result:
        cat = "success" if result.get("success") else "error"
        flash(result.get("message", ""), cat)
    else:
        flash("Detection Engine unreachable.", "error")
    return redirect(url_for("alerts"))


# ─────────────────────────────────────────────────────────────────────────────
# LOGS
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/logs")
def logs():
    data = _de("/api/internal/logs") or {"logs": []}
    return render_template("logs.html", logs=data.get("logs", []))


@app.route("/api/logs")
def api_logs():
    data = _de("/api/internal/logs") or {"logs": []}
    return jsonify(logs=data.get("logs", []))


# ─────────────────────────────────────────────────────────────────────────────
# WHITELIST
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/whitelist")
def whitelist():
    data = _de("/api/internal/whitelist") or {"whitelist": [], "auto_whitelist": {}}
    return render_template(
        "whitelist.html",
        whitelist=data.get("whitelist", []),
        auto_whitelist=data.get("auto_whitelist", {}),
    )


@app.route("/whitelist/add", methods=["POST"])
def whitelist_add():
    name = (request.form.get("process_name") or "").strip()
    if name:
        result = _de("/api/internal/whitelist/add", method="POST", json_body={"name": name})
        flash(result.get("message", f"'{name}' added.") if result and result.get("ok") else "Failed to add.", "success" if result and result.get("ok") else "error")
    else:
        flash("Please enter a process name.", "error")
    return redirect(url_for("whitelist"))


@app.route("/whitelist/remove", methods=["POST"])
def whitelist_remove():
    name = (request.form.get("process_name") or "").strip()
    if name:
        result = _de("/api/internal/whitelist/remove", method="POST", json_body={"name": name})
        flash(result.get("message", f"'{name}' removed.") if result and result.get("ok") else "Failed to remove.", "success" if result and result.get("ok") else "error")
    return redirect(url_for("whitelist"))


@app.route("/auto-whitelist")
def auto_whitelist():
    data = _de("/api/internal/auto-whitelist") or {"auto_whitelist": {}, "threshold": 5}
    return render_template(
        "auto_whitelist.html",
        auto_whitelist=data.get("auto_whitelist", {}),
        threshold=data.get("threshold", 5),
    )


# ─────────────────────────────────────────────────────────────────────────────
# ANALYTICS
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/analytics")
def analytics():
    summary   = _an("/api/analytics/summary")          or {}
    top_procs = _an("/api/analytics/top-processes")    or {"processes": []}
    trends    = _an("/api/analytics/trends")           or {"trends": []}
    heatmap   = _an("/api/analytics/heatmap")          or {"cells": [], "days": [], "hours": [], "max_count": 1}
    risk_dist = _an("/api/analytics/risk-distribution") or {}
    return render_template(
        "analytics.html",
        summary=summary,
        top_processes=top_procs.get("processes", []),
        trends=trends.get("trends", []),
        heatmap=heatmap,
        risk_dist=risk_dist,
    )


@app.route("/api/analytics/summary")
def api_analytics_summary():
    return jsonify(_an("/api/analytics/summary") or {})

@app.route("/api/analytics/trends")
def api_analytics_trends():
    return jsonify(_an("/api/analytics/trends") or {})

@app.route("/api/analytics/top-processes")
def api_analytics_top():
    return jsonify(_an("/api/analytics/top-processes") or {})


# ─────────────────────────────────────────────────────────────────────────────
# POLICY ENGINE
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/policy")
def policy():
    full_policy = _pe("/api/policy") or {}
    return render_template("policy.html", policy=full_policy)


@app.route("/policy/thresholds", methods=["POST"])
def policy_thresholds():
    try:
        low_max    = float(request.form.get("low_max", 40))
        medium_max = float(request.form.get("medium_max", 70))
    except ValueError:
        flash("Invalid threshold values.", "error")
        return redirect(url_for("policy"))
    result = _pe("/api/policy/thresholds", method="POST", json_body={"low_max": low_max, "medium_max": medium_max})
    if result and result.get("ok"):
        flash(f"Thresholds updated: LOW < {low_max}%, MEDIUM ≤ {medium_max}%, HIGH > {medium_max}%", "success")
    else:
        flash(result.get("message", "Failed to update thresholds.") if result else "Policy Engine unreachable.", "error")
    return redirect(url_for("policy"))


@app.route("/policy/settings", methods=["POST"])
def policy_settings():
    try:
        cooldown_hours           = float(request.form.get("cooldown_hours", 2.0))
        auto_whitelist_threshold = int(request.form.get("auto_whitelist_threshold", 5))
    except ValueError:
        flash("Invalid setting values.", "error")
        return redirect(url_for("policy"))
    result = _pe("/api/policy/settings", method="POST", json_body={
        "cooldown_hours": cooldown_hours,
        "auto_whitelist_threshold": auto_whitelist_threshold,
    })
    if result and result.get("ok"):
        flash("Settings updated successfully.", "success")
    else:
        flash("Failed to update settings.", "error")
    return redirect(url_for("policy"))


@app.route("/policy/rules/add", methods=["POST"])
def policy_rule_add():
    name   = (request.form.get("name") or "").strip()
    action = (request.form.get("action") or "").strip()
    reason = (request.form.get("reason") or "").strip()
    if not name or not action:
        flash("Process name and action are required.", "error")
        return redirect(url_for("policy"))
    result = _pe("/api/policy/rules", method="POST", json_body={"name": name, "action": action, "reason": reason})
    if result and result.get("ok"):
        flash(f"Rule for '{name}' saved: {action}", "success")
    else:
        flash(result.get("message", "Failed to save rule.") if result else "Policy Engine unreachable.", "error")
    return redirect(url_for("policy"))


@app.route("/policy/rules/delete", methods=["POST"])
def policy_rule_delete():
    name = (request.form.get("name") or "").strip()
    if not name:
        flash("No process name provided.", "error")
        return redirect(url_for("policy"))
    result = _call(PE_URL, f"/api/policy/rules/{name}", method="DELETE")
    if result and result.get("ok"):
        flash(f"Rule for '{name}' deleted.", "success")
    else:
        flash(result.get("message", "Failed to delete rule.") if result else "Policy Engine unreachable.", "error")
    return redirect(url_for("policy"))


# ─────────────────────────────────────────────────────────────────────────────
# NOTIFICATIONS
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/notifications")
def notifications():
    data = _ns("/api/notify/config") or {"config": {}}
    return render_template("notifications.html", config=data.get("config", {}))


@app.route("/notifications/config", methods=["POST"])
def notifications_config():
    enabled          = request.form.get("enabled") == "on"
    min_risk         = request.form.get("min_risk", "HIGH")
    cooldown_seconds = int(request.form.get("cooldown_seconds", 60))
    result = _ns("/api/notify/config", method="POST", json_body={
        "enabled": enabled,
        "min_risk": min_risk,
        "cooldown_seconds": cooldown_seconds,
    })
    if result and result.get("ok"):
        flash("Notification settings updated.", "success")
    else:
        flash("Failed to update notification settings.", "error")
    return redirect(url_for("notifications"))


@app.route("/notifications/webhooks/add", methods=["POST"])
def webhooks_add():
    url   = (request.form.get("url") or "").strip()
    name  = (request.form.get("name") or "").strip()
    wtype = (request.form.get("type") or "generic").strip().lower()
    if not url:
        flash("Webhook URL is required.", "error")
        return redirect(url_for("notifications"))
    result = _ns("/api/notify/webhooks", method="POST", json_body={"url": url, "name": name, "type": wtype, "enabled": True})
    if result and result.get("ok"):
        flash(f"Webhook '{name or url}' added.", "success")
    else:
        flash(result.get("message", "Failed to add webhook.") if result else "Notification Service unreachable.", "error")
    return redirect(url_for("notifications"))


@app.route("/notifications/webhooks/<webhook_id>/toggle", methods=["POST"])
def webhooks_toggle(webhook_id: str):
    enabled = request.form.get("enabled") == "true"
    result  = _call(NS_URL, f"/api/notify/webhooks/{webhook_id}", method="PATCH", json_body={"enabled": enabled})
    if result and result.get("ok"):
        flash(f"Webhook {'enabled' if enabled else 'disabled'}.", "success")
    else:
        flash("Failed to update webhook.", "error")
    return redirect(url_for("notifications"))


@app.route("/notifications/webhooks/<webhook_id>/delete", methods=["POST"])
def webhooks_delete(webhook_id: str):
    result = _call(NS_URL, f"/api/notify/webhooks/{webhook_id}", method="DELETE")
    if result and result.get("ok"):
        flash("Webhook deleted.", "success")
    else:
        flash("Failed to delete webhook.", "error")
    return redirect(url_for("notifications"))


@app.route("/notifications/webhooks/<webhook_id>/test", methods=["POST"])
def webhooks_test(webhook_id: str):
    result = _ns(f"/api/notify/webhooks/{webhook_id}/test", method="POST")
    if result:
        ok = result.get("ok", False)
        flash(f"Test {'succeeded ✅' if ok else 'failed ❌'}: {result.get('result', {}).get('error', '')}", "success" if ok else "error")
    else:
        flash("Notification Service unreachable.", "error")
    return redirect(url_for("notifications"))


# ─────────────────────────────────────────────────────────────────────────────
# HEALTH
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/health")
def health():
    return jsonify(
        status="ok",
        service="dashboard",
        detection_engine_reachable=_de("/health") is not None,
        analytics_reachable=_an("/health") is not None,
        policy_engine_reachable=_pe("/health") is not None,
        notification_service_reachable=_ns("/health") is not None,
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=False, host="0.0.0.0", port=port)
