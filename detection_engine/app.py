# detection_engine/app.py
# Detection Engine Microservice — the brain of DTRS.
# Receives process snapshots from Agent, evaluates risk,
# stores state, queues actions, and serves data to the Dashboard.
# Now integrates with Policy Engine (rules/thresholds) and
# Notification Service (webhook alerts).

from flask import Flask, jsonify, request
import threading
import os
import requests as _requests
import detection

app = Flask(__name__)

# ── Service URLs ──────────────────────────────────────────────────────────────
NOTIFICATION_SERVICE_URL = os.environ.get(
    "NOTIFICATION_SERVICE_URL", "http://localhost:5002"
).rstrip("/")

# ── In-Memory State ────────────────────────────────────────────────────────────
_lock         = threading.Lock()
_processes    = []   # latest snapshot from agent
_alerts       = []   # active HIGH-risk alerts
_action_queue = []   # pending actions to send to agent: [{pid, action, name, cpu}]


# ── Notification Helper ────────────────────────────────────────────────────────
def _fire_notifications(new_alerts: list) -> None:
    """POST each new alert to the Notification Service (non-blocking)."""
    if not new_alerts:
        return

    def _dispatch():
        for alert in new_alerts:
            try:
                _requests.post(
                    f"{NOTIFICATION_SERVICE_URL}/api/notify/alert",
                    json={"alert": alert},
                    timeout=5,
                )
            except Exception as exc:
                print(f"[detection-engine] notification dispatch failed: {exc}")

    threading.Thread(target=_dispatch, daemon=True).start()


# ═════════════════════════════════════════════════════════════════════════════
# AGENT-FACING ENDPOINTS
# ═════════════════════════════════════════════════════════════════════════════

@app.route("/api/agent/report", methods=["POST"])
def agent_report():
    """
    Agent posts its raw process list here every scan cycle.
    We evaluate each process and update in-memory state.
    Returns: active alerts so the agent can fire local toasts.
    """
    data         = request.get_json(silent=True) or {}
    raw_processes = data.get("processes", [])

    snapshot       = []
    new_alert_pids = set()

    for proc in raw_processes:
        name = proc.get("name", "unknown")
        cpu  = float(proc.get("cpu", 0.0))
        mem  = float(proc.get("mem", 0.0))
        pid  = int(proc.get("pid", -1))

        decision = detection.evaluate_process(name, cpu, mem)
        row = {
            "pid":    pid,
            "name":   name,
            "cpu":    round(cpu, 2),
            "mem":    round(mem, 2),
            "risk":   decision["risk"],
            "action": decision["action"],
            "reason": decision["reason"],
        }
        snapshot.append(row)

        if decision["action"] == "alert":
            new_alert_pids.add(pid)

    newly_added = []
    with _lock:
        global _processes, _alerts
        _processes = snapshot

        existing_pids = {a["pid"] for a in _alerts}
        running_pids  = {p["pid"] for p in snapshot}

        # Drop alerts for dead processes
        _alerts = [a for a in _alerts if a["pid"] in running_pids]

        # Add brand-new alerts
        for row in snapshot:
            if row["pid"] in new_alert_pids and row["pid"] not in existing_pids:
                _alerts.append(row)
                newly_added.append(row)

    # Fire webhooks for newly detected alerts (non-blocking)
    _fire_notifications(newly_added)

    return jsonify(new_alerts=newly_added, alert_count=len(_alerts))


@app.route("/api/agent/actions", methods=["GET"])
def agent_get_actions():
    """
    Agent polls this to receive pending user-initiated actions (e.g., terminate PID).
    Actions are cleared after being sent once.
    """
    with _lock:
        global _action_queue
        pending = list(_action_queue)
        _action_queue = []
    return jsonify(actions=pending)


@app.route("/api/agent/action-result", methods=["POST"])
def agent_action_result():
    """Agent reports the result of executing a terminate action."""
    data    = request.get_json(silent=True) or {}
    pid     = int(data.get("pid", -1))
    success = data.get("success", False)
    message = data.get("message", "")
    name    = data.get("name", "unknown")
    cpu     = float(data.get("cpu", 0.0))

    with _lock:
        global _alerts
        _alerts = [a for a in _alerts if a["pid"] != pid]

    if success:
        detection.record_action_cooldown(name)
        detection.log_event(name, cpu, "HIGH", "terminated")
    else:
        detection.log_event(name, cpu, "HIGH", "access-denied")

    return jsonify(ok=True)


# ═════════════════════════════════════════════════════════════════════════════
# DASHBOARD-FACING (INTERNAL) ENDPOINTS
# ═════════════════════════════════════════════════════════════════════════════

@app.route("/api/internal/processes", methods=["GET"])
def internal_processes():
    with _lock:
        procs = list(_processes)
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    procs.sort(key=lambda p: order.get(p["risk"], 3))
    return jsonify(processes=procs, alert_count=len(_alerts))


@app.route("/api/internal/alerts", methods=["GET"])
def internal_alerts():
    with _lock:
        alerts = list(_alerts)
    return jsonify(alerts=alerts)


@app.route("/api/internal/logs", methods=["GET"])
def internal_logs():
    logs = list(reversed(detection.load_logs()))
    return jsonify(logs=logs)


@app.route("/api/internal/whitelist", methods=["GET"])
def internal_whitelist():
    wl  = sorted(detection.load_whitelist())
    awl = detection.load_auto_whitelist()
    return jsonify(whitelist=wl, auto_whitelist=awl)


@app.route("/api/internal/whitelist/add", methods=["POST"])
def internal_whitelist_add():
    data = request.get_json(silent=True) or {}
    name = data.get("name", "").strip()
    if name:
        detection.add_to_whitelist(name)
        return jsonify(ok=True, message=f"'{name}' added to whitelist.")
    return jsonify(ok=False, message="No name provided."), 400


@app.route("/api/internal/whitelist/remove", methods=["POST"])
def internal_whitelist_remove():
    data = request.get_json(silent=True) or {}
    name = data.get("name", "").strip()
    if name:
        detection.remove_from_whitelist(name)
        return jsonify(ok=True, message=f"'{name}' removed from whitelist.")
    return jsonify(ok=False, message="No name provided."), 400


@app.route("/api/internal/auto-whitelist", methods=["GET"])
def internal_auto_whitelist():
    awl       = detection.load_auto_whitelist()
    threshold = detection.AUTO_WHITELIST_THRESHOLD
    return jsonify(auto_whitelist=awl, threshold=threshold)


@app.route("/api/internal/queue-action", methods=["POST"])
def internal_queue_action():
    """
    Dashboard queues a terminate/ignore action.
    For 'ignore', we handle it here directly.
    For 'terminate', push to agent queue.
    """
    data   = request.get_json(silent=True) or {}
    pid    = int(data.get("pid", -1))
    act    = data.get("action", "ignore")
    name   = data.get("name", "unknown")
    cpu    = float(data.get("cpu", 0.0))

    lname = name.lower().strip()

    if act == "ignore":
        with _lock:
            global _alerts
            _alerts = [a for a in _alerts if a["pid"] != pid]
        detection.record_action_cooldown(name)
        detection.log_event(name, cpu, "HIGH", "ignored")
        return jsonify(success=True, message=f"Alert for '{name}' dismissed.")

    elif act == "terminate":
        if lname in {s.lower() for s in detection.SYSTEM_CRITICAL}:
            with _lock:
                _alerts[:] = [a for a in _alerts if a["pid"] != pid]
            detection.log_event(name, cpu, "HIGH", "refused-system-critical")
            return jsonify(success=False, message="Cannot terminate system-critical process.")

        with _lock:
            _action_queue.append({"pid": pid, "action": "terminate", "name": name, "cpu": cpu})
        return jsonify(success=True, message=f"Terminate command queued for '{name}' (PID {pid}).")

    return jsonify(success=False, message="Unknown action."), 400


# ── Health Check ───────────────────────────────────────────────────────────────
@app.route("/health")
def health():
    return jsonify(status="ok", service="detection-engine")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))
    app.run(debug=False, host="0.0.0.0", port=port)
