# app.py
# Flask application – all routes for the Adaptive Dynamic Threat Response System

from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
import psutil
import os

import monitor
import detection

app = Flask(__name__)
app.secret_key = "dtrs-secret-2025"   # needed for flash messages

# Start background monitor on first import
monitor.start_monitor()


# ─────────────────────────────────────────────────────────────────────────────
# HOME – Live process table
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/")
def home():
    processes = monitor.get_processes()
    # Sort: HIGH first, then MEDIUM, then LOW
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    processes.sort(key=lambda p: order.get(p["risk"], 3))
    alert_count = len(monitor.get_alerts())
    return render_template("home.html", processes=processes, alert_count=alert_count)


# ─────────────────────────────────────────────────────────────────────────────
# API – Live process snapshot (JSON for polling)
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/api/processes")
def api_processes():
    processes = monitor.get_processes()
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    processes.sort(key=lambda p: order.get(p["risk"], 3))
    return jsonify(processes=processes, alert_count=len(monitor.get_alerts()))


# ─────────────────────────────────────────────────────────────────────────────
# ALERTS – HIGH-risk processes awaiting user decision
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/alerts")
def alerts():
    alerts = monitor.get_alerts()
    return render_template("alerts.html", alerts=alerts)


@app.route("/api/alerts")
def api_alerts():
    return jsonify(alerts=monitor.get_alerts())


# ─────────────────────────────────────────────────────────────────────────────
# ACTION – User-initiated terminate or ignore
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/action", methods=["POST"])
def action():
    data   = request.get_json(silent=True) or {}
    pid    = int(data.get("pid", -1))
    act    = data.get("action", "ignore")   # "terminate" or "ignore"
    pname  = data.get("name", "unknown")
    cpu    = float(data.get("cpu", 0.0))

    result_msg = ""

    if act == "terminate":
        lname = pname.lower().strip()
        # Safety guard: never touch system-critical processes
        if lname in {s.lower() for s in detection.SYSTEM_CRITICAL}:
            monitor.remove_alert(pid)
            detection.log_event(pname, cpu, "HIGH", "refused-system-critical")
            return jsonify(success=False, message="Cannot terminate system-critical process.")

        try:
            proc = psutil.Process(pid)
            proc.terminate()
            monitor.remove_alert(pid)
            detection.log_event(pname, cpu, "HIGH", "terminated")
            detection.record_action_cooldown(pname)
            result_msg = f"Process '{pname}' (PID {pid}) terminated."
            return jsonify(success=True, message=result_msg)
        except psutil.NoSuchProcess:
            monitor.remove_alert(pid)
            detection.log_event(pname, cpu, "HIGH", "already-gone")
            detection.record_action_cooldown(pname)
            return jsonify(success=True, message=f"Process '{pname}' was already gone.")
        except psutil.AccessDenied:
            detection.log_event(pname, cpu, "HIGH", "access-denied")
            detection.record_action_cooldown(pname)
            return jsonify(success=False, message=f"Access denied – cannot terminate '{pname}'.")
        except Exception as exc:
            return jsonify(success=False, message=str(exc))

    else:   # ignore
        monitor.remove_alert(pid)
        detection.log_event(pname, cpu, "HIGH", "ignored")
        detection.record_action_cooldown(pname)
        return jsonify(success=True, message=f"Alert for '{pname}' dismissed.")


# ─────────────────────────────────────────────────────────────────────────────
# QUICK ACTION – Handles clicks from Windows toast notification buttons
# URL: /quick-action/<pid>/<action>/<name>/<cpu>
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/quick-action/<int:pid>/<action>/<name>/<float:cpu>")
def quick_action(pid: int, action: str, name: str, cpu: float):
    """
    Called when the user clicks 'Terminate' or 'Ignore' inside a Windows
    desktop toast notification.  Performs the action and redirects to /alerts.
    """
    if action == "terminate":
        lname = name.lower().strip()
        if lname in {s.lower() for s in detection.SYSTEM_CRITICAL}:
            monitor.remove_alert(pid)
            detection.log_event(name, cpu, "HIGH", "refused-system-critical")
            flash(f"Cannot terminate system-critical process '{name}'.", "error")
        else:
            try:
                proc = psutil.Process(pid)
                proc.terminate()
                monitor.remove_alert(pid)
                detection.log_event(name, cpu, "HIGH", "terminated")
                detection.record_action_cooldown(name)
                flash(f"✅ Process '{name}' (PID {pid}) terminated via notification.", "success")
            except psutil.NoSuchProcess:
                monitor.remove_alert(pid)
                detection.log_event(name, cpu, "HIGH", "already-gone")
                detection.record_action_cooldown(name)
                flash(f"Process '{name}' was already gone.", "success")
            except psutil.AccessDenied:
                detection.log_event(name, cpu, "HIGH", "access-denied")
                detection.record_action_cooldown(name)
                flash(f"⚠️ Access denied – cannot terminate '{name}'.", "error")
            except Exception as exc:
                flash(str(exc), "error")
    else:   # ignore
        monitor.remove_alert(pid)
        detection.log_event(name, cpu, "HIGH", "ignored")
        detection.record_action_cooldown(name)
        flash(f"Alert for '{name}' dismissed via notification.", "success")

    return redirect(url_for("alerts"))


# ─────────────────────────────────────────────────────────────────────────────
# LOGS – Event history
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/logs")
def logs():
    all_logs = detection.load_logs()
    all_logs = list(reversed(all_logs))     # newest first
    return render_template("logs.html", logs=all_logs)


@app.route("/api/logs")
def api_logs():
    return jsonify(logs=list(reversed(detection.load_logs())))


# ─────────────────────────────────────────────────────────────────────────────
# WHITELIST MANAGER
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/whitelist")
def whitelist():
    wl = sorted(detection.load_whitelist())
    awl = detection.load_auto_whitelist()
    return render_template("whitelist.html", whitelist=wl, auto_whitelist=awl)


@app.route("/whitelist/add", methods=["POST"])
def whitelist_add():
    name = (request.form.get("process_name") or "").strip()
    if name:
        detection.add_to_whitelist(name)
        flash(f"'{name}' added to whitelist.", "success")
    else:
        flash("Please enter a process name.", "error")
    return redirect(url_for("whitelist"))


@app.route("/whitelist/remove", methods=["POST"])
def whitelist_remove():
    name = (request.form.get("process_name") or "").strip()
    if name:
        detection.remove_from_whitelist(name)
        flash(f"'{name}' removed from whitelist.", "success")
    return redirect(url_for("whitelist"))


# ─────────────────────────────────────────────────────────────────────────────
# AUTO-WHITELIST VIEW
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/auto-whitelist")
def auto_whitelist():
    awl = detection.load_auto_whitelist()
    threshold = detection.AUTO_WHITELIST_THRESHOLD
    return render_template("auto_whitelist.html", auto_whitelist=awl, threshold=threshold)


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app.run(debug=True, use_reloader=False, host="0.0.0.0", port=5000)
