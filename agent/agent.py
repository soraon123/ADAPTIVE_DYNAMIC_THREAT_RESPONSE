# agent/agent.py
# Agent Microservice – runs locally on the machine to be monitored.
# Responsibilities:
#   1. Collect running processes via psutil
#   2. POST raw snapshot to the Detection Engine
#   3. Show Windows toast notifications for new HIGH-risk alerts
#   4. Poll the Detection Engine for pending terminate actions
#   5. Execute terminations locally and report results back

import os
import time
import psutil
import requests

# ── Config ─────────────────────────────────────────────────────────────────
DETECTION_ENGINE_URL = os.environ.get(
    "DETECTION_ENGINE_URL", "http://localhost:5001"
).rstrip("/")

SCAN_INTERVAL   = int(os.environ.get("SCAN_INTERVAL", 3))    # seconds between scans
ACTION_INTERVAL = int(os.environ.get("ACTION_INTERVAL", 2))  # seconds between action polls

# ── Desktop Notifications (Windows only) ───────────────────────────────────
try:
    from winotify import Notification, audio
    _NOTIFY_AVAILABLE = True
except ImportError:
    _NOTIFY_AVAILABLE = False

DASHBOARD_URL = os.environ.get("DASHBOARD_URL", "http://localhost:5000")


def _notify_new_alert(pid: int, name: str, cpu: float, mem: float) -> None:
    """Fire a native Windows toast for a new HIGH-risk process."""
    if not _NOTIFY_AVAILABLE:
        print(f"[agent] NEW ALERT (no toast): {name} PID={pid} CPU={cpu:.1f}% Mem={mem:.1f}%")
        return
    try:
        toast = Notification(
            app_id="DTRS – Threat Response",
            title="🚨 HIGH-Risk Process Detected",
            msg=f"{name}  |  PID {pid}  |  CPU {cpu:.1f}%  |  Mem {mem:.1f}%",
            duration="long",
            icon="",
        )
        toast.set_audio(audio.Default, loop=False)
        toast.add_actions(
            label="View Alerts",
            launch=f"{DASHBOARD_URL}/alerts",
        )
        toast.show()
    except Exception as exc:
        print(f"[agent] toast error: {exc}")


# ── Process Collector ───────────────────────────────────────────────────────
def collect_processes() -> list:
    """Gather all running processes using psutil."""
    snapshot = []
    for proc in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent"]):
        try:
            info = proc.info
            snapshot.append({
                "pid":  info["pid"],
                "name": info["name"] or "unknown",
                "cpu":  round(info["cpu_percent"] or 0.0, 2),
                "mem":  round(info["memory_percent"] or 0.0, 2),
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return snapshot


# ── Send Report to Detection Engine ────────────────────────────────────────
def send_report(processes: list) -> list:
    """POST process snapshot; returns list of newly detected alerts."""
    try:
        resp = requests.post(
            f"{DETECTION_ENGINE_URL}/api/agent/report",
            json={"processes": processes},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
        return data.get("new_alerts", [])
    except Exception as exc:
        print(f"[agent] send_report error: {exc}")
        return []


# ── Poll Pending Actions ────────────────────────────────────────────────────
def poll_actions() -> list:
    """Fetch pending terminate commands from Detection Engine."""
    try:
        resp = requests.get(
            f"{DETECTION_ENGINE_URL}/api/agent/actions",
            timeout=5,
        )
        resp.raise_for_status()
        return resp.json().get("actions", [])
    except Exception as exc:
        print(f"[agent] poll_actions error: {exc}")
        return []


# ── Execute Action Locally ──────────────────────────────────────────────────
def execute_action(action: dict) -> None:
    """Terminate a local process as instructed and report the result."""
    pid  = action.get("pid", -1)
    name = action.get("name", "unknown")
    cpu  = action.get("cpu", 0.0)

    success = False
    message = ""

    try:
        proc = psutil.Process(pid)
        proc.terminate()
        success = True
        message = f"Process '{name}' (PID {pid}) terminated."
        print(f"[agent] ✅ {message}")
    except psutil.NoSuchProcess:
        success = True
        message = f"Process '{name}' was already gone."
        print(f"[agent] ✅ {message}")
    except psutil.AccessDenied:
        success = False
        message = f"Access denied – cannot terminate '{name}'."
        print(f"[agent] ⚠️  {message}")
    except Exception as exc:
        success = False
        message = str(exc)
        print(f"[agent] ❌ {message}")

    # Report result back
    try:
        requests.post(
            f"{DETECTION_ENGINE_URL}/api/agent/action-result",
            json={"pid": pid, "name": name, "cpu": cpu, "success": success, "message": message},
            timeout=5,
        )
    except Exception as exc:
        print(f"[agent] action-result report error: {exc}")


# ── Main Loop ───────────────────────────────────────────────────────────────
def run():
    print(f"[agent] Starting. Detection Engine: {DETECTION_ENGINE_URL}")
    print(f"[agent] Dashboard URL:  {DASHBOARD_URL}")
    print(f"[agent] Scan interval:  {SCAN_INTERVAL}s | Action poll: {ACTION_INTERVAL}s")
    print(f"[agent] Toast available: {_NOTIFY_AVAILABLE}")

    last_action_poll = 0.0

    while True:
        now = time.time()

        # ── 1. Collect & report processes ────────────────────────────────
        processes = collect_processes()
        new_alerts = send_report(processes)

        # ── 2. Fire toast notifications for new alerts ───────────────────
        for alert in new_alerts:
            _notify_new_alert(
                alert["pid"], alert["name"], alert["cpu"], alert["mem"]
            )

        # ── 3. Poll for pending actions (throttled separately) ────────────
        if now - last_action_poll >= ACTION_INTERVAL:
            actions = poll_actions()
            for act in actions:
                execute_action(act)
            last_action_poll = now

        time.sleep(SCAN_INTERVAL)


if __name__ == "__main__":
    run()
