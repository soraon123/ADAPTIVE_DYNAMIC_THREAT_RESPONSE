# monitor.py
# Background thread: continuously scans running processes and populates
# an in-memory snapshot that Flask routes can read safely.

import threading
import time
import psutil
from detection import evaluate_process, SYSTEM_CRITICAL

# ── Desktop Notifications (Windows) ──────────────────────────────────────────
try:
    from winotify import Notification, audio
    _NOTIFY_AVAILABLE = True
except ImportError:
    _NOTIFY_AVAILABLE = False

DTRS_PORT = 5000   # must match app.run() port


def _notify_new_alert(pid: int, name: str, cpu: float, mem: float) -> None:
    """Fire a native Windows toast for a new HIGH-risk process."""
    if not _NOTIFY_AVAILABLE:
        return
    try:
        toast = Notification(
            app_id="DTRS – Threat Response",
            title="🚨 HIGH-Risk Process Detected",
            msg=f"{name}  |  PID {pid}  |  CPU {cpu:.1f}%  |  Mem {mem:.1f}%",
            duration="long",            # stays visible longer
            icon="",
        )
        toast.set_audio(audio.Default, loop=False)
        toast.add_actions(
            label="View Alerts",
            launch=f"http://localhost:{DTRS_PORT}/alerts",
        )
        toast.add_actions(
            label="Terminate",
            launch=f"http://localhost:{DTRS_PORT}/quick-action/{pid}/terminate/{name}/{cpu}",
        )
        toast.show()
    except Exception as exc:
        print(f"[monitor] toast error: {exc}")

# ── Shared State ──────────────────────────────────────────────────────────────
_lock      = threading.Lock()
_processes = []   # list of dicts – current process snapshot
_alerts    = []   # list of dicts – HIGH-risk active alerts (not yet acted on)

SCAN_INTERVAL = 3  # seconds between scans


# ── Public Readers ────────────────────────────────────────────────────────────
def get_processes() -> list:
    with _lock:
        return list(_processes)


def get_alerts() -> list:
    with _lock:
        return list(_alerts)


def remove_alert(pid: int) -> None:
    """Remove an alert once the user has acted (terminate or ignore)."""
    with _lock:
        global _alerts
        _alerts = [a for a in _alerts if a["pid"] != pid]


# ── Scanner ───────────────────────────────────────────────────────────────────
def _scan() -> None:
    """Single scan pass over all running processes."""
    snapshot = []
    new_alert_pids = set()

    for proc in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent"]):
        try:
            info = proc.info
            pid  = info["pid"]
            name = info["name"] or "unknown"
            cpu  = info["cpu_percent"] or 0.0
            mem  = info["memory_percent"] or 0.0

            decision = evaluate_process(name, cpu, mem)
            risk      = decision["risk"]
            action    = decision["action"]

            row = {
                "pid":    pid,
                "name":   name,
                "cpu":    round(cpu, 2),
                "mem":    round(mem, 2),
                "risk":   risk,
                "action": action,
                "reason": decision["reason"],
            }
            snapshot.append(row)

            # Accumulate new alerts (HIGH-risk, not ignored)
            if action == "alert":
                new_alert_pids.add(pid)

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            # Process vanished or is inaccessible – skip gracefully
            continue

    with _lock:
        global _processes, _alerts
        _processes = snapshot

        # Keep existing alerts that are still running + add new ones
        existing_pids = {a["pid"] for a in _alerts}
        running_pids  = {p["pid"] for p in snapshot}

        # Drop alerts for dead processes
        _alerts = [a for a in _alerts if a["pid"] in running_pids]

        # Add brand-new HIGH-risk alerts
        newly_added = []
        for row in snapshot:
            if row["pid"] in new_alert_pids and row["pid"] not in existing_pids:
                _alerts.append(row)
                newly_added.append(row)

    # Fire desktop notifications OUTSIDE the lock to avoid holding it during I/O
    for row in newly_added:
        _notify_new_alert(row["pid"], row["name"], row["cpu"], row["mem"])


# ── Background Worker ─────────────────────────────────────────────────────────
def _worker() -> None:
    while True:
        try:
            _scan()
        except Exception as exc:
            # Never crash the monitor thread
            print(f"[monitor] scan error: {exc}")
        time.sleep(SCAN_INTERVAL)


def start_monitor() -> None:
    """Start the background monitoring thread (daemon – exits with main process)."""
    t = threading.Thread(target=_worker, daemon=True, name="ProcessMonitor")
    t.start()
    print("[monitor] background scan thread started.")
