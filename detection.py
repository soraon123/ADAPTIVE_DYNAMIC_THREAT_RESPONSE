# detection.py
# Handles risk classification and whitelist/auto-whitelist logic

import json
import os
import threading
from datetime import datetime

# ── Constants ────────────────────────────────────────────────────────────────
SYSTEM_CRITICAL = {
    "svchost.exe", "csrss.exe", "wininit.exe",
    "services.exe", "explorer.exe"
}

WHITELIST_FILE    = "whitelist.txt"
AUTO_WHITELIST_FILE = "auto_whitelist.json"
LOGS_FILE         = "logs.json"
COOLDOWN_FILE     = "cooldowns.json"

# Auto-whitelist threshold: safe runs before a process is trusted
AUTO_WHITELIST_THRESHOLD = 5

# Cooldown period (in hours) after user takes action before showing alert again
ALERT_COOLDOWN_HOURS = 2.0

# ── In-Memory Cache for Cooldowns ───────────────────────────────────────────
_cooldown_cache = None
_cooldown_lock = threading.Lock()


# ── Risk Classifier ──────────────────────────────────────────────────────────
def classify_risk(cpu: float) -> str:
    """Return LOW / MEDIUM / HIGH based on CPU usage."""
    if cpu < 40:
        return "LOW"
    elif cpu <= 70:
        return "MEDIUM"
    return "HIGH"


# ── Whitelist Helpers ─────────────────────────────────────────────────────────
def load_whitelist() -> set:
    """Load user-managed whitelist from whitelist.txt."""
    if not os.path.exists(WHITELIST_FILE):
        return set()
    with open(WHITELIST_FILE, "r") as f:
        return {line.strip().lower() for line in f if line.strip()}


def save_whitelist(processes: set) -> None:
    """Persist the updated whitelist."""
    with open(WHITELIST_FILE, "w") as f:
        f.write("\n".join(sorted(processes)) + "\n")


def add_to_whitelist(name: str) -> None:
    wl = load_whitelist()
    wl.add(name.lower().strip())
    save_whitelist(wl)


def remove_from_whitelist(name: str) -> None:
    wl = load_whitelist()
    wl.discard(name.lower().strip())
    save_whitelist(wl)


# ── Auto-Whitelist Helpers ────────────────────────────────────────────────────
def load_auto_whitelist() -> dict:
    """Load auto-whitelist run counts from JSON."""
    if not os.path.exists(AUTO_WHITELIST_FILE):
        return {}
    try:
        with open(AUTO_WHITELIST_FILE, "r") as f:
            return json.load(f)
    except json.JSONDecodeError:
        return {}


def save_auto_whitelist(data: dict) -> None:
    with open(AUTO_WHITELIST_FILE, "w") as f:
        json.dump(data, f, indent=2)


def increment_safe_run(name: str) -> None:
    """Increment safe-run counter; promote to auto-whitelist when threshold met."""
    data = load_auto_whitelist()
    key  = name.lower().strip()
    data[key] = data.get(key, 0) + 1
    save_auto_whitelist(data)


def is_auto_whitelisted(name: str) -> bool:
    data  = load_auto_whitelist()
    count = data.get(name.lower().strip(), 0)
    return count >= AUTO_WHITELIST_THRESHOLD


# ── Cooldown Helpers ──────────────────────────────────────────────────────────
def load_cooldowns() -> dict:
    """Load cooldowns from JSON file."""
    if not os.path.exists(COOLDOWN_FILE):
        return {}
    try:
        with open(COOLDOWN_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def save_cooldowns(data: dict) -> None:
    """Save cooldowns to JSON file."""
    try:
        with open(COOLDOWN_FILE, "w") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print(f"[detection] error saving cooldowns: {e}")


def get_cooldowns_dict() -> dict:
    """Thread-safe lazy initialization and retrieval of the cooldowns cache."""
    global _cooldown_cache
    with _cooldown_lock:
        if _cooldown_cache is None:
            _cooldown_cache = load_cooldowns()
        return _cooldown_cache


def record_action_cooldown(name: str) -> None:
    """Record that the user took action on a process name to suppress alerts."""
    key = name.lower().strip()
    now_str = datetime.now().isoformat()
    
    cooldowns = get_cooldowns_dict()
    with _cooldown_lock:
        cooldowns[key] = now_str
        
    save_cooldowns(cooldowns)


def is_in_cooldown(name: str) -> bool:
    """Check if process alert is in cooldown, purging it if expired."""
    cooldowns = get_cooldowns_dict()
    key = name.lower().strip()
    
    with _cooldown_lock:
        if key not in cooldowns:
            return False
        
        try:
            last_action_time = datetime.fromisoformat(cooldowns[key])
            elapsed = datetime.now() - last_action_time
            if elapsed.total_seconds() < ALERT_COOLDOWN_HOURS * 3600:
                return True
            else:
                # Expired cooldown - remove it
                del cooldowns[key]
                save_cooldowns(cooldowns)
                return False
        except Exception:
            return False


# ── Log Helper ────────────────────────────────────────────────────────────────
def load_logs() -> list:
    if not os.path.exists(LOGS_FILE):
        return []
    try:
        with open(LOGS_FILE, "r") as f:
            return json.load(f)
    except json.JSONDecodeError:
        return []


def append_log(entry: dict) -> None:
    """Append a single log entry (keeps last 500 entries)."""
    logs = load_logs()
    logs.append(entry)
    logs = logs[-500:]          # cap to avoid unbounded growth
    with open(LOGS_FILE, "w") as f:
        json.dump(logs, f, indent=2)


def log_event(name: str, cpu: float, risk: str, action: str) -> None:
    append_log({
        "process":   name,
        "cpu":       round(cpu, 2),
        "risk":      risk,
        "action":    action,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    })


# ── Decision Engine ───────────────────────────────────────────────────────────
def evaluate_process(name: str, cpu: float, mem: float) -> dict:
    """
    Returns a dict describing what action (if any) should be taken.
    The system NEVER terminates automatically – it only generates alerts.
    """
    lname = name.lower().strip()
    risk  = classify_risk(cpu)

    # Priority order: system-critical → whitelist → auto-whitelist → LOW → MEDIUM → HIGH
    if lname in {s.lower() for s in SYSTEM_CRITICAL}:
        return {"action": "ignore", "reason": "system-critical", "risk": risk}

    if lname in load_whitelist():
        increment_safe_run(lname)
        return {"action": "ignore", "reason": "whitelisted", "risk": risk}

    if is_auto_whitelisted(lname):
        increment_safe_run(lname)
        return {"action": "ignore", "reason": "auto-whitelisted", "risk": risk}

    if risk == "LOW":
        increment_safe_run(lname)
        return {"action": "ignore", "reason": "low-risk", "risk": risk}

    if risk == "MEDIUM":
        log_event(name, cpu, risk, "logged")
        return {"action": "log", "reason": "medium-risk", "risk": risk}

    # HIGH risk → generate alert (no auto-termination)
    if is_in_cooldown(lname):
        return {"action": "ignore", "reason": "action-cooldown", "risk": risk}

    log_event(name, cpu, risk, "alert")
    return {"action": "alert", "reason": "high-risk", "risk": risk}
