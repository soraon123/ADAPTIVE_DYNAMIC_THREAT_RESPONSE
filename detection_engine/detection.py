# detection_engine/detection.py
# Core risk classification, whitelist management, logging, and cooldown logic.
# Now fetches thresholds and per-process rules from the Policy Engine service.

import json
import os
import threading
import time
import requests
from datetime import datetime

# ── Service URLs ──────────────────────────────────────────────────────────────
POLICY_ENGINE_URL = os.environ.get("POLICY_ENGINE_URL", "http://localhost:5004").rstrip("/")

# ── Constants ─────────────────────────────────────────────────────────────────
SYSTEM_CRITICAL = {
    "svchost.exe", "csrss.exe", "wininit.exe",
    "services.exe", "explorer.exe"
}

DATA_DIR            = os.environ.get("DATA_DIR", ".")
WHITELIST_FILE      = os.path.join(DATA_DIR, "whitelist.txt")
AUTO_WHITELIST_FILE = os.path.join(DATA_DIR, "auto_whitelist.json")
LOGS_FILE           = os.path.join(DATA_DIR, "logs.json")
COOLDOWN_FILE       = os.path.join(DATA_DIR, "cooldowns.json")

# ── Policy Cache ──────────────────────────────────────────────────────────────
# Refreshed every POLICY_REFRESH_INTERVAL seconds from the Policy Engine.
POLICY_REFRESH_INTERVAL = 30  # seconds

_policy_lock       = threading.Lock()
_policy_cache      = None        # full policy dict
_policy_fetched_at = 0.0         # epoch time of last successful fetch

# Fallback defaults (used when Policy Engine is unreachable)
_FALLBACK_THRESHOLDS           = {"low_max": 40, "medium_max": 70}
AUTO_WHITELIST_THRESHOLD       = 5     # updated from policy
ALERT_COOLDOWN_HOURS           = 2.0   # updated from policy


def _fetch_policy() -> dict | None:
    """Fetch full policy from Policy Engine. Returns None on failure."""
    try:
        resp = requests.get(f"{POLICY_ENGINE_URL}/api/policy", timeout=3)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        print(f"[detection] policy fetch failed: {e}")
        return None


def _get_policy() -> dict:
    """Return cached policy, refreshing if stale or missing."""
    global _policy_cache, _policy_fetched_at, AUTO_WHITELIST_THRESHOLD, ALERT_COOLDOWN_HOURS

    now = time.time()
    with _policy_lock:
        if _policy_cache is None or (now - _policy_fetched_at) > POLICY_REFRESH_INTERVAL:
            fetched = _fetch_policy()
            if fetched:
                _policy_cache      = fetched
                _policy_fetched_at = now
                # Sync module-level constants for external callers
                AUTO_WHITELIST_THRESHOLD = int(fetched.get("auto_whitelist_threshold", 5))
                ALERT_COOLDOWN_HOURS     = float(fetched.get("cooldown_hours", 2.0))
            elif _policy_cache is None:
                # First call, Policy Engine unreachable — use defaults
                _policy_cache = {
                    "thresholds": _FALLBACK_THRESHOLDS,
                    "cooldown_hours": 2.0,
                    "auto_whitelist_threshold": 5,
                    "process_rules": {},
                }
        return _policy_cache


# ── Risk Classifier (uses dynamic thresholds from Policy Engine) ──────────────
def classify_risk(cpu: float) -> str:
    thresholds = _get_policy().get("thresholds", _FALLBACK_THRESHOLDS)
    low_max    = thresholds.get("low_max", 40)
    medium_max = thresholds.get("medium_max", 70)
    if cpu < low_max:
        return "LOW"
    elif cpu <= medium_max:
        return "MEDIUM"
    return "HIGH"


# ── Per-Process Rule Lookup ────────────────────────────────────────────────────
def get_process_rule(name: str) -> dict | None:
    """Return a custom process rule from the Policy Engine, or None."""
    rules = _get_policy().get("process_rules", {})
    return rules.get(name.lower().strip())


# ── Whitelist Helpers ─────────────────────────────────────────────────────────
def load_whitelist() -> set:
    if not os.path.exists(WHITELIST_FILE):
        return set()
    with open(WHITELIST_FILE, "r") as f:
        return {line.strip().lower() for line in f if line.strip()}


def save_whitelist(processes: set) -> None:
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
    data = load_auto_whitelist()
    key  = name.lower().strip()
    data[key] = data.get(key, 0) + 1
    save_auto_whitelist(data)


def is_auto_whitelisted(name: str) -> bool:
    policy    = _get_policy()
    threshold = int(policy.get("auto_whitelist_threshold", AUTO_WHITELIST_THRESHOLD))
    data      = load_auto_whitelist()
    count     = data.get(name.lower().strip(), 0)
    return count >= threshold


# ── Cooldown Helpers ──────────────────────────────────────────────────────────
_cooldown_cache = None
_cooldown_lock  = threading.Lock()


def load_cooldowns() -> dict:
    if not os.path.exists(COOLDOWN_FILE):
        return {}
    try:
        with open(COOLDOWN_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def save_cooldowns(data: dict) -> None:
    try:
        with open(COOLDOWN_FILE, "w") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print(f"[detection] error saving cooldowns: {e}")


def get_cooldowns_dict() -> dict:
    global _cooldown_cache
    with _cooldown_lock:
        if _cooldown_cache is None:
            _cooldown_cache = load_cooldowns()
        return _cooldown_cache


def record_action_cooldown(name: str) -> None:
    key     = name.lower().strip()
    now_str = datetime.now().isoformat()
    cooldowns = get_cooldowns_dict()
    with _cooldown_lock:
        cooldowns[key] = now_str
    save_cooldowns(cooldowns)


def is_in_cooldown(name: str) -> bool:
    policy       = _get_policy()
    cooldown_hrs = float(policy.get("cooldown_hours", ALERT_COOLDOWN_HOURS))
    cooldowns    = get_cooldowns_dict()
    key          = name.lower().strip()
    with _cooldown_lock:
        if key not in cooldowns:
            return False
        try:
            last_action_time = datetime.fromisoformat(cooldowns[key])
            elapsed = datetime.now() - last_action_time
            if elapsed.total_seconds() < cooldown_hrs * 3600:
                return True
            else:
                del cooldowns[key]
                save_cooldowns(cooldowns)
                return False
        except Exception:
            return False


# ── Log Helpers ───────────────────────────────────────────────────────────────
def load_logs() -> list:
    if not os.path.exists(LOGS_FILE):
        return []
    try:
        with open(LOGS_FILE, "r") as f:
            return json.load(f)
    except json.JSONDecodeError:
        return []


def append_log(entry: dict) -> None:
    logs = load_logs()
    logs.append(entry)
    logs = logs[-500:]
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
    Priority order:
      1. System-critical → always ignore
      2. Per-process policy rule (from Policy Engine)
      3. Manual whitelist
      4. Auto-whitelist
      5. Low-risk → ignore
      6. Medium-risk → log
      7. High-risk + cooldown check → alert
    """
    lname = name.lower().strip()
    risk  = classify_risk(cpu)

    # 1. System-critical
    if lname in {s.lower() for s in SYSTEM_CRITICAL}:
        return {"action": "ignore", "reason": "system-critical", "risk": risk}

    # 2. Per-process policy rule
    rule = get_process_rule(lname)
    if rule:
        rule_action = rule.get("action", "ignore")
        rule_reason = rule.get("reason", "policy-rule")
        if rule_action == "ignore":
            return {"action": "ignore", "reason": rule_reason, "risk": risk}
        elif rule_action == "alert":
            log_event(name, cpu, risk, "alert")
            record_action_cooldown(name)   # suppress repeat for cooldown_hours
            return {"action": "alert", "reason": rule_reason, "risk": risk}
        elif rule_action == "terminate":
            log_event(name, cpu, risk, "alert")
            record_action_cooldown(name)   # suppress repeat for cooldown_hours
            return {"action": "alert", "reason": rule_reason, "risk": risk}

    # 3. Manual whitelist
    if lname in load_whitelist():
        increment_safe_run(lname)
        return {"action": "ignore", "reason": "whitelisted", "risk": risk}

    # 4. Auto-whitelist
    if is_auto_whitelisted(lname):
        increment_safe_run(lname)
        return {"action": "ignore", "reason": "auto-whitelisted", "risk": risk}

    # 5. Low risk
    if risk == "LOW":
        increment_safe_run(lname)
        return {"action": "ignore", "reason": "low-risk", "risk": risk}

    # 6. Medium risk
    if risk == "MEDIUM":
        log_event(name, cpu, risk, "logged")
        return {"action": "log", "reason": "medium-risk", "risk": risk}

    # 7. HIGH risk — check cooldown
    if is_in_cooldown(lname):
        return {"action": "ignore", "reason": "action-cooldown", "risk": risk}

    # Alert fires — immediately set cooldown so same process won't alert again
    # for the configured period (default 2h), even without explicit user action.
    log_event(name, cpu, risk, "alert")
    record_action_cooldown(name)
    return {"action": "alert", "reason": "high-risk", "risk": risk}
