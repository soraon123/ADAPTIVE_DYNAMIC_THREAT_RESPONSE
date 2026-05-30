# policy_engine/policy.py
# Runtime rule storage and lookup for the DTRS Policy Engine.
# Stores CPU thresholds, per-process rules, and cooldown settings in JSON.

import json
import os
import threading
from datetime import datetime

DATA_DIR    = os.environ.get("DATA_DIR", ".")
POLICY_FILE = os.path.join(DATA_DIR, "policy.json")

_lock = threading.Lock()

# ── Default Policy ────────────────────────────────────────────────────────────
_DEFAULT_POLICY = {
    "thresholds": {
        "low_max":    40,   # CPU below this → LOW
        "medium_max": 70,   # CPU between low_max and this → MEDIUM; above → HIGH
    },
    "cooldown_hours":          2.0,
    "auto_whitelist_threshold": 5,
    "process_rules": {},    # name (lower) → { action: ignore|alert|terminate, reason }
    "updated_at": None,
}


# ── File I/O ──────────────────────────────────────────────────────────────────
def load_policy() -> dict:
    if not os.path.exists(POLICY_FILE):
        return dict(_DEFAULT_POLICY)
    try:
        with open(POLICY_FILE, "r") as f:
            data = json.load(f)
        # Back-fill any missing top-level keys added in future versions
        merged = dict(_DEFAULT_POLICY)
        merged.update(data)
        # Ensure nested defaults
        merged["thresholds"] = {**_DEFAULT_POLICY["thresholds"], **merged.get("thresholds", {})}
        return merged
    except Exception:
        return dict(_DEFAULT_POLICY)


def _save_policy(policy: dict) -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    policy["updated_at"] = datetime.now().isoformat()
    with _lock:
        with open(POLICY_FILE, "w") as f:
            json.dump(policy, f, indent=2)


# ── Thresholds ────────────────────────────────────────────────────────────────
def get_thresholds() -> dict:
    return load_policy()["thresholds"]


def update_thresholds(low_max: float = None, medium_max: float = None) -> dict:
    policy = load_policy()
    if low_max is not None:
        policy["thresholds"]["low_max"] = float(low_max)
    if medium_max is not None:
        policy["thresholds"]["medium_max"] = float(medium_max)
    if policy["thresholds"]["low_max"] >= policy["thresholds"]["medium_max"]:
        raise ValueError("low_max must be less than medium_max")
    _save_policy(policy)
    return policy["thresholds"]


# ── Global Settings ────────────────────────────────────────────────────────────
def get_settings() -> dict:
    p = load_policy()
    return {
        "cooldown_hours":           p.get("cooldown_hours", 2.0),
        "auto_whitelist_threshold": p.get("auto_whitelist_threshold", 5),
    }


def update_settings(cooldown_hours: float = None, auto_whitelist_threshold: int = None) -> dict:
    policy = load_policy()
    if cooldown_hours is not None:
        policy["cooldown_hours"] = float(cooldown_hours)
    if auto_whitelist_threshold is not None:
        policy["auto_whitelist_threshold"] = int(auto_whitelist_threshold)
    _save_policy(policy)
    return get_settings()


# ── Per-Process Rules ─────────────────────────────────────────────────────────
def list_rules() -> list:
    rules = load_policy().get("process_rules", {})
    return [{"name": k, **v} for k, v in rules.items()]


def get_rule(name: str):
    """Return the rule for a process name, or None."""
    rules = load_policy().get("process_rules", {})
    return rules.get(name.lower().strip())


def upsert_rule(name: str, action: str, reason: str = "") -> dict:
    """
    Create or update a per-process rule.
    action: 'ignore' | 'alert' | 'terminate'
    """
    valid_actions = {"ignore", "alert", "terminate"}
    if action not in valid_actions:
        raise ValueError(f"action must be one of: {valid_actions}")

    policy = load_policy()
    key    = name.lower().strip()
    policy.setdefault("process_rules", {})[key] = {
        "action": action,
        "reason": reason or f"custom-rule:{action}",
        "created_at": policy.get("process_rules", {}).get(key, {}).get("created_at", datetime.now().isoformat()),
        "updated_at": datetime.now().isoformat(),
    }
    _save_policy(policy)
    return {"name": key, **policy["process_rules"][key]}


def delete_rule(name: str) -> bool:
    """Remove a per-process rule. Returns True if it existed."""
    policy = load_policy()
    key    = name.lower().strip()
    rules  = policy.get("process_rules", {})
    if key not in rules:
        return False
    del rules[key]
    policy["process_rules"] = rules
    _save_policy(policy)
    return True


# ── Full Policy Snapshot ───────────────────────────────────────────────────────
def get_full_policy() -> dict:
    """Return the complete policy object (for Detection Engine to fetch on startup)."""
    p = load_policy()
    return {
        "thresholds":              p["thresholds"],
        "cooldown_hours":          p.get("cooldown_hours", 2.0),
        "auto_whitelist_threshold": p.get("auto_whitelist_threshold", 5),
        "process_rules":           p.get("process_rules", {}),
        "updated_at":              p.get("updated_at"),
    }


# ── Classify Risk (mirrors detection engine, using dynamic thresholds) ─────────
def classify_risk(cpu: float) -> str:
    t = get_thresholds()
    if cpu < t["low_max"]:
        return "LOW"
    elif cpu <= t["medium_max"]:
        return "MEDIUM"
    return "HIGH"
