# notification_service/notifier.py
# Webhook dispatch logic for DTRS Notification Service.
# Supports: Slack, Discord, Microsoft Teams, and generic HTTP webhooks.

import json
import os
import threading
import time
import requests
from datetime import datetime

# ── Config Storage ─────────────────────────────────────────────────────────────
DATA_DIR   = os.environ.get("DATA_DIR", ".")
CONFIG_FILE = os.path.join(DATA_DIR, "notif_config.json")

_config_lock = threading.Lock()

_DEFAULT_CONFIG = {
    "enabled": True,
    "webhooks": [],        # list of webhook objects: {url, type, name, enabled}
    "min_risk": "HIGH",    # minimum risk level to notify: HIGH | MEDIUM
    "cooldown_seconds": 60,  # per-process notification cooldown
}

# ── In-memory cooldown tracker ─────────────────────────────────────────────────
_notif_cooldowns: dict = {}
_cooldown_lock = threading.Lock()


# ── Config Helpers ─────────────────────────────────────────────────────────────
def load_config() -> dict:
    """Load notification config from disk, merging defaults for missing keys."""
    if not os.path.exists(CONFIG_FILE):
        return dict(_DEFAULT_CONFIG)
    try:
        with open(CONFIG_FILE, "r") as f:
            data = json.load(f)
        # Merge defaults for any keys added in future versions
        merged = dict(_DEFAULT_CONFIG)
        merged.update(data)
        return merged
    except Exception:
        return dict(_DEFAULT_CONFIG)


def save_config(config: dict) -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    with _config_lock:
        with open(CONFIG_FILE, "w") as f:
            json.dump(config, f, indent=2)


def get_config() -> dict:
    return load_config()


def update_config(updates: dict) -> dict:
    config = load_config()
    config.update(updates)
    save_config(config)
    return config


# ── Cooldown Check ─────────────────────────────────────────────────────────────
def _is_on_cooldown(process_name: str, cooldown_seconds: int) -> bool:
    key = process_name.lower().strip()
    now = time.time()
    with _cooldown_lock:
        last = _notif_cooldowns.get(key, 0)
        if now - last < cooldown_seconds:
            return True
        _notif_cooldowns[key] = now
        return False


# ── Webhook Formatters ─────────────────────────────────────────────────────────
def _risk_emoji(risk: str) -> str:
    return {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}.get(risk, "⚪")


def _build_slack_payload(alert: dict) -> dict:
    """Slack Block Kit message."""
    name = alert.get("name", "unknown")
    pid  = alert.get("pid", -1)
    cpu  = alert.get("cpu", 0.0)
    mem  = alert.get("mem", 0.0)
    risk = alert.get("risk", "HIGH")
    ts   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    color = {"HIGH": "#FF4444", "MEDIUM": "#FFA500", "LOW": "#00CC44"}.get(risk, "#888888")

    return {
        "attachments": [{
            "color": color,
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": f"{_risk_emoji(risk)} DTRS Alert – {risk} Risk Process"}
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Process:*\n`{name}`"},
                        {"type": "mrkdwn", "text": f"*PID:*\n`{pid}`"},
                        {"type": "mrkdwn", "text": f"*CPU:*\n`{cpu:.1f}%`"},
                        {"type": "mrkdwn", "text": f"*Memory:*\n`{mem:.1f}%`"},
                    ]
                },
                {
                    "type": "context",
                    "elements": [{"type": "mrkdwn", "text": f"🕐 {ts} · Adaptive Dynamic Threat Response System"}]
                }
            ]
        }]
    }


def _build_discord_payload(alert: dict) -> dict:
    """Discord Embed message."""
    name = alert.get("name", "unknown")
    pid  = alert.get("pid", -1)
    cpu  = alert.get("cpu", 0.0)
    mem  = alert.get("mem", 0.0)
    risk = alert.get("risk", "HIGH")
    ts   = datetime.utcnow().isoformat() + "Z"

    color_int = {"HIGH": 0xFF4444, "MEDIUM": 0xFFA500, "LOW": 0x00CC44}.get(risk, 0x888888)

    return {
        "username": "DTRS Alert Bot",
        "embeds": [{
            "title": f"{_risk_emoji(risk)} {risk} Risk Process Detected",
            "color": color_int,
            "fields": [
                {"name": "Process", "value": f"`{name}`", "inline": True},
                {"name": "PID",     "value": f"`{pid}`",  "inline": True},
                {"name": "CPU",     "value": f"`{cpu:.1f}%`", "inline": True},
                {"name": "Memory",  "value": f"`{mem:.1f}%`", "inline": True},
            ],
            "footer": {"text": "Adaptive Dynamic Threat Response System"},
            "timestamp": ts,
        }]
    }


def _build_teams_payload(alert: dict) -> dict:
    """Microsoft Teams Adaptive Card (Incoming Webhook format)."""
    name = alert.get("name", "unknown")
    pid  = alert.get("pid", -1)
    cpu  = alert.get("cpu", 0.0)
    mem  = alert.get("mem", 0.0)
    risk = alert.get("risk", "HIGH")
    ts   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    theme = {"HIGH": "attention", "MEDIUM": "warning", "LOW": "good"}.get(risk, "default")

    return {
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.4",
                "body": [
                    {
                        "type": "TextBlock",
                        "text": f"{_risk_emoji(risk)} DTRS Alert – {risk} Risk",
                        "weight": "Bolder",
                        "size": "Large",
                        "color": theme,
                    },
                    {
                        "type": "FactSet",
                        "facts": [
                            {"title": "Process", "value": name},
                            {"title": "PID",     "value": str(pid)},
                            {"title": "CPU",     "value": f"{cpu:.1f}%"},
                            {"title": "Memory",  "value": f"{mem:.1f}%"},
                            {"title": "Time",    "value": ts},
                        ]
                    }
                ]
            }
        }]
    }


def _build_generic_payload(alert: dict) -> dict:
    """Plain JSON payload for generic webhooks."""
    return {
        "source": "DTRS",
        "event":  "threat_alert",
        "alert":  alert,
        "timestamp": datetime.now().isoformat(),
    }


# ── Dispatch to a Single Webhook ───────────────────────────────────────────────
def _dispatch_webhook(webhook: dict, alert: dict) -> dict:
    """Send alert to one webhook. Returns result dict."""
    url      = webhook.get("url", "")
    wtype    = webhook.get("type", "generic").lower()
    wname    = webhook.get("name", url)

    if not url:
        return {"webhook": wname, "success": False, "error": "No URL configured"}

    payload_fn = {
        "slack":   _build_slack_payload,
        "discord": _build_discord_payload,
        "teams":   _build_teams_payload,
    }.get(wtype, _build_generic_payload)

    payload = payload_fn(alert)

    try:
        resp = requests.post(url, json=payload, timeout=8)
        resp.raise_for_status()
        return {"webhook": wname, "type": wtype, "success": True, "status_code": resp.status_code}
    except requests.exceptions.HTTPError as e:
        return {"webhook": wname, "type": wtype, "success": False, "error": f"HTTP {e.response.status_code}: {e.response.text[:200]}"}
    except Exception as e:
        return {"webhook": wname, "type": wtype, "success": False, "error": str(e)}


# ── Public: Send Alert to All Configured Webhooks ─────────────────────────────
def send_alert(alert: dict) -> list:
    """
    Dispatch a threat alert to all enabled webhooks.
    Respects min_risk filter and per-process cooldowns.
    Returns list of result dicts (one per webhook attempted).
    """
    config   = load_config()
    webhooks = config.get("webhooks", [])
    min_risk = config.get("min_risk", "HIGH")
    cooldown = int(config.get("cooldown_seconds", 60))

    if not config.get("enabled", True):
        return [{"skipped": True, "reason": "notifications disabled"}]

    # Risk level filter
    risk_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
    alert_risk = alert.get("risk", "HIGH")
    if risk_order.get(alert_risk, 0) < risk_order.get(min_risk, 2):
        return [{"skipped": True, "reason": f"alert risk {alert_risk} below threshold {min_risk}"}]

    # Cooldown check
    if _is_on_cooldown(alert.get("name", ""), cooldown):
        return [{"skipped": True, "reason": "process on notification cooldown"}]

    enabled_webhooks = [w for w in webhooks if w.get("enabled", True)]
    if not enabled_webhooks:
        return [{"skipped": True, "reason": "no enabled webhooks configured"}]

    results = []
    for wh in enabled_webhooks:
        result = _dispatch_webhook(wh, alert)
        results.append(result)
        print(f"[notifier] {wh.get('name', wh.get('url'))}: {'✅' if result.get('success') else '❌'} {result.get('error', '')}")

    return results


# ── Test Webhook ───────────────────────────────────────────────────────────────
def test_webhook(webhook: dict) -> dict:
    """Send a test payload to a single webhook to verify connectivity."""
    test_alert = {
        "name": "test_process.exe",
        "pid":  9999,
        "cpu":  95.0,
        "mem":  12.5,
        "risk": "HIGH",
        "reason": "test-notification",
    }
    return _dispatch_webhook(webhook, test_alert)
