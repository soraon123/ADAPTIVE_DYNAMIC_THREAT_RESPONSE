# notification_service/app.py
# Notification Service Microservice — webhook-based alerting for DTRS.
# Called by the Detection Engine when HIGH-risk alerts are generated.
# Supports Slack, Discord, Microsoft Teams, and generic HTTP webhooks.

import os
import uuid
from flask import Flask, jsonify, request
import notifier

app = Flask(__name__)


# ═════════════════════════════════════════════════════════════════════════════
# ALERT DISPATCH ENDPOINT (called by Detection Engine)
# ═════════════════════════════════════════════════════════════════════════════

@app.route("/api/notify/alert", methods=["POST"])
def notify_alert():
    """
    Detection Engine posts a HIGH-risk alert here.
    We forward it to all configured, enabled webhooks.
    """
    data  = request.get_json(silent=True) or {}
    alert = data.get("alert", data)   # accept both {alert: {...}} and direct alert dicts

    if not alert:
        return jsonify(ok=False, message="No alert data provided."), 400

    results = notifier.send_alert(alert)
    success_count = sum(1 for r in results if r.get("success"))
    skip_count    = sum(1 for r in results if r.get("skipped"))
    fail_count    = len(results) - success_count - skip_count

    return jsonify(
        ok=True,
        dispatched=success_count,
        skipped=skip_count,
        failed=fail_count,
        results=results,
    )


# ═════════════════════════════════════════════════════════════════════════════
# CONFIG ENDPOINTS
# ═════════════════════════════════════════════════════════════════════════════

@app.route("/api/notify/config", methods=["GET"])
def get_config():
    """Return current notification configuration."""
    return jsonify(config=notifier.get_config())


@app.route("/api/notify/config", methods=["POST"])
def update_config():
    """
    Update top-level notification settings.
    Body: { enabled, min_risk, cooldown_seconds }
    """
    data = request.get_json(silent=True) or {}
    allowed_keys = {"enabled", "min_risk", "cooldown_seconds"}
    updates = {k: v for k, v in data.items() if k in allowed_keys}

    if not updates:
        return jsonify(ok=False, message="No valid fields to update."), 400

    config = notifier.update_config(updates)
    return jsonify(ok=True, config=config)


# ─────────────────────────────────────────────────────────────────────────────
# WEBHOOK MANAGEMENT
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/notify/webhooks", methods=["GET"])
def list_webhooks():
    """List all configured webhooks."""
    config   = notifier.get_config()
    webhooks = config.get("webhooks", [])
    return jsonify(webhooks=webhooks)


@app.route("/api/notify/webhooks", methods=["POST"])
def add_webhook():
    """
    Add a new webhook.
    Body: { name, url, type (slack|discord|teams|generic), enabled }
    """
    data = request.get_json(silent=True) or {}
    url  = (data.get("url") or "").strip()
    name = (data.get("name") or "").strip()

    if not url:
        return jsonify(ok=False, message="'url' is required."), 400
    if not url.startswith("http"):
        return jsonify(ok=False, message="URL must start with http/https."), 400

    config   = notifier.get_config()
    webhooks = config.get("webhooks", [])

    new_wh = {
        "id":      str(uuid.uuid4())[:8],
        "name":    name or url,
        "url":     url,
        "type":    data.get("type", "generic").lower(),
        "enabled": bool(data.get("enabled", True)),
    }
    webhooks.append(new_wh)
    config["webhooks"] = webhooks
    notifier.save_config(config)

    return jsonify(ok=True, webhook=new_wh), 201


@app.route("/api/notify/webhooks/<webhook_id>", methods=["PATCH"])
def update_webhook(webhook_id: str):
    """
    Update an existing webhook's fields.
    Body: any subset of { name, url, type, enabled }
    """
    data     = request.get_json(silent=True) or {}
    config   = notifier.get_config()
    webhooks = config.get("webhooks", [])

    for wh in webhooks:
        if wh.get("id") == webhook_id:
            for field in ("name", "url", "type", "enabled"):
                if field in data:
                    wh[field] = data[field]
            config["webhooks"] = webhooks
            notifier.save_config(config)
            return jsonify(ok=True, webhook=wh)

    return jsonify(ok=False, message=f"Webhook '{webhook_id}' not found."), 404


@app.route("/api/notify/webhooks/<webhook_id>", methods=["DELETE"])
def delete_webhook(webhook_id: str):
    """Delete a webhook by ID."""
    config   = notifier.get_config()
    webhooks = config.get("webhooks", [])
    original_len = len(webhooks)
    config["webhooks"] = [w for w in webhooks if w.get("id") != webhook_id]

    if len(config["webhooks"]) == original_len:
        return jsonify(ok=False, message=f"Webhook '{webhook_id}' not found."), 404

    notifier.save_config(config)
    return jsonify(ok=True, message=f"Webhook '{webhook_id}' deleted.")


@app.route("/api/notify/webhooks/<webhook_id>/test", methods=["POST"])
def test_webhook(webhook_id: str):
    """
    Send a test notification to a specific webhook to verify connectivity.
    """
    config   = notifier.get_config()
    webhooks = config.get("webhooks", [])
    wh = next((w for w in webhooks if w.get("id") == webhook_id), None)

    if not wh:
        return jsonify(ok=False, message=f"Webhook '{webhook_id}' not found."), 404

    result = notifier.test_webhook(wh)
    return jsonify(ok=result.get("success", False), result=result)


# ─────────────────────────────────────────────────────────────────────────────
# HEALTH
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/health")
def health():
    config = notifier.get_config()
    return jsonify(
        status="ok",
        service="notification-service",
        webhooks_configured=len(config.get("webhooks", [])),
        notifications_enabled=config.get("enabled", True),
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5002))
    app.run(debug=False, host="0.0.0.0", port=port)
