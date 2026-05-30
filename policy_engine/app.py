# policy_engine/app.py
# Policy Engine Microservice — runtime rule configuration for DTRS.
# Detection Engine fetches policy at startup and periodically to pick up changes
# without requiring a restart.

import os
from flask import Flask, jsonify, request
import policy

app = Flask(__name__)


# ═════════════════════════════════════════════════════════════════════════════
# FULL POLICY SNAPSHOT (Detection Engine primary endpoint)
# ═════════════════════════════════════════════════════════════════════════════

@app.route("/api/policy")
def get_policy():
    """Return the complete policy snapshot — used by Detection Engine."""
    return jsonify(policy.get_full_policy())


# ═════════════════════════════════════════════════════════════════════════════
# THRESHOLDS
# ═════════════════════════════════════════════════════════════════════════════

@app.route("/api/policy/thresholds", methods=["GET"])
def get_thresholds():
    """Return current CPU risk thresholds."""
    return jsonify(thresholds=policy.get_thresholds())


@app.route("/api/policy/thresholds", methods=["POST"])
def update_thresholds():
    """
    Update CPU risk thresholds.
    Body: { low_max: float, medium_max: float }
    low_max < medium_max; anything above medium_max is HIGH.
    """
    data = request.get_json(silent=True) or {}
    low_max    = data.get("low_max")
    medium_max = data.get("medium_max")

    if low_max is None and medium_max is None:
        return jsonify(ok=False, message="Provide at least one of: low_max, medium_max"), 400

    try:
        thresholds = policy.update_thresholds(low_max=low_max, medium_max=medium_max)
        return jsonify(ok=True, thresholds=thresholds)
    except ValueError as e:
        return jsonify(ok=False, message=str(e)), 400


# ═════════════════════════════════════════════════════════════════════════════
# GLOBAL SETTINGS
# ═════════════════════════════════════════════════════════════════════════════

@app.route("/api/policy/settings", methods=["GET"])
def get_settings():
    """Return cooldown and auto-whitelist threshold settings."""
    return jsonify(settings=policy.get_settings())


@app.route("/api/policy/settings", methods=["POST"])
def update_settings():
    """
    Update global detection settings.
    Body: { cooldown_hours: float, auto_whitelist_threshold: int }
    """
    data = request.get_json(silent=True) or {}
    ch  = data.get("cooldown_hours")
    awt = data.get("auto_whitelist_threshold")

    if ch is None and awt is None:
        return jsonify(ok=False, message="Provide at least one of: cooldown_hours, auto_whitelist_threshold"), 400

    try:
        settings = policy.update_settings(cooldown_hours=ch, auto_whitelist_threshold=awt)
        return jsonify(ok=True, settings=settings)
    except Exception as e:
        return jsonify(ok=False, message=str(e)), 400


# ═════════════════════════════════════════════════════════════════════════════
# PER-PROCESS RULES
# ═════════════════════════════════════════════════════════════════════════════

@app.route("/api/policy/rules", methods=["GET"])
def list_rules():
    """List all per-process rules."""
    return jsonify(rules=policy.list_rules())


@app.route("/api/policy/rules", methods=["POST"])
def upsert_rule():
    """
    Create or update a per-process rule.
    Body: { name: str, action: ignore|alert|terminate, reason: str (optional) }
    """
    data   = request.get_json(silent=True) or {}
    name   = (data.get("name") or "").strip()
    action = (data.get("action") or "").strip().lower()
    reason = (data.get("reason") or "").strip()

    if not name:
        return jsonify(ok=False, message="'name' is required."), 400
    if not action:
        return jsonify(ok=False, message="'action' is required (ignore|alert|terminate)."), 400

    try:
        rule = policy.upsert_rule(name, action, reason)
        return jsonify(ok=True, rule=rule), 201
    except ValueError as e:
        return jsonify(ok=False, message=str(e)), 400


@app.route("/api/policy/rules/<path:process_name>", methods=["GET"])
def get_rule(process_name: str):
    """Get the rule for a specific process name."""
    rule = policy.get_rule(process_name)
    if rule is None:
        return jsonify(ok=False, message=f"No rule found for '{process_name}'."), 404
    return jsonify(ok=True, name=process_name.lower(), rule=rule)


@app.route("/api/policy/rules/<path:process_name>", methods=["DELETE"])
def delete_rule(process_name: str):
    """Delete the rule for a specific process name."""
    deleted = policy.delete_rule(process_name)
    if deleted:
        return jsonify(ok=True, message=f"Rule for '{process_name}' deleted.")
    return jsonify(ok=False, message=f"No rule found for '{process_name}'."), 404


# ═════════════════════════════════════════════════════════════════════════════
# HEALTH
# ═════════════════════════════════════════════════════════════════════════════

@app.route("/health")
def health():
    p = policy.get_full_policy()
    return jsonify(
        status="ok",
        service="policy-engine",
        thresholds=p["thresholds"],
        rule_count=len(p.get("process_rules", {})),
        updated_at=p.get("updated_at"),
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5004))
    app.run(debug=False, host="0.0.0.0", port=port)
