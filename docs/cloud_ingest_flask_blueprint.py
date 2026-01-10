"""Minimal Flask ingest endpoint for HashInsight collectors.

Drop this into your cloud Flask app (server-side) to accept uploads from the HashInsight Remote/HashInsight Remote.

Contract:
- POST /api/collector/upload
- Headers:
  - X-Collector-Key: <site token>
  - X-Site-ID: <site id>
  - Content-Encoding: gzip
- Body: gzip(JSON array of miner data dicts)

Return: {"success": true}

Security notes:
- Treat the collector token as a site-scoped secret. Rotate when needed.
- Ensure HTTPS end-to-end.
- Add rate limiting, audit logs, and per-site quota as you scale.
"""

import gzip
import json
from datetime import datetime
from flask import Blueprint, request, jsonify

collector_bp = Blueprint("collector_bp", __name__)


def _validate_collector_token(site_id: str, token: str) -> bool:
    """Replace with your real validation logic.

    Typical patterns:
    - Lookup `site_id` in DB and compare hashed token
    - Or use a JWT signed by your cloud with `site_id` claim
    """
    if not site_id or not token:
        return False

    # TODO: implement DB lookup
    return True


@collector_bp.route("/api/collector/upload", methods=["POST"])
def collector_upload():
    site_id = request.headers.get("X-Site-ID", "").strip()
    token = request.headers.get("X-Collector-Key", "").strip()

    if not _validate_collector_token(site_id, token):
        return jsonify({"success": False, "error": "unauthorized"}), 401

    raw = request.get_data() or b""
    if not raw:
        return jsonify({"success": False, "error": "empty body"}), 400

    # gzip expected
    try:
        if request.headers.get("Content-Encoding", "").lower() == "gzip":
            raw = gzip.decompress(raw)
    except Exception as e:
        return jsonify({"success": False, "error": f"gzip decode failed: {e}"}), 400

    try:
        payload = json.loads(raw.decode("utf-8", errors="ignore"))
        if not isinstance(payload, list):
            return jsonify({"success": False, "error": "payload must be a list"}), 400
    except Exception as e:
        return jsonify({"success": False, "error": f"json decode failed: {e}"}), 400

    # TODO: Persist to DB (recommended) or push to a queue.
    # For MVP: just compute stats.
    online = sum(1 for x in payload if isinstance(x, dict) and x.get("online") is True)

    return jsonify({
        "success": True,
        "received": len(payload),
        "online": online,
        "site_id": site_id,
        "ingested_at": datetime.utcnow().isoformat() + "Z",
    })
