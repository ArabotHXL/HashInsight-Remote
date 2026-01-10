import json
from typing import Any, Dict, Optional, Tuple

import requests

class WhatsminerHTTPClient:
    """Best-effort Whatsminer HTTP adapter.

    Supports reading summary/stats/pools via a set of common endpoints.
    Control is intentionally conservative because Whatsminer firmware differs.
    """

    DEFAULT_ENDPOINTS = [
        "/cgi-bin/summary.cgi",
        "/cgi-bin/stats.cgi",
        "/cgi-bin/pools.cgi",
        "/cgi-bin/get_miner_status.cgi",
        "/cgi-bin/get_system_info.cgi",
        "/cgi-bin/get_status.cgi",
        "/summary",
        "/status",
        "/api/status",
    ]

    def __init__(self, host: str, *, timeout: float = 5.0, username: str = "", password: str = ""):
        self.host = host
        self.timeout = timeout
        self.username = username
        self.password = password
        self.session = requests.Session()

    def _get(self, path: str) -> Optional[Dict[str, Any]]:
        url = f"http://{self.host}{path}"
        auth = (self.username, self.password) if (self.username or self.password) else None
        try:
            resp = self.session.get(url, timeout=self.timeout, auth=auth)
            if resp.status_code != 200:
                return None
            ctype = resp.headers.get("content-type", "")
            txt = resp.text.strip()
            if "application/json" in ctype or (txt.startswith("{") and txt.endswith("}")):
                return resp.json()
            try:
                return json.loads(txt)
            except Exception:
                return None
        except Exception:
            return None

    def probe(self) -> Tuple[bool, str]:
        for ep in self.DEFAULT_ENDPOINTS:
            d = self._get(ep)
            if isinstance(d, dict) and d:
                return True, f"ok:{ep}"
        return False, "unsupported"

    def get_snapshot(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"http": {}}
        for ep in self.DEFAULT_ENDPOINTS:
            d = self._get(ep)
            if isinstance(d, dict) and d:
                out["http"][ep] = d
        return out

    @staticmethod
    def extract_fields(snapshot: Dict[str, Any]) -> Dict[str, Any]:
        """Best-effort extraction into a normalized subset."""
        http = snapshot.get("http") or {}
        hashrate = None
        temp = None
        for _, d in http.items():
            if not isinstance(d, dict):
                continue
            for k, v in d.items():
                lk = str(k).lower()
                if hashrate is None and any(x in lk for x in ["hashrate", "ghs", "ths"]):
                    try:
                        hashrate = float(v)
                    except Exception:
                        pass
                if temp is None and "temp" in lk:
                    try:
                        temp = float(v)
                    except Exception:
                        pass
        out = {}
        if hashrate is not None:
            out["hashrate_reported"] = hashrate
        if temp is not None:
            out["temperature_reported"] = temp
        return out
