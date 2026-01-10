import csv
import json
import sqlite3
import secrets
import base64
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..crypto import load_local_key, encrypt_json, decrypt_json


def _gen_miner_key() -> str:
    """Generate a non-enumerable device token (128-bit), base32 (lowercase, no padding)."""
    raw = secrets.token_bytes(16)  # 128-bit
    s = base64.b32encode(raw).decode("utf-8").rstrip("=").lower()
    return s


@dataclass
class BindingRecord:
    asset_id: str
    miner_key: str
    ip: str
    port: int = 4028
    vendor: str = "antminer"   # antminer|whatsminer|avalon|other
    protocol: str = "cgminer"  # cgminer|http
    zone_id: str = ""
    site_id: str = ""
    cred: Optional[Dict[str, str]] = None  # {"username":..., "password":...}
    notes: str = ""
    capability: Optional[Dict[str, Any]] = None
    last_seen: str = ""


class BindingStore:
    """Local-only asset binding store (CSV -> SQLite).

    Security invariants:
    - Stores ip/port/credentials ONLY on the EDGE device.
    - This store is never uploaded to cloud.
    - Credentials are stored encrypted (AES-GCM via pickaxe_app.crypto) when a local key is available.

    Purpose:
    - Persist miner_key (device token) per miner for stable cloud targeting.
    - Persist local mapping miner_key/asset_id -> ip/port/protocol so commands can be executed without cloud IP.
    """

    def __init__(self, db_path: str, *, ensure_parent: bool = True):
        self.db_path = Path(db_path)
        if ensure_parent:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        return conn

    def _table_columns(self, conn: sqlite3.Connection, table: str) -> List[str]:
        cur = conn.cursor()
        cur.execute(f"PRAGMA table_info({table})")
        return [r[1] for r in cur.fetchall()]  # name

    def _init_db(self) -> None:
        conn = self._conn()
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS bindings (
                asset_id TEXT PRIMARY KEY,
                miner_key TEXT UNIQUE,
                ip TEXT NOT NULL,
                port INTEGER NOT NULL,
                vendor TEXT,
                protocol TEXT,
                zone_id TEXT,
                site_id TEXT,
                cred_enc_json TEXT,
                notes TEXT,
                capability_json TEXT,
                last_seen TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        # Migration / forward-compat: add missing columns if upgrading from older schema.
        cols = set(self._table_columns(conn, "bindings"))
        def _add(coldef: str):
            try:
                cur.execute(f"ALTER TABLE bindings ADD COLUMN {coldef}")
            except Exception:
                pass

        if "miner_key" not in cols:
            _add("miner_key TEXT")
        if "capability_json" not in cols:
            _add("capability_json TEXT")
        if "updated_at" not in cols:
            _add("updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP")

        # Ensure indexes
        try:
            cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_bindings_miner_key ON bindings(miner_key)")
        except Exception:
            pass

        conn.commit()
        conn.close()

    @staticmethod
    def _norm_row(row: Dict[str, str]) -> Dict[str, str]:
        """Normalize CSV row to canonical keys."""
        def g(*keys, default=""):
            for k in keys:
                if k in row and str(row[k]).strip() != "":
                    return str(row[k]).strip()
            return default

        return {
            "asset_id": g("asset_id", "miner_id", "id"),
            "miner_key": g("miner_key", "device_key", "hash", "token"),
            "ip": g("ip", "ip_address", "host"),
            "port": g("port", default="4028"),
            "vendor": g("vendor", "type", default="antminer").lower(),
            "protocol": g("protocol", default="cgminer").lower(),
            "zone_id": g("zone_id", "zone"),
            "site_id": g("site_id", "site"),
            "username": g("username", "user", "login"),
            "password": g("password", "pass"),
            "notes": g("notes", "comment", "label"),
        }

    def ensure_miner_key(self, asset_id: str, *, preferred: str = "") -> str:
        """Return existing miner_key for asset_id, or set/generate one.

        If preferred is provided, it will be used (and stored) when safe to do so.
        """
        asset_id = str(asset_id or "").strip()
        if not asset_id:
            raise ValueError("asset_id required")

        conn = self._conn()
        cur = conn.cursor()
        cur.execute("SELECT miner_key FROM bindings WHERE asset_id=?", (asset_id,))
        row = cur.fetchone()
        existing = (row[0] if row and row[0] else "").strip()

        if existing and not preferred:
            conn.close()
            return existing

        target = (preferred or existing or _gen_miner_key()).strip()
        # Ensure uniqueness (best-effort)
        cur.execute("SELECT asset_id FROM bindings WHERE miner_key=? AND asset_id<>?", (target, asset_id))
        clash = cur.fetchone()
        if clash:
            target = _gen_miner_key()

        # If the row exists, update; otherwise caller should upsert binding with ip/port.
        if row:
            cur.execute("UPDATE bindings SET miner_key=?, updated_at=CURRENT_TIMESTAMP WHERE asset_id=?", (target, asset_id))
            conn.commit()
            conn.close()
            return target

        conn.close()
        return target

    def upsert_binding(
        self,
        *,
        asset_id: str,
        ip: str,
        port: int = 4028,
        vendor: str = "antminer",
        protocol: str = "cgminer",
        zone_id: str = "",
        site_id: str = "",
        miner_key: str = "",
        credentials: Optional[Dict[str, str]] = None,
        notes: str = "",
        capability: Optional[Dict[str, Any]] = None,
        last_seen: str = "",
        encrypt_credentials: bool = True,
        key_env: str = "PICKAXE_LOCAL_KEY",
    ) -> str:
        asset_id = str(asset_id or "").strip()
        ip = str(ip or "").strip()
        if not asset_id or not ip:
            raise ValueError("asset_id and ip are required")
        try:
            port = int(port)
        except Exception:
            port = 4028

        mk = self.ensure_miner_key(asset_id, preferred=miner_key)

        cred_enc_json = None
        if credentials and (credentials.get("username") or credentials.get("password")) and encrypt_credentials:
            try:
                key = load_local_key(key_env)
                cred_enc_json = json.dumps(encrypt_json({
                    "username": str(credentials.get("username") or ""),
                    "password": str(credentials.get("password") or ""),
                }, key=key))
            except Exception:
                cred_enc_json = None

        cap_json = None
        if capability is not None:
            try:
                cap_json = json.dumps(capability)
            except Exception:
                cap_json = None

        conn = self._conn()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO bindings(
                asset_id, miner_key, ip, port, vendor, protocol, zone_id, site_id,
                cred_enc_json, notes, capability_json, last_seen, updated_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP)
            ON CONFLICT(asset_id) DO UPDATE SET
                miner_key=excluded.miner_key,
                ip=excluded.ip,
                port=excluded.port,
                vendor=excluded.vendor,
                protocol=excluded.protocol,
                zone_id=excluded.zone_id,
                site_id=excluded.site_id,
                cred_enc_json=COALESCE(excluded.cred_enc_json, bindings.cred_enc_json),
                notes=excluded.notes,
                capability_json=COALESCE(excluded.capability_json, bindings.capability_json),
                last_seen=COALESCE(excluded.last_seen, bindings.last_seen),
                updated_at=CURRENT_TIMESTAMP
            """,
            (asset_id, mk, ip, port, vendor, protocol, zone_id, site_id, cred_enc_json, notes, cap_json, last_seen or None),
        )
        conn.commit()
        conn.close()
        return mk

    def import_from_csv(
        self,
        csv_path: str,
        *,
        default_site_id: str = "",
        default_zone_id: str = "",
        encrypt_credentials: bool = True,
        key_env: str = "PICKAXE_LOCAL_KEY",
    ) -> Tuple[int, List[str]]:
        """Import (upsert) bindings from CSV. Returns (imported_count, warnings)."""
        p = Path(csv_path)
        warnings: List[str] = []
        if not p.exists():
            warnings.append(f"CSV not found: {csv_path}")
            return 0, warnings

        key: Optional[bytes] = None
        if encrypt_credentials:
            try:
                key = load_local_key(key_env)
            except Exception as e:
                warnings.append(f"Local key not available; credentials will not be stored. ({e})")
                key = None

        with p.open("r", encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        imported = 0
        conn = self._conn()
        cur = conn.cursor()

        for raw in rows:
            row = self._norm_row(raw)
            asset_id = row["asset_id"]
            ip = row["ip"]
            if not asset_id or not ip:
                warnings.append(f"Missing asset_id or ip in row: {raw}")
                continue

            try:
                port = int(row["port"] or "4028")
            except Exception:
                port = 4028

            zone_id = row["zone_id"] or default_zone_id or ""
            site_id = row["site_id"] or default_site_id or ""

            # miner_key: keep existing if CSV omits it
            miner_key = row["miner_key"].strip() if row["miner_key"] else ""
            if not miner_key:
                cur.execute("SELECT miner_key FROM bindings WHERE asset_id=?", (asset_id,))
                r = cur.fetchone()
                miner_key = (r[0] if r and r[0] else "").strip()
            if not miner_key:
                miner_key = _gen_miner_key()

            # Uniqueness guard
            cur.execute("SELECT asset_id FROM bindings WHERE miner_key=? AND asset_id<>?", (miner_key, asset_id))
            if cur.fetchone():
                miner_key = _gen_miner_key()
                warnings.append(f"miner_key clash detected for asset_id={asset_id}; regenerated.")

            cred_enc_json = None
            if key and (row["username"] or row["password"]):
                try:
                    cred_enc_json = json.dumps(encrypt_json({
                        "username": row["username"],
                        "password": row["password"],
                    }, key=key))
                except Exception:
                    cred_enc_json = None

            cur.execute(
                """
                INSERT INTO bindings(
                    asset_id, miner_key, ip, port, vendor, protocol, zone_id, site_id,
                    cred_enc_json, notes, capability_json, last_seen, updated_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,NULL,CURRENT_TIMESTAMP)
                ON CONFLICT(asset_id) DO UPDATE SET
                    miner_key=COALESCE(excluded.miner_key, bindings.miner_key),
                    ip=excluded.ip,
                    port=excluded.port,
                    vendor=excluded.vendor,
                    protocol=excluded.protocol,
                    zone_id=excluded.zone_id,
                    site_id=excluded.site_id,
                    cred_enc_json=COALESCE(excluded.cred_enc_json, bindings.cred_enc_json),
                    notes=excluded.notes,
                    updated_at=CURRENT_TIMESTAMP
                """,
                (asset_id, miner_key, ip, port, row["vendor"], row["protocol"], zone_id, site_id, cred_enc_json, row["notes"], None),
            )
            imported += 1

        conn.commit()
        conn.close()
        return imported, warnings

    def list_bindings(self, *, site_id: str = "", zone_id: str = "") -> List[Dict[str, Any]]:
        """List bindings (optionally filtered by site/zone)."""
        conn = self._conn()
        cur = conn.cursor()

        q = ("SELECT asset_id, miner_key, ip, port, vendor, protocol, zone_id, site_id, "
             "cred_enc_json, notes, capability_json, last_seen FROM bindings")
        args: List[Any] = []
        where: List[str] = []
        if site_id:
            where.append("site_id=?")
            args.append(site_id)
        if zone_id:
            where.append("zone_id=?")
            args.append(zone_id)
        if where:
            q += " WHERE " + " AND ".join(where)
        q += " ORDER BY asset_id"
        cur.execute(q, args)

        out: List[Dict[str, Any]] = []
        for r in cur.fetchall():
            asset_id, miner_key, ip, port, vendor, protocol, z, s, cred_enc_json, notes, cap_json, last_seen = r
            cred = None
            if cred_enc_json:
                try:
                    key = load_local_key()
                    cred = decrypt_json(json.loads(cred_enc_json), key=key)
                except Exception:
                    cred = None
            cap = None
            if cap_json:
                try:
                    cap = json.loads(cap_json)
                except Exception:
                    cap = None
            out.append({
                "asset_id": asset_id,
                "miner_key": miner_key or "",
                "ip": ip,
                "port": int(port) if port is not None else 4028,
                "vendor": vendor or "",
                "protocol": protocol or "",
                "zone_id": z or "",
                "site_id": s or "",
                "credentials": cred or {},
                "notes": notes or "",
                "capability": cap or {},
                "last_seen": last_seen or "",
            })

        conn.close()
        return out

    def touch_last_seen(self, asset_id: str, *, ts: Optional[str] = None) -> None:
        """Update last_seen for asset_id."""
        asset_id = str(asset_id or "").strip()
        if not asset_id:
            return
        conn = self._conn()
        cur = conn.cursor()
        cur.execute(
            "UPDATE bindings SET last_seen=COALESCE(?, last_seen), updated_at=CURRENT_TIMESTAMP WHERE asset_id=?",
            (ts, asset_id),
        )
        conn.commit()
        conn.close()
