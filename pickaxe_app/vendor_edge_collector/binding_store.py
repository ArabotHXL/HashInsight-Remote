import csv
import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..crypto import load_local_key, encrypt_json, decrypt_json


@dataclass
class BindingRecord:
    asset_id: str
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

    Stores asset_id -> {ip, port, vendor, protocol, credentials(optional)} on the EDGE only.
    Nothing in this store is uploaded to cloud.
    """

    def __init__(self, db_path: str, *, ensure_parent: bool = True):
        self.db_path = Path(db_path)
        if ensure_parent:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        return sqlite3.connect(str(self.db_path))

    def _init_db(self) -> None:
        conn = self._conn()
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS bindings (
                asset_id TEXT PRIMARY KEY,
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
        conn.commit()
        conn.close()

    @staticmethod
    def _norm_row(row: Dict[str, str]) -> Dict[str, str]:
        # tolerate different column names
        def g(*keys, default=""):
            for k in keys:
                if k in row and str(row[k]).strip() != "":
                    return str(row[k]).strip()
            return default

        asset_id = g("asset_id", "miner_id", "id")
        ip = g("ip", "ip_address", "host")
        port_s = g("port", default="4028")
        vendor = g("vendor", "type", default="antminer").lower()
        protocol = g("protocol", default="cgminer").lower()
        zone_id = g("zone_id", "zone")
        site_id = g("site_id", "site")
        username = g("username", "user", "http_user")
        password = g("password", "pass", "http_pass")
        notes = g("notes", "note", default="")
        return {
            "asset_id": asset_id,
            "ip": ip,
            "port": port_s,
            "vendor": vendor,
            "protocol": protocol,
            "zone_id": zone_id,
            "site_id": site_id,
            "username": username,
            "password": password,
            "notes": notes,
        }

    def import_from_csv(
        self,
        csv_path: str,
        *,
        zone_filter: str = "",
        site_filter: str = "",
        encrypt_credentials: bool = True,
        key_env: str = "PICKAXE_LOCAL_KEY",
    ) -> Tuple[int, List[str]]:
        """Import (upsert) bindings from CSV.

        Returns: (imported_count, warnings)
        """
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
                warnings.append(f"Local key not available; credentials will be stored as NULL. ({e})")
                key = None

        with p.open("r", encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        conn = self._conn()
        cur = conn.cursor()
        imported = 0
        for raw in rows:
            row = self._norm_row(raw)
            asset_id = row["asset_id"]
            ip = row["ip"]
            if not asset_id or not ip:
                continue

            zone_id = row["zone_id"]
            site_id = row["site_id"]

            if zone_filter and zone_id and zone_id != zone_filter:
                continue
            if site_filter and site_id and site_id != site_filter:
                continue

            try:
                port = int(row["port"]) if row["port"] else 4028
            except Exception:
                port = 4028

            cred_enc_json = None
            if row["username"] or row["password"]:
                if key:
                    cred_enc_json = json.dumps(encrypt_json({"username": row["username"], "password": row["password"]}, key=key))
                else:
                    cred_enc_json = None  # do not store plaintext by default

            cur.execute(
                """
                INSERT INTO bindings(asset_id, ip, port, vendor, protocol, zone_id, site_id, cred_enc_json, notes, capability_json, last_seen)
                VALUES(?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(asset_id) DO UPDATE SET
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
                (asset_id, ip, port, row["vendor"], row["protocol"], zone_id, site_id, cred_enc_json, row["notes"], None, ""),
            )
            imported += 1

        conn.commit()
        conn.close()
        return imported, warnings

    def list_bindings(self, *, zone_id: str = "", site_id: str = "") -> List[BindingRecord]:
        conn = self._conn()
        cur = conn.cursor()
        q = "SELECT asset_id, ip, port, vendor, protocol, zone_id, site_id, cred_enc_json, notes, capability_json, last_seen FROM bindings"
        args: List[Any] = []
        where = []
        if zone_id:
            where.append("(zone_id = ? OR zone_id IS NULL OR zone_id = '')")
            args.append(zone_id)
        if site_id:
            where.append("(site_id = ? OR site_id IS NULL OR site_id = '')")
            args.append(site_id)
        if where:
            q += " WHERE " + " AND ".join(where)
        q += " ORDER BY asset_id"
        cur.execute(q, args)
        out: List[BindingRecord] = []
        for r in cur.fetchall():
            asset_id, ip, port, vendor, protocol, z, s, cred_enc_json, notes, cap_json, last_seen = r
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
            out.append(BindingRecord(
                asset_id=str(asset_id),
                ip=str(ip),
                port=int(port),
                vendor=str(vendor or "antminer"),
                protocol=str(protocol or "cgminer"),
                zone_id=str(z or ""),
                site_id=str(s or ""),
                cred=cred,
                notes=str(notes or ""),
                capability=cap,
                last_seen=str(last_seen or ""),
            ))
        conn.close()
        return out

    def get_binding(self, asset_id: str) -> Optional[BindingRecord]:
        conn = self._conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT asset_id, ip, port, vendor, protocol, zone_id, site_id, cred_enc_json, notes, capability_json, last_seen FROM bindings WHERE asset_id=?",
            (asset_id,),
        )
        r = cur.fetchone()
        conn.close()
        if not r:
            return None
        asset_id, ip, port, vendor, protocol, z, s, cred_enc_json, notes, cap_json, last_seen = r
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
        return BindingRecord(
            asset_id=str(asset_id),
            ip=str(ip),
            port=int(port),
            vendor=str(vendor or "antminer"),
            protocol=str(protocol or "cgminer"),
            zone_id=str(z or ""),
            site_id=str(s or ""),
            cred=cred,
            notes=str(notes or ""),
            capability=cap,
            last_seen=str(last_seen or ""),
        )

    def set_capability(self, asset_id: str, capability: Dict[str, Any]) -> None:
        conn = self._conn()
        cur = conn.cursor()
        cur.execute(
            "UPDATE bindings SET capability_json=?, updated_at=CURRENT_TIMESTAMP WHERE asset_id=?",
            (json.dumps(capability, ensure_ascii=False), asset_id),
        )
        conn.commit()
        conn.close()

    def set_last_seen(self, asset_id: str, last_seen_iso: str) -> None:
        conn = self._conn()
        cur = conn.cursor()
        cur.execute(
            "UPDATE bindings SET last_seen=?, updated_at=CURRENT_TIMESTAMP WHERE asset_id=?",
            (last_seen_iso, asset_id),
        )
        conn.commit()
        conn.close()
