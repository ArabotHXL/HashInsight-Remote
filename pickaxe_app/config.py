import json
import os
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Any, Dict, List, Optional

# Non-fatal warnings captured during last load_config()
LAST_WARNINGS: List[str] = []

def get_last_warnings() -> List[str]:
    return list(LAST_WARNINGS)


from .crypto import load_local_key, encrypt_json, decrypt_json, DEFAULT_KEY_ENV

DEFAULT_PORT = 4028
DEFAULT_LOCAL_PORT = 8711  # local UI port

# Two-loop polling: "latest" (fast, lightweight) and "raw" (slower, heavier)
DEFAULT_LATEST_INTERVAL_SEC = 60
DEFAULT_RAW_INTERVAL_SEC = 60

# Backward-compatible single interval
DEFAULT_POLL_INTERVAL_SEC = 60

DEFAULT_TIMEOUT_SEC = 5
DEFAULT_CONNECT_TIMEOUT_SEC = 2
DEFAULT_READ_TIMEOUT_SEC = 30

DEFAULT_MAX_WORKERS = 50

# Command channel (optional)
DEFAULT_ENABLE_COMMANDS = False
DEFAULT_COMMAND_POLL_INTERVAL_SEC = 5

# Sharding (for 5k-10k miners): split miner list across multiple HashInsight Remote instances
DEFAULT_SHARD_TOTAL = 1
DEFAULT_SHARD_INDEX = 0

# Per-miner dynamic timeouts (fast pass vs slow retry)
DEFAULT_MINER_TIMEOUT_FAST_SEC = 1.5
DEFAULT_MINER_TIMEOUT_SLOW_SEC = 5.0

# Offline backoff (avoid hammering dead miners)
DEFAULT_OFFLINE_BACKOFF_BASE_SEC = 30
DEFAULT_OFFLINE_BACKOFF_MAX_SEC = 300

# Minimum intervals to protect networks/CPU in near-real-time modes
MIN_LATEST_INTERVAL_SEC = 5
MIN_RAW_INTERVAL_SEC = 10

@dataclass
class MinerConfig:
    miner_id: str
    ip: str
    port: int = DEFAULT_PORT
    miner_type: str = "antminer"

@dataclass
class AppConfig:
    # Site & cloud
    site_id: str = "site_001"
    site_name: str = ""
    cloud_api_base: str = "https://calc.hashinsight.net"
    collector_token: str = ""

    # Optional: multi-zone / region binding (used by some cloud deployments)
    zone_id: str = ""
    # Optional: override stable edge device id (otherwise generated & persisted locally)
    device_id: str = ""

    # Cloud API modes
    telemetry_api_mode: str = "legacy"  # legacy | v1 | auto
    command_api_mode: str = "auto"      # legacy | v1 | auto
    ack_include_snapshot: bool = True

    # Local API auth secret (protects start/stop/save operations). Stored locally.
    local_api_secret: str = ""
    # Polling
    latest_interval_sec: int = DEFAULT_LATEST_INTERVAL_SEC
    raw_interval_sec: int = DEFAULT_RAW_INTERVAL_SEC
    poll_interval_sec: int = DEFAULT_POLL_INTERVAL_SEC  # legacy alias used by some UIs
    timeout_sec: int = DEFAULT_TIMEOUT_SEC
    max_workers: int = DEFAULT_MAX_WORKERS

    # Upload tuning (edge -> cloud)
    # NOTE: connect_timeout_sec/read_timeout_sec are kept for backward compatibility
    # but the collector uses these upload_* fields.
    upload_connect_timeout_sec: int = DEFAULT_CONNECT_TIMEOUT_SEC
    upload_read_timeout_sec: int = DEFAULT_READ_TIMEOUT_SEC
    upload_workers: int = 4
    batch_size: int = 1000
    max_retries: int = 5
    latest_max_miners: int = 2000

    # Backward-compat aliases (older configs / older code)
    connect_timeout_sec: int = DEFAULT_CONNECT_TIMEOUT_SEC
    read_timeout_sec: int = DEFAULT_READ_TIMEOUT_SEC

    # Sharding
    shard_total: int = DEFAULT_SHARD_TOTAL
    shard_index: int = DEFAULT_SHARD_INDEX

    # Miner probing behavior
    miner_timeout_fast_sec: float = DEFAULT_MINER_TIMEOUT_FAST_SEC
    miner_timeout_slow_sec: float = DEFAULT_MINER_TIMEOUT_SLOW_SEC
    offline_backoff_base_sec: int = DEFAULT_OFFLINE_BACKOFF_BASE_SEC
    offline_backoff_max_sec: int = DEFAULT_OFFLINE_BACKOFF_MAX_SEC

    # Commands
    enable_commands: bool = DEFAULT_ENABLE_COMMANDS
    command_poll_interval_sec: int = DEFAULT_COMMAND_POLL_INTERVAL_SEC

    # Security (local-only IP, optionally encrypted at rest)
    # Default OFF to avoid breaking first-run (user can enable once key is set).
    encrypt_miners_config: bool = False
    # Privacy: whether to include miner IP address in uploads to the cloud
    upload_ip_to_cloud: bool = False
    local_key_env: str = DEFAULT_KEY_ENV

    # ---------------------------
    # Local-only binding store (CSV -> SQLite)
    # ---------------------------
    # If enabled and CSV exists, the collector will import miner bindings into a local
    # SQLite store and use it as the primary inventory (zone/site filtered).
    binding_enable: bool = True
    binding_csv_path: str = "./miners.csv"
    # If empty, defaults to <data_dir>/binding_store.db
    binding_db_path: str = ""
    binding_encrypt_credentials: bool = True

    # ---------------------------
    # Offline spool retention (telemetry + acks)
    # ---------------------------
    offline_spool_max_age_hours: int = 24
    offline_spool_max_total_bytes: int = 10 * 1024 * 1024 * 1024  # 10GB

    # ---------------------------
    # Burst sampling (anomaly-driven near-real-time)
    # ---------------------------
    enable_burst_sampling: bool = False
    burst_interval_sec: int = 10
    burst_duration_sec: int = 300
    burst_hashrate_drop_pct: int = 15
    burst_temp_threshold_c: int = 85

    # ---------------------------
    # Privacy
    # ---------------------------
    mask_ip_in_logs: bool = True
    enable_whatsminer_http: bool = True

    
    # Inventory sources (order matters for merge): miners | binding | ip_ranges
    # If config file omits this field, runtime will default to ["miners","binding","ip_ranges"] for backward compatibility.
    inventory_sources: List[str] = field(default_factory=lambda: ["miners","binding","ip_ranges"])

# Miner sources
    miners: List[MinerConfig] = None  # type: ignore
    ip_ranges: List[Dict[str, Any]] = None  # type: ignore

    def __post_init__(self) -> None:
        if self.miners is None:
            self.miners = []
        if self.ip_ranges is None:
            self.ip_ranges = []

        # Normalize inventory_sources for backward compatibility
        inv = getattr(self, "inventory_sources", None)
        if not isinstance(inv, list) or not inv:
            self.inventory_sources = ["miners", "binding", "ip_ranges"]
        else:
            self.inventory_sources = [str(x).strip().lower() for x in inv if str(x).strip()]
            if not self.inventory_sources:
                self.inventory_sources = ["miners", "binding", "ip_ranges"]

def get_config_path(path: Optional[str] = None) -> Path:
    """Resolve the config file path.

    Priority:
    1) explicit path argument
    2) env var PICKAXE_CONFIG_PATH
    3) ./collector_config.json if it exists (backward compatible)
    4) user home config: ~/.hashinsight/pickaxe/collector_config.json
    """
    if path:
        return Path(path).expanduser().resolve()

    env_path = os.getenv("PICKAXE_CONFIG_PATH", "").strip()
    if env_path:
        return Path(env_path).expanduser().resolve()

    local = Path("./collector_config.json").resolve()
    if local.exists():
        return local

    home_dir = Path.home() / ".hashinsight" / "pickaxe"
    home_dir.mkdir(parents=True, exist_ok=True)
    return (home_dir / "collector_config.json").resolve()

def clamp_intervals(cfg: AppConfig) -> None:
    # clamp to minimums
    cfg.latest_interval_sec = max(int(cfg.latest_interval_sec), MIN_LATEST_INTERVAL_SEC)
    cfg.raw_interval_sec = max(int(cfg.raw_interval_sec), MIN_RAW_INTERVAL_SEC)
    # legacy alias
    cfg.poll_interval_sec = max(int(cfg.poll_interval_sec), MIN_LATEST_INTERVAL_SEC)

def load_config(path: Optional[str] = None) -> AppConfig:
    global LAST_WARNINGS
    warnings: List[str] = []

    p = get_config_path(path)
    if not p.exists():
        LAST_WARNINGS = []
        return AppConfig()

    raw: Dict[str, Any] = json.loads(p.read_text(encoding="utf-8"))

    # Backward compatibility from earlier collector terminology
    # - api_url -> cloud_api_base
    # - api_key -> collector_token
    cloud_api_base = str(raw.get("cloud_api_base") or raw.get("api_url") or raw.get("api_base") or "")
    collector_token = str(raw.get("collector_token") or raw.get("api_key") or raw.get("token") or "")

    # Inventory sources (merge order): miners | binding | ip_ranges
    inv_raw = raw.get("inventory_sources")
    inventory_sources: List[str] = []
    if isinstance(inv_raw, list):
        inventory_sources = [str(x).strip().lower() for x in inv_raw if str(x).strip()]
    elif isinstance(inv_raw, str):
        inventory_sources = [s.strip().lower() for s in inv_raw.split(",") if s.strip()]
    if not inventory_sources:
        inventory_sources = ["miners", "binding", "ip_ranges"]

    cfg = AppConfig(
        site_id=str(raw.get("site_id", "site_001")),
        site_name=str(raw.get("site_name", "")),
        cloud_api_base=cloud_api_base,
        collector_token=collector_token,
        zone_id=str(raw.get('zone_id','')),
        device_id=str(raw.get('device_id','')),
        telemetry_api_mode=str(raw.get('telemetry_api_mode', raw.get('telemetry_mode','legacy'))),
        command_api_mode=str(raw.get('command_api_mode', raw.get('command_mode','auto'))),
        ack_include_snapshot=bool(raw.get('ack_include_snapshot', True)),
        local_api_secret=str(raw.get("local_api_secret", raw.get("local_api_key", ""))),
        latest_interval_sec=int(raw.get("latest_interval_sec", raw.get("poll_interval_sec", DEFAULT_LATEST_INTERVAL_SEC))),
        raw_interval_sec=int(raw.get("raw_interval_sec", raw.get("poll_interval_sec", DEFAULT_RAW_INTERVAL_SEC))),
        poll_interval_sec=int(raw.get("poll_interval_sec", raw.get("latest_interval_sec", DEFAULT_POLL_INTERVAL_SEC))),
        timeout_sec=int(raw.get("timeout_sec", DEFAULT_TIMEOUT_SEC)),
        # Upload tuning (prefer upload_*; fall back to legacy connect/read)
        upload_connect_timeout_sec=int(raw.get("upload_connect_timeout_sec", raw.get("connect_timeout_sec", DEFAULT_CONNECT_TIMEOUT_SEC))),
        upload_read_timeout_sec=int(raw.get("upload_read_timeout_sec", raw.get("read_timeout_sec", DEFAULT_READ_TIMEOUT_SEC))),
        upload_workers=int(raw.get("upload_workers", 4)),
        batch_size=int(raw.get("batch_size", 1000)),
        max_retries=int(raw.get("max_retries", 5)),
        latest_max_miners=int(raw.get("latest_max_miners", 2000)),
        # Legacy aliases (kept so older code/tools reading config keep working)
        connect_timeout_sec=int(raw.get("connect_timeout_sec", DEFAULT_CONNECT_TIMEOUT_SEC)),
        read_timeout_sec=int(raw.get("read_timeout_sec", DEFAULT_READ_TIMEOUT_SEC)),
        max_workers=int(raw.get("max_workers", DEFAULT_MAX_WORKERS)),
        enable_commands=bool(raw.get("enable_commands", DEFAULT_ENABLE_COMMANDS)),
        command_poll_interval_sec=int(raw.get("command_poll_interval_sec", DEFAULT_COMMAND_POLL_INTERVAL_SEC)),
        shard_total=int(raw.get("shard_total", DEFAULT_SHARD_TOTAL)),
        shard_index=int(raw.get("shard_index", DEFAULT_SHARD_INDEX)),
        miner_timeout_fast_sec=float(raw.get("miner_timeout_fast_sec", DEFAULT_MINER_TIMEOUT_FAST_SEC)),
        miner_timeout_slow_sec=float(raw.get("miner_timeout_slow_sec", DEFAULT_MINER_TIMEOUT_SLOW_SEC)),
        offline_backoff_base_sec=int(raw.get("offline_backoff_base_sec", DEFAULT_OFFLINE_BACKOFF_BASE_SEC)),
        offline_backoff_max_sec=int(raw.get("offline_backoff_max_sec", DEFAULT_OFFLINE_BACKOFF_MAX_SEC)),
        encrypt_miners_config=bool(raw.get("encrypt_miners_config", False)),
        upload_ip_to_cloud=bool(raw.get("upload_ip_to_cloud", False)),
        local_key_env=str(raw.get("local_key_env") or DEFAULT_KEY_ENV),
        binding_enable=bool(raw.get("binding_enable", True)),
        binding_csv_path=str(raw.get("binding_csv_path") or "./miners.csv"),
        binding_db_path=str(raw.get("binding_db_path") or ""),
        binding_encrypt_credentials=bool(raw.get("binding_encrypt_credentials", True)),
        offline_spool_max_age_hours=int(raw.get("offline_spool_max_age_hours", 24)),
        offline_spool_max_total_bytes=int(raw.get("offline_spool_max_total_bytes", 10 * 1024 * 1024 * 1024)),
        enable_burst_sampling=bool(raw.get("enable_burst_sampling", False)),
        burst_interval_sec=int(raw.get("burst_interval_sec", 10)),
        burst_duration_sec=int(raw.get("burst_duration_sec", 300)),
        burst_hashrate_drop_pct=int(raw.get("burst_hashrate_drop_pct", 15)),
        burst_temp_threshold_c=int(raw.get("burst_temp_threshold_c", 85)),
        mask_ip_in_logs=bool(raw.get("mask_ip_in_logs", True)),
        enable_whatsminer_http=bool(raw.get("enable_whatsminer_http", True)),
        inventory_sources=inventory_sources,
        ip_ranges=raw.get("ip_ranges") or [],
    )

    # Miner list: plaintext (legacy) or encrypted (recommended)
    src_list = raw.get("miners") or []
    if isinstance(raw.get("miners_encrypted"), dict):
        enc = raw.get("miners_encrypted")
        try:
            key = load_local_key(cfg.local_key_env)
            decrypted = decrypt_json(enc, key=key)
            if isinstance(decrypted, list):
                src_list = decrypted
        except Exception as e:
            # If key is missing/invalid, fall back to plaintext miners (if present)
            # rather than breaking app startup. Record a warning for the UI.
            warnings.append(
                f"miners_encrypted exists but could not be decrypted ({type(e).__name__}). "
                f"Set env var {cfg.local_key_env} (default {DEFAULT_KEY_ENV}) to your 32-byte key."
            )

    miners: List[MinerConfig] = []
    for m in (src_list or []):
        if not isinstance(m, dict):
            continue
        miner_id = str(m.get("miner_id") or m.get("id") or m.get("ip") or "")
        ip = str(m.get("ip") or "")
        if not miner_id or not ip:
            continue
        try:
            miners.append(MinerConfig(
                miner_id=miner_id,
                ip=ip,
                port=int(m.get("port", DEFAULT_PORT)),
                miner_type=str(m.get("miner_type") or m.get("type") or "antminer"),
            ))
        except Exception:
            continue
    cfg.miners = miners

    clamp_intervals(cfg)
    LAST_WARNINGS = warnings
    return cfg

def save_config(cfg: AppConfig, path: Optional[str] = None) -> Path:
    p = get_config_path(path)
    clamp_intervals(cfg)

    payload = asdict(cfg)
    miners_plain = [asdict(m) for m in cfg.miners]

    if cfg.encrypt_miners_config:
        try:
            key = load_local_key(cfg.local_key_env)
            payload.pop("miners", None)
            payload["miners_encrypted"] = encrypt_json(miners_plain, key=key)
        except Exception:
            # Fail open to plaintext to avoid breaking first-run.
            payload["encrypt_miners_config"] = False
            payload["miners"] = miners_plain
            payload.pop("miners_encrypted", None)
    else:
        payload["miners"] = miners_plain
        payload.pop("miners_encrypted", None)

    p.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return p
