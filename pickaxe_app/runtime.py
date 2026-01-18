import threading
import time
import logging
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, Optional

from .config import AppConfig
from .vendor_edge_collector.cgminer_collector import EdgeCollector

logger = logging.getLogger("HashInsightRemoteRunner")


def build_edge_config(cfg: AppConfig, data_dir: Path) -> Dict[str, Any]:
    """Map AppConfig -> EdgeCollector config dict."""
    miners = []
    for m in cfg.miners:
        miners.append({
            "id": m.miner_id,
            "ip": m.ip,
            "port": m.port,
            "type": m.miner_type,
        })

    # Also allow "ip_ranges" passthrough (used by some deployments)
    return {
        "api_url": cfg.cloud_api_base,
        "api_key": cfg.collector_token,
        "site_id": cfg.site_id,
        "zone_id": str(getattr(cfg, "zone_id", "") or ""),
        "device_id": str(getattr(cfg, "device_id", "") or ""),
        "telemetry_api_mode": str(getattr(cfg, "telemetry_api_mode", "legacy") or "legacy"),
        "command_api_mode": str(getattr(cfg, "command_api_mode", "auto") or "auto"),
        "ack_include_snapshot": bool(getattr(cfg, "ack_include_snapshot", True)),
        "upload_include_ip": bool(getattr(cfg, "upload_ip_to_cloud", False)),
        # Backward compatibility: EdgeCollector historically used collection_interval.
        # In v0.2+ we run two loops (latest/raw) and keep collection_interval mapped to latest.
        "collection_interval": int(cfg.latest_interval_sec),
        "latest_interval": int(cfg.latest_interval_sec),
        "raw_interval": int(cfg.raw_interval_sec),
        "max_workers": int(cfg.max_workers),
        "batch_size": int(cfg.batch_size),
        "latest_max_miners": int(cfg.latest_max_miners),
        "shard_total": int(cfg.shard_total),
        "shard_index": int(cfg.shard_index),
        # Miner connection behavior
        "miner_timeout": float(cfg.timeout_sec),
        "miner_timeout_fast": float(cfg.miner_timeout_fast_sec),
        "miner_timeout_slow": float(cfg.miner_timeout_slow_sec),
        "miner_max_retries": 1,
        "max_retries": int(cfg.max_retries),
        "offline_backoff_base": float(cfg.offline_backoff_base_sec),
        "offline_backoff_max": float(cfg.offline_backoff_max_sec),
        # Upload behavior
        "upload_connect_timeout": float(cfg.upload_connect_timeout_sec),
        "upload_read_timeout": float(cfg.upload_read_timeout_sec),
        "upload_workers": int(cfg.upload_workers),
        "cache_dir": str(data_dir / "cache"),
        # Local-only Binding Store (CSV -> SQLite)
        "binding_enable": bool(getattr(cfg, "binding_enable", True)),
        "binding_csv_path": str(getattr(cfg, "binding_csv_path", "./miners.csv") or "./miners.csv"),
        "binding_db_path": str(getattr(cfg, "binding_db_path", "") or (data_dir / "data" / "binding_store.db")),
        "binding_encrypt_credentials": bool(getattr(cfg, "binding_encrypt_credentials", True)),
        # Offline spool retention (telemetry + acks)
        "offline_spool_max_age_hours": int(getattr(cfg, "offline_spool_max_age_hours", 24)),
        "offline_spool_max_total_bytes": int(getattr(cfg, "offline_spool_max_total_bytes", 10 * 1024 * 1024 * 1024)),
        # Burst sampling
        "enable_burst_sampling": bool(getattr(cfg, "enable_burst_sampling", False)),
        "burst_interval_sec": int(getattr(cfg, "burst_interval_sec", 10)),
        "burst_duration_sec": int(getattr(cfg, "burst_duration_sec", 300)),
        "burst_hashrate_drop_pct": int(getattr(cfg, "burst_hashrate_drop_pct", 15)),
        "burst_temp_threshold_c": int(getattr(cfg, "burst_temp_threshold_c", 85)),
        # Privacy toggles
        "mask_ip_in_logs": bool(getattr(cfg, "mask_ip_in_logs", True)),
        "enable_whatsminer_http": bool(getattr(cfg, "enable_whatsminer_http", True)),
        "inventory_sources": list(getattr(cfg, "inventory_sources", ["miners","binding","ip_ranges"])),
        "miners": miners,
        "ip_ranges": cfg.ip_ranges,
        "enable_commands": bool(cfg.enable_commands),
        "command_poll_interval": int(cfg.command_poll_interval_sec),
        "command_max_workers": int(getattr(cfg, "command_max_workers", 16)),
        # Safety override (local protection)
        "enable_safety_override": bool(getattr(cfg, "enable_safety_override", False)),
        "safety_interval_sec": int(getattr(cfg, "safety_interval_sec", 10)),
        "safety_max_staleness_sec": int(getattr(cfg, "safety_max_staleness_sec", 30)),
        "safety_temp_high_c": float(getattr(cfg, "safety_temp_high_c", 85)),
        "safety_temp_emergency_c": float(getattr(cfg, "safety_temp_emergency_c", 95)),
        "safety_temp_recover_c": float(getattr(cfg, "safety_temp_recover_c", 70)),
        "safety_high_action": str(getattr(cfg, "safety_high_action", "disable")),
        "safety_emergency_action": str(getattr(cfg, "safety_emergency_action", "reboot")),
        "safety_recover_action": str(getattr(cfg, "safety_recover_action", "enable")),
        "safety_high_cooldown_sec": int(getattr(cfg, "safety_high_cooldown_sec", 1800)),
        "safety_emergency_cooldown_sec": int(getattr(cfg, "safety_emergency_cooldown_sec", 3600)),
        "safety_recover_cooldown_sec": int(getattr(cfg, "safety_recover_cooldown_sec", 900)),
        "safety_max_actions_per_tick": int(getattr(cfg, "safety_max_actions_per_tick", 50)),
        "safety_workers": int(getattr(cfg, "safety_workers", 16)),
    }


class CollectorRunner:
    """Owns a background collection loop and exposes lightweight status."""

    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._lock = threading.Lock()

        self._edge: Optional[EdgeCollector] = None
        self._running = False
        self._last_cycle: Optional[Dict[str, Any]] = None
        self._last_error: Optional[str] = None

    def start(self, cfg: AppConfig) -> Dict[str, Any]:
        with self._lock:
            if self._running:
                return {"running": True, "message": "Collector already running"}

            edge_cfg = build_edge_config(cfg, self.data_dir)
            self._edge = EdgeCollector(edge_cfg)
            self._stop.clear()
            self._last_error = None

            self._thread = threading.Thread(target=self._loop, name="collector", daemon=True)
            self._running = True
            self._thread.start()
            logger.info("Collector started (site_id=%s, miners=%s)", cfg.site_id, len(cfg.miners))

            return {"running": True, "message": "Collector started"}

    def stop(self) -> Dict[str, Any]:
        with self._lock:
            if not self._running:
                return {"running": False, "message": "Collector not running"}

            # Signal the runner loop
            self._stop.set()

            # Signal the edge collector to stop ASAP (do not wait for long cycles)
            try:
                if self._edge:
                    try:
                        if hasattr(self._edge, "request_stop"):
                            self._edge.request_stop()
                    except Exception:
                        pass
                    # Backward compatible flag checked by command polling
                    try:
                        self._edge.running = False
                    except Exception:
                        pass
            except Exception:
                pass

        # Give the loop a moment to exit (best-effort)
        if self._thread:
            self._thread.join(timeout=2.5)

        with self._lock:
            self._running = False
            try:
                if self._edge:
                    self._edge.stop()
            except Exception:
                pass
            self._edge = None

        logger.info("Collector stopped")
        return {"running": False, "message": "Collector stopped"}

    def _loop(self) -> None:
        assert self._edge is not None

        # Mark as running for the command polling loop (which checks self.running)
        try:
            self._edge.running = True
        except Exception:
            pass

        # Optional: command polling is handled inside EdgeCollector.run().
        # In this runner we implement our own loop via run_once() so we also spin the
        # command poll loop only if enabled.
        # Start background workers once (command polling + safety override)
        try:
            if hasattr(self._edge, "start_background_workers"):
                self._edge.start_background_workers()
            else:
                # Backward compatibility
                if getattr(self._edge, "enable_commands", False):
                    cmd_thread = threading.Thread(target=self._edge._command_poll_loop, daemon=True)
                    cmd_thread.start()
        except Exception:
            logger.exception("Failed to start background workers")

        # Two-loop scheduler


        # NOTE: schedule next runs based on *completion time* so we never "catch up"


        # immediately when a cycle takes longer than the configured interval.


        next_latest = time.time()


        next_raw = time.time()



        while not self._stop.is_set():


            try:


                now = time.time()


                due = min(next_raw, next_latest)


                if now < due:


                    time.sleep(min(0.25, max(0.0, due - now)))


                    continue



                if self._stop.is_set():


                    break



                if now >= next_raw:


                    result = self._edge.run_once(mode="raw")


                    result["mode"] = "raw"


                    finished = time.time()


                    raw_interval = max(1, int(getattr(self._edge, "raw_interval", 60)))


                    latest_interval = max(1, int(getattr(self._edge, "latest_interval", 60)))


                    next_raw = finished + raw_interval


                    # A raw cycle also refreshes "latest"; push latest forward from completion time.


                    next_latest = max(next_latest, finished + latest_interval)


                else:


                    result = self._edge.run_once(mode="latest")


                    result["mode"] = "latest"


                    finished = time.time()


                    latest_interval = max(1, int(getattr(self._edge, "latest_interval", 60)))


                    next_latest = finished + latest_interval



                with self._lock:


                    self._last_cycle = result


                    self._last_error = None


                    # Useful for UI


                    self._last_cycle["next_latest_at"] = next_latest


                    self._last_cycle["next_raw_at"] = next_raw



                logger.info("Cycle complete: %s", result)

            except Exception as e:
                err = f"{type(e).__name__}: {e}"
                with self._lock:
                    self._last_error = err
                logger.exception("Cycle failed: %s", err)
                time.sleep(2)

        # Ensure command polling thread exits
        try:
            if self._edge:
                try:
                    # signal the edge collector to stop ASAP (interrupt long cycles)
                    if hasattr(self._edge, 'request_stop'):
                        self._edge.request_stop()
                except Exception:
                    pass
                self._edge.running = False
        except Exception:
            pass

        with self._lock:
            self._running = False

    def status(self) -> Dict[str, Any]:
        with self._lock:
            stats = None
            command_stats = None
            if self._edge:
                try:
                    stats = dict(self._edge.stats)
                except Exception:
                    stats = None
                try:
                    command_stats = self._edge.get_command_stats() if getattr(self._edge, "enable_commands", False) else None
                except Exception:
                    command_stats = None

            return {
                "running": self._running,
                "last_cycle": self._last_cycle,
                "last_error": self._last_error,
                "edge_stats": stats,
                "command_stats": command_stats,
            }
