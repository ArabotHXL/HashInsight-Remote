#!/usr/bin/env python3
"""
HashInsight HashInsight Remote - 矿场边缘数据采集器
Mining Farm Edge Data Collector

功能:
- 通过CGMiner API (端口4028) 采集矿机实时数据
- 支持批量采集6000+矿机
- 数据压缩后上传到云端
- 断网时本地缓存，恢复后自动重传
- 支持Antminer S19/S21, Whatsminer M30/M50, Avalon等主流矿机

部署: 在矿场本地服务器运行此脚本
"""

import socket
import json
import gzip
import time
import logging
import threading
import queue
import os
import sqlite3
import hashlib
import requests
import uuid
from .ip_scanner import IPRangeParser, IPRangeError
from .binding_store import BindingStore
from .capability_probe import CapabilityProbe
from .whatsminer_http import WhatsminerHTTPClient
from .utils import mask_ip, redact_ips
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('EdgeCollector')


def _join_url(base: str, path: str) -> str:
    """Join base URL and path without dropping an existing base path prefix.

    We deliberately do not use urllib.parse.urljoin with absolute paths because urljoin
    would discard an existing base path (e.g., https://host/prefix + /api/...).
    """
    base = (base or "").rstrip("/") + "/"
    path = (path or "").lstrip("/")
    return base + path


def _iso_utc_now() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


@dataclass
class MinerData:
    """矿机数据结构"""
    miner_id: str
    miner_key: str = ""
    ip_address: str
    timestamp: str
    online: bool
    hashrate_ghs: float = 0.0
    hashrate_5s_ghs: float = 0.0
    temperature_avg: float = 0.0
    temperature_max: float = 0.0
    temperature_chips: List[float] = None
    fan_speeds: List[int] = None
    frequency_avg: float = 0.0
    accepted_shares: int = 0
    rejected_shares: int = 0
    hardware_errors: int = 0
    uptime_seconds: int = 0
    power_consumption: float = 0.0
    efficiency: float = 0.0
    pool_url: str = ""
    worker_name: str = ""
    firmware_version: str = ""
    error_type: str = ""
    error_message: str = ""
    
    def __post_init__(self):
        if self.temperature_chips is None:
            self.temperature_chips = []
        if self.fan_speeds is None:
            self.fan_speeds = []


class CGMinerAPI:
    """CGMiner API客户端"""
    
    def __init__(self, host: str, port: int = 4028, timeout: float = 5.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.last_error_type: Optional[str] = None
        self.last_error_message: str = ""
    
    def send_command(self, command: str, parameter: str = "") -> Optional[Dict]:
        """发送API命令并返回JSON响应"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.host, self.port))
            
            request = json.dumps({"command": command, "parameter": parameter})
            sock.sendall(request.encode('utf-8'))
            
            response = b''
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                if b'\x00' in chunk:
                    break
            
            sock.close()
            
            data = response.rstrip(b'\x00').decode('utf-8', errors='ignore')
            # Reset last error on successful round-trip
            self.last_error_type = None
            self.last_error_message = ""
            return json.loads(data) if data else None
            
        except socket.timeout as e:
            self.last_error_type = 'timeout'
            self.last_error_message = str(e)
            logger.debug(f"Timeout connecting to {self.host}:{self.port}")
            return None
        except ConnectionRefusedError as e:
            self.last_error_type = 'refused'
            self.last_error_message = str(e)
            logger.debug(f"Connection refused: {self.host}:{self.port}")
            return None
        except Exception as e:
            self.last_error_type = 'error'
            self.last_error_message = str(e)
            logger.debug(f"Error querying {self.host}: {e}")
            return None
    
    def get_summary(self) -> Optional[Dict]:
        """获取矿机摘要信息"""
        return self.send_command("summary")
    
    def get_stats(self) -> Optional[Dict]:
        """获取详细统计信息(温度、频率等)"""
        return self.send_command("stats")
    
    def get_pools(self) -> Optional[Dict]:
        """获取矿池信息"""
        return self.send_command("pools")
    
    def get_devs(self) -> Optional[Dict]:
        """获取设备信息"""
        return self.send_command("devs")
    
    def get_version(self) -> Optional[Dict]:
        """获取版本信息"""
        return self.send_command("version")
    
    def enable_mining(self) -> Tuple[bool, str]:
        """启用挖矿 - 恢复ASIC芯片运行"""
        result = self.send_command("ascunlock")
        if result is None:
            result = self.send_command("gpuenable", "0")
        if result is None:
            result = self.send_command("enablepool", "0")
        
        if result and result.get('STATUS', [{}])[0].get('STATUS') in ['S', 'I']:
            return True, "Mining enabled successfully"
        return False, f"Enable failed: {result}"
    
    def disable_mining(self) -> Tuple[bool, str]:
        """禁用挖矿 - 停止ASIC芯片"""
        result = self.send_command("asclock")
        if result is None:
            result = self.send_command("gpudisable", "0")
        if result is None:
            result = self.send_command("disablepool", "0")
        
        if result and result.get('STATUS', [{}])[0].get('STATUS') in ['S', 'I']:
            return True, "Mining disabled successfully"
        return False, f"Disable failed: {result}"
    
    def restart_miner(self) -> Tuple[bool, str]:
        """重启CGMiner进程"""
        result = self.send_command("restart")
        if result and result.get('STATUS', [{}])[0].get('STATUS') in ['S', 'I']:
            return True, "CGMiner restarted successfully"
        return False, f"Restart failed: {result}"
    
    def switch_pool(self, pool_id: int = 0) -> Tuple[bool, str]:
        """切换到指定矿池"""
        result = self.send_command("switchpool", str(pool_id))
        if result and result.get('STATUS', [{}])[0].get('STATUS') in ['S', 'I']:
            return True, f"Switched to pool {pool_id}"
        return False, f"Switch pool failed: {result}"
    
    def add_pool(self, url: str, user: str, password: str = "x") -> Tuple[bool, str]:
        """添加新矿池"""
        param = f"{url},{user},{password}"
        result = self.send_command("addpool", param)
        if result and result.get('STATUS', [{}])[0].get('STATUS') in ['S', 'I']:
            return True, f"Pool added: {url}"
        return False, f"Add pool failed: {result}"
    
    def set_fan_speed(self, speed: int) -> Tuple[bool, str]:
        """设置风扇转速 (需要固件支持)"""
        result = self.send_command("fanctrl", str(speed))
        if result is None:
            return False, "Fan control not supported by this firmware"
        if result.get('STATUS', [{}])[0].get('STATUS') in ['S', 'I']:
            return True, f"Fan speed set to {speed}"
        return False, f"Set fan failed: {result}"
    
    def set_frequency(self, freq: int) -> Tuple[bool, str]:
        """设置频率 (需要固件支持)"""
        result = self.send_command("setconfig", f"freq={freq}")
        if result is None:
            return False, "Frequency control not supported"
        if result.get('STATUS', [{}])[0].get('STATUS') in ['S', 'I']:
            return True, f"Frequency set to {freq}"
        return False, f"Set frequency failed: {result}"
    
    def execute_control_command(self, command: str, params: Dict = None) -> Tuple[bool, str]:
        """执行控制命令
        
        Args:
            command: 命令类型 (enable/disable/restart/reboot/set_pool/set_fan/set_frequency)
            params: 命令参数
        
        Returns:
            (success, message)
        """
        params = params or {}
        
        try:
            if command == 'enable':
                return self.enable_mining()
            elif command == 'disable':
                return self.disable_mining()
            elif command == 'restart':
                return self.restart_miner()
            elif command == 'reboot':
                return self.restart_miner()
            elif command == 'set_pool':
                pool_url = params.get('pool_url')
                pool_user = params.get('pool_user')
                if pool_url and pool_user:
                    return self.add_pool(pool_url, pool_user, params.get('pool_password', 'x'))
                pool_id = params.get('pool_id', 0)
                return self.switch_pool(pool_id)
            elif command == 'set_fan':
                speed = params.get('speed', 100)
                return self.set_fan_speed(speed)
            elif command == 'set_frequency':
                freq = params.get('frequency', 0)
                return self.set_frequency(freq)
            else:
                return False, f"Unknown command: {command}"
        except Exception as e:
            return False, f"Command execution error: {str(e)}"


class MinerDataParser:
    """矿机数据解析器 - 支持多种矿机固件"""
    
    @staticmethod
    def parse_antminer(summary: Dict, stats: Dict, pools: Any, ip: str, miner_id: str, miner_key: str = "") -> MinerData:
        """解析Antminer数据 (S19/S21/T19等)"""
        data = MinerData(
            miner_id=miner_id,
            miner_key=miner_key,
            ip_address=ip,
            timestamp=datetime.utcnow().isoformat(),
            online=True
        )
        
        try:
            if summary and 'SUMMARY' in summary and summary['SUMMARY']:
                s = summary['SUMMARY'][0]
                data.hashrate_ghs = s.get('GHS av', s.get('MHS av', 0) / 1000)
                data.hashrate_5s_ghs = s.get('GHS 5s', s.get('MHS 5s', 0) / 1000)
                data.accepted_shares = s.get('Accepted', 0)
                data.rejected_shares = s.get('Rejected', 0)
                data.hardware_errors = s.get('Hardware Errors', 0)
                data.uptime_seconds = s.get('Elapsed', 0)
            
            if stats and 'STATS' in stats:
                temps = []
                fans = []
                freqs = []
                
                for stat in stats['STATS']:
                    for key, value in stat.items():
                        if isinstance(value, (int, float)):
                            key_lower = key.lower()
                            if 'temp' in key_lower and value > 0 and value < 150:
                                temps.append(value)
                            elif 'fan' in key_lower and value > 0:
                                fans.append(int(value))
                            elif 'freq' in key_lower and value > 0:
                                freqs.append(value)
                
                if temps:
                    data.temperature_chips = temps
                    data.temperature_avg = sum(temps) / len(temps)
                    data.temperature_max = max(temps)
                if fans:
                    data.fan_speeds = fans
                if freqs:
                    data.frequency_avg = sum(freqs) / len(freqs)
            
            if pools and 'POOLS' in pools and pools['POOLS']:
                pool = pools['POOLS'][0]
                data.pool_url = pool.get('URL', '')
                data.worker_name = pool.get('User', '')
        
        except Exception as e:
            logger.error(f"Error parsing Antminer data for {mask_ip(ip)}: {e}")
            data.error_message = str(e)
        
        return data
    
    @staticmethod
    def parse_whatsminer(summary: Dict, stats: Dict, pools: Any, ip: str, miner_id: str, miner_key: str = "") -> MinerData:
        """解析Whatsminer数据 (M30/M50等)"""
        return MinerDataParser.parse_antminer(summary, stats, pools, ip, miner_id, miner_key)

    @staticmethod
    def parse_whatsminer_http(payload: Dict, ip: str, miner_id: str, miner_key: str = "") -> MinerData:
        """Best-effort parse of Whatsminer HTTP JSON payload.

        Notes:
        - Whatsminer web endpoints vary by firmware.
        - We treat this parser as *best-effort telemetry only* and keep control actions on 4028/cgminer.
        """
        def _find_number(obj, keys):
            if not isinstance(obj, (dict, list)):
                return None
            # dict scan
            if isinstance(obj, dict):
                for k in keys:
                    if k in obj:
                        try:
                            v = obj.get(k)
                            if v is None:
                                continue
                            if isinstance(v, (int, float)):
                                return float(v)
                            # strings like "1234.5" or "1234 GH/s"
                            s = str(v)
                            num = "".join(ch for ch in s if (ch.isdigit() or ch in ".-"))
                            return float(num) if num else None
                        except Exception:
                            pass
                for v in obj.values():
                    n = _find_number(v, keys)
                    if n is not None:
                        return n
            else:
                for v in obj:
                    n = _find_number(v, keys)
                    if n is not None:
                        return n
            return None

        def _find_list_numbers(obj, key_substrings):
            out = []
            if isinstance(obj, dict):
                for k, v in obj.items():
                    lk = str(k).lower()
                    if any(s in lk for s in key_substrings):
                        if isinstance(v, list):
                            for it in v:
                                try:
                                    out.append(float(it))
                                except Exception:
                                    pass
                        else:
                            try:
                                out.append(float(v))
                            except Exception:
                                pass
                    else:
                        out.extend(_find_list_numbers(v, key_substrings))
            elif isinstance(obj, list):
                for v in obj:
                    out.extend(_find_list_numbers(v, key_substrings))
            return out

        now = datetime.utcnow().isoformat()
        md = MinerData(miner_id=miner_id, ip_address=ip, timestamp=now, online=True)

        # Hashrate - prefer TH/s or GH/s values if present
        hr = _find_number(payload, ["hashrate", "rt_hashrate", "rate", "ghs_5s", "ghs_ave", "mhs_av"])
        # Some firmwares report TH/s
        hr_ths = _find_number(payload, ["ths", "hashrate_ths", "rt_ths"])
        if hr_ths is not None and hr_ths > 0:
            md.hashrate_ghs = float(hr_ths) * 1000.0
        elif hr is not None:
            # assume it's GH/s unless it's clearly TH/s sized
            md.hashrate_ghs = float(hr) if hr < 1e6 else float(hr) / 1000.0

        hr5 = _find_number(payload, ["ghs_5s", "hashrate_5s", "rt_rate"])
        if hr5 is not None:
            md.hashrate_5s_ghs = float(hr5) if hr5 < 1e6 else float(hr5) / 1000.0

        # Temperatures
        temps = _find_list_numbers(payload, ["temp", "temperature"])
        temps = [t for t in temps if -20.0 < t < 140.0]
        if temps:
            md.temperature_chips = temps
            md.temperature_avg = sum(temps) / len(temps)
            md.temperature_max = max(temps)

        # Fans
        fans = _find_list_numbers(payload, ["fan", "fanspeed", "rpm"])
        fans = [int(f) for f in fans if 0 <= f <= 30000]
        if fans:
            md.fan_speeds = fans

        # Power
        pwr = _find_number(payload, ["power", "power_w", "watt", "input_power"])
        if pwr is not None:
            md.power_consumption = float(pwr)

        # Uptime
        up = _find_number(payload, ["uptime", "elapsed", "running_time"])
        if up is not None:
            md.uptime_seconds = int(up)

        # Pools (best effort)
        try:
            if isinstance(payload, dict):
                pools = payload.get("pools") or payload.get("pool")
                if isinstance(pools, list) and pools:
                    p0 = pools[0] if isinstance(pools[0], dict) else {}
                    md.pool_url = str(p0.get("url") or p0.get("pool") or "")
                    md.worker_name = str(p0.get("user") or p0.get("worker") or "")
        except Exception:
            pass

        # Firmware
        fw = None
        try:
            fw = payload.get("firmware") if isinstance(payload, dict) else None
        except Exception:
            fw = None
        if fw:
            md.firmware_version = str(fw)

        return md
    
    @staticmethod
    def parse_avalon(summary: Dict, stats: Dict, pools: Any, ip: str, miner_id: str, miner_key: str = "") -> MinerData:
        """解析Avalon数据"""
        return MinerDataParser.parse_antminer(summary, stats, pools, ip, miner_id, miner_key)


class OfflineCache:
    """离线缓存管理器 - 使用SQLite存储"""
    
    def __init__(
        self,
        cache_dir: str = "./cache",
        *,
        max_age_hours: int = 24,
        max_total_bytes: int = 10 * 1024 * 1024 * 1024,
    ):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.cache_dir / "offline_cache.db"
        self.max_age_hours = int(max_age_hours)
        self.max_total_bytes = int(max_total_bytes)
        self._init_db()
    
    def _init_db(self):
        """初始化SQLite数据库"""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS pending_uploads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                batch_id TEXT UNIQUE,
                data BLOB,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                retry_count INTEGER DEFAULT 0
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS executed_commands (
                command_id TEXT PRIMARY KEY,
                site_id TEXT,
                miner_id TEXT,
                command TEXT,
                status TEXT,
                result_code INTEGER,
                message TEXT,
                executed_at TEXT
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS pending_acks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ack_id TEXT UNIQUE,
                protocol TEXT,
                endpoint TEXT,
                payload_json TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                retry_count INTEGER DEFAULT 0,
                last_error TEXT DEFAULT ''
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS gap_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                kind TEXT,
                start_ts TEXT,
                end_ts TEXT,
                meta_json TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                sent_at TEXT DEFAULT ''
            )
        ''')

        conn.commit()
        conn.close()

    def cleanup(self, *, max_age_hours: Optional[int] = None, max_total_bytes: Optional[int] = None) -> None:
        """Apply retention to offline spool tables.

        - Age limit: deletes telemetry/ack items older than max_age_hours.
        - Size limit: deletes oldest items until total bytes <= max_total_bytes.

        This is best-effort; failures never block collection.
        """
        age_h = int(max_age_hours if max_age_hours is not None else self.max_age_hours)
        size_b = int(max_total_bytes if max_total_bytes is not None else self.max_total_bytes)

        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            # Age-based retention
            try:
                cursor.execute("DELETE FROM pending_uploads WHERE created_at < datetime('now', ?)", (f"-{age_h} hours",))
                cursor.execute("DELETE FROM pending_acks WHERE created_at < datetime('now', ?)", (f"-{age_h} hours",))
            except Exception:
                pass

            # Size-based retention (approx bytes of BLOB/TEXT columns)
            total = 0
            items: List[Tuple[str, int, int]] = []  # (table, id, bytes)
            cursor.execute("SELECT id, COALESCE(length(data),0) FROM pending_uploads ORDER BY created_at")
            for rid, blen in cursor.fetchall() or []:
                b = int(blen or 0)
                total += b
                items.append(("pending_uploads", int(rid), b))

            cursor.execute("SELECT id, COALESCE(length(payload_json),0) FROM pending_acks ORDER BY created_at")
            for rid, tlen in cursor.fetchall() or []:
                b = int(tlen or 0)
                total += b
                items.append(("pending_acks", int(rid), b))

            if size_b > 0 and total > size_b and items:
                # Delete oldest first until under the limit
                items_sorted = items  # already in chronological order by each table, but interleaving isn't guaranteed
                # To avoid expensive cross-table ordering, we just delete in table order; still works as a cap.
                for table, rid, b in items_sorted:
                    if total <= size_b:
                        break
                    try:
                        if table == "pending_uploads":
                            cursor.execute("DELETE FROM pending_uploads WHERE id=?", (rid,))
                        else:
                            cursor.execute("DELETE FROM pending_acks WHERE id=?", (rid,))
                        total -= b
                    except Exception:
                        continue

            conn.commit()
            conn.close()
        except Exception:
            return

    def record_gap_event(self, kind: str, start_ts: str, end_ts: str, meta: Dict[str, Any]) -> None:
        """Persist a gap/delay interval for later reporting.

        kind: 'telemetry_upload' | 'command_ack' | ...
        """
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO gap_events (kind, start_ts, end_ts, meta_json) VALUES (?,?,?,?)",
                (str(kind), str(start_ts), str(end_ts), json.dumps(meta or {}, ensure_ascii=False)),
            )
            conn.commit()
            conn.close()
        except Exception:
            return

    def list_unsent_gap_events(self, limit: int = 200) -> List[Dict[str, Any]]:
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, kind, start_ts, end_ts, meta_json, created_at FROM gap_events WHERE (sent_at IS NULL OR sent_at='') ORDER BY created_at LIMIT ?",
                (int(limit),),
            )
            rows = cursor.fetchall() or []
            conn.close()
            out = []
            for rid, kind, s, e, mj, created_at in rows:
                try:
                    out.append({
                        "id": int(rid),
                        "kind": kind,
                        "start_ts": s,
                        "end_ts": e,
                        "meta": json.loads(mj or "{}"),
                        "created_at": created_at,
                    })
                except Exception:
                    continue
            return out
        except Exception:
            return []

    def mark_gap_events_sent(self, ids: List[int]) -> None:
        if not ids:
            return
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            now = datetime.utcnow().isoformat()
            for rid in ids:
                try:
                    cursor.execute("UPDATE gap_events SET sent_at=? WHERE id=?", (now, int(rid)))
                except Exception:
                    continue
            conn.commit()
            conn.close()
        except Exception:
            return
    
    def save_batch(self, batch_id: str, data: bytes):
        """保存待上传批次"""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        try:
            cursor.execute(
                'INSERT OR REPLACE INTO pending_uploads (batch_id, data) VALUES (?, ?)',
                (batch_id, data)
            )
            conn.commit()
            logger.info(f"Cached batch {batch_id} for later upload")
            self.cleanup(max_age_hours=self.max_age_hours, max_total_bytes=self.max_total_bytes)
        finally:
            conn.close()
    
    def get_pending_batches(self, max_retry: int = 5) -> List[Tuple[str, bytes]]:
        """获取待上传批次"""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        try:
            cursor.execute(
                'SELECT batch_id, data FROM pending_uploads WHERE retry_count < ? ORDER BY created_at',
                (max_retry,)
            )
            return cursor.fetchall()
        finally:
            conn.close()

    def count_pending_batches(self, max_retry: int = 5) -> int:
        """Return number of pending cached batches.

        A batch is considered pending when retry_count < max_retry.
        """
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        try:
            cursor.execute(
                'SELECT COUNT(*) FROM pending_uploads WHERE retry_count < ?',
                (max_retry,)
            )
            row = cursor.fetchone()
            return int(row[0] if row and row[0] is not None else 0)
        finally:
            conn.close()
    
    def mark_uploaded(self, batch_id: str):
        """标记批次已上传"""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        try:
            cursor.execute('DELETE FROM pending_uploads WHERE batch_id = ?', (batch_id,))
            conn.commit()
        finally:
            conn.close()
    
    def increment_retry(self, batch_id: str):
        """增加重试次数"""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        try:
            cursor.execute(
                'UPDATE pending_uploads SET retry_count = retry_count + 1 WHERE batch_id = ?',
                (batch_id,)
            )
            conn.commit()
        finally:
            conn.close()



    # -------------------------
    # Command idempotency cache
    # -------------------------
    def is_command_executed(self, command_id: str) -> bool:
        """Return True if command_id has already been executed (or skipped/rejected)."""
        if not command_id:
            return False
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        try:
            cursor.execute('SELECT 1 FROM executed_commands WHERE command_id = ? LIMIT 1', (str(command_id),))
            return cursor.fetchone() is not None
        finally:
            conn.close()

    def mark_command_executed(
        self,
        command_id: str,
        site_id: str,
        miner_id: str,
        command: str,
        status: str,
        result_code: int,
        message: str,
        executed_at: str,
    ) -> None:
        """Persist execution record for a command_id to ensure idempotency."""
        if not command_id:
            return
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        try:
            cursor.execute(
                'INSERT OR REPLACE INTO executed_commands (command_id, site_id, miner_id, command, status, result_code, message, executed_at) '
                'VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                (str(command_id), str(site_id), str(miner_id), str(command), str(status), int(result_code), str(message), str(executed_at)),
            )
            conn.commit()
        finally:
            conn.close()



    # -------------------------
    # Pending ACK spool (command results)
    # -------------------------
    def save_ack(self, ack_id: str, protocol: str, endpoint: str, payload_json: str, *, max_payload_chars: int = 200000) -> None:
        """Persist an ACK payload for later replay.

        - ack_id: typically command_id
        - protocol: 'v1' or 'legacy'
        - endpoint: relative endpoint path used for replay
        - payload_json: JSON string (kept small; truncated if needed)
        """
        if not ack_id:
            return
        if payload_json and len(payload_json) > max_payload_chars:
            payload_json = payload_json[:max_payload_chars]
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        try:
            cursor.execute(
                'INSERT OR REPLACE INTO pending_acks (ack_id, protocol, endpoint, payload_json, last_error) VALUES (?, ?, ?, ?, ?)',
                (str(ack_id), str(protocol), str(endpoint), str(payload_json or ""), ""),
            )
            conn.commit()
        finally:
            conn.close()

    def get_pending_acks(self, max_retry: int = 10, limit: int = 50) -> List[Tuple[str, str, str, str]]:
        """Return (ack_id, protocol, endpoint, payload_json) pending replay."""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        try:
            cursor.execute(
                'SELECT ack_id, protocol, endpoint, payload_json FROM pending_acks WHERE retry_count < ? ORDER BY created_at LIMIT ?',
                (int(max_retry), int(limit)),
            )
            return cursor.fetchall()
        finally:
            conn.close()

    def count_pending_acks(self, max_retry: int = 10) -> int:
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        try:
            cursor.execute('SELECT COUNT(*) FROM pending_acks WHERE retry_count < ?', (int(max_retry),))
            row = cursor.fetchone()
            return int(row[0] if row and row[0] is not None else 0)
        finally:
            conn.close()

    def mark_ack_sent(self, ack_id: str) -> None:
        if not ack_id:
            return
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        try:
            cursor.execute('DELETE FROM pending_acks WHERE ack_id = ?', (str(ack_id),))
            conn.commit()
        finally:
            conn.close()

    def increment_ack_retry(self, ack_id: str, last_error: str = "") -> None:
        if not ack_id:
            return
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        try:
            cursor.execute(
                'UPDATE pending_acks SET retry_count = retry_count + 1, last_error = ? WHERE ack_id = ?',
                (str(last_error or ""), str(ack_id)),
            )
            conn.commit()
        finally:
            conn.close()


class CloudUploader:
    """云端数据上传器

    Supports:
    - Legacy endpoint:   POST {base}/api/collector/upload
    - v1 endpoint:       POST {base}/api/edge/v1/telemetry/batch

    Default behavior remains legacy for compatibility, but you can switch via telemetry_api_mode.

    Security invariant:
    - Miner IP addresses and credential-like fields are never uploaded unless include_ip=True.
    - Cached offline batches (spool) are also scrubbed before upload to prevent historical leakage.
    """

    def __init__(
        self,
        api_url: str,
        api_key: str,
        site_id: str,
        include_ip: bool = False,
        *,
        connect_timeout: float = 5.0,
        read_timeout: float = 30.0,
        telemetry_api_mode: str = "legacy",
    ):
        self.api_url = (api_url or "").rstrip("/")
        self.api_key = api_key
        self.site_id = site_id
        self.include_ip = bool(include_ip)
        self.telemetry_api_mode = (telemetry_api_mode or "legacy").strip().lower()
        if self.telemetry_api_mode not in ("legacy", "v1", "auto"):
            self.telemetry_api_mode = "legacy"

        self.session = requests.Session()
        self.session.headers.update({
            # Keep existing header for backward compatibility
            "X-Collector-Key": api_key,
            "X-Site-ID": site_id,
            # Also send Authorization for future-proofing
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/octet-stream",
            "Content-Encoding": "gzip",
        })
        # Use a tuple timeout so connect vs read are controlled independently.
        self.timeout = (float(connect_timeout), float(read_timeout))

        self.last_upload_status: Dict[str, Any] = {
            "ok": None,
            "http_status": None,
            "error_kind": None,
            "error": None,
            "at": None,
            "endpoint": None,
            "mode": None,
        }

    def _endpoint_for_mode(self) -> str:
        # auto -> try v1, fall back to legacy on 404/405
        if self.telemetry_api_mode == "v1":
            return "api/edge/v1/telemetry/batch"
        if self.telemetry_api_mode == "legacy":
            return "api/collector/upload"
        # auto
        return "api/edge/v1/telemetry/batch"

    def _fallback_endpoint(self) -> str:
        return "api/collector/upload"

    def build_payload(self, data: List[MinerData]) -> bytes:
        """Build a gzipped JSON payload for telemetry upload.

        Enforces: no IP/credential fields unless include_ip=True.
        """
        rows: List[Dict[str, Any]] = []
        for d in (data or []):
            dd = asdict(d)
            if not self.include_ip:
                dd.pop("ip_address", None)
                # defense-in-depth: remove any accidental sensitive keys if present
                for k in ("ip", "host", "hostname", "credentials", "cred", "password", "username"):
                    dd.pop(k, None)
            rows.append(dd)
        return gzip.compress(json.dumps(rows).encode("utf-8"))

    def scrub_compressed_payload(self, compressed: bytes) -> bytes:
        """Sanitize an existing cached payload so it cannot leak IP/credentials.

        Protects against older cached batches created before guards were enforced.
        """
        if self.include_ip:
            return compressed
        try:
            raw = gzip.decompress(compressed).decode("utf-8")
            obj = json.loads(raw)
            if not isinstance(obj, list):
                return compressed
            changed = False
            for row in obj:
                if not isinstance(row, dict):
                    continue
                for k in ("ip_address", "ip", "host", "hostname", "credentials", "cred", "password", "username"):
                    if k in row:
                        row.pop(k, None)
                        changed = True
            if changed:
                return gzip.compress(json.dumps(obj).encode("utf-8"))
        except Exception:
            pass
        return compressed

    def upload_compressed(self, compressed: bytes, *, mode: str = "raw") -> bool:
        """Upload a pre-built gzipped payload (used for offline spool replay)."""
        endpoint = self._endpoint_for_mode()
        try:
            payload = self.scrub_compressed_payload(compressed)

            # Optional hint for the cloud side (it can ignore this header if not implemented).
            self.session.headers["X-Upload-Mode"] = str(mode or "raw")

            url = _join_url(self.api_url, endpoint)
            self.last_upload_status.update({
                "ok": None,
                "http_status": None,
                "error_kind": None,
                "error": None,
                "at": _iso_utc_now(),
                "endpoint": endpoint,
                "mode": mode,
            })

            response = self.session.post(url, data=payload, timeout=self.timeout)

            # If we are in auto mode, a 404/405 likely indicates cloud still on legacy.
            if self.telemetry_api_mode == "auto" and response.status_code in (404, 405):
                endpoint = self._fallback_endpoint()
                url = _join_url(self.api_url, endpoint)
                response = self.session.post(url, data=payload, timeout=self.timeout)

            self.last_upload_status["http_status"] = int(response.status_code)

            if response.status_code in (401, 403):
                self.last_upload_status.update({"ok": False, "error_kind": "auth", "error": f"HTTP {response.status_code}"})
                logger.error("Upload auth failed (HTTP %s). Token may be invalid or revoked.", response.status_code)
                return False

            if response.status_code == 200:
                try:
                    result = response.json()
                except Exception:
                    result = {}
                if isinstance(result, dict) and result.get("success"):
                    self.last_upload_status.update({"ok": True, "error_kind": None, "error": None})
                    return True
                err = None
                if isinstance(result, dict):
                    err = result.get("error") or result.get("message")
                self.last_upload_status.update({"ok": False, "error_kind": "app", "error": str(err or "unknown_error")})
                return False

            self.last_upload_status.update({"ok": False, "error_kind": "http", "error": f"HTTP {response.status_code}"})
            return False

        except requests.exceptions.ConnectionError as e:
            self.last_upload_status.update({"ok": False, "error_kind": "network", "error": str(e), "at": _iso_utc_now(), "endpoint": endpoint, "mode": mode})
            logger.warning("Network unavailable, data will be cached")
            return False
        except Exception as e:
            self.last_upload_status.update({"ok": False, "error_kind": "error", "error": f"{type(e).__name__}: {e}", "at": _iso_utc_now(), "endpoint": endpoint, "mode": mode})
            logger.error("Upload error: %s", e)
            return False

    def upload(self, data: List[MinerData], *, mode: str = "raw") -> bool:
        """Convenience wrapper: build payload then upload."""
        return self.upload_compressed(self.build_payload(data), mode=mode)

class CommandExecutor:
    """命令执行器 - 从云端获取并执行控制命令

    Protocol support:
    - v1:    GET  {base}/api/edge/v1/commands/poll
             POST {base}/api/edge/v1/commands/{id}/ack
    - legacy:GET  {base}/api/collector/commands/pending
             POST {base}/api/collector/commands/{id}/result

    Default is 'auto' so the edge can work during cloud migration.
    """

    def __init__(
        self,
        api_url: str,
        api_key: str,
        site_id: str,
        miner_map: Dict[str, Dict],
        miner_key_map: Optional[Dict[str, Dict]] = None,
        offline_cache: Optional["OfflineCache"] = None,
        device_id: Optional[str] = None,
        zone_id: Optional[str] = None,
        enforce_site_id: bool = True,
        enforce_zone_id: bool = True,
        command_api_mode: str = "auto",
        ack_include_snapshot: bool = True,
    ):
        self.api_url = (api_url or "").rstrip("/")
        self.api_key = api_key
        self.site_id = site_id
        self.miner_map = miner_map
        self.miner_key_map = miner_key_map or {}
        self.offline_cache = offline_cache
        self.device_id = device_id
        self.zone_id = zone_id
        self.enforce_site_id = enforce_site_id
        self.enforce_zone_id = bool(enforce_zone_id)
        self.command_api_mode = (command_api_mode or "auto").strip().lower()
        if self.command_api_mode not in ("auto", "legacy", "v1"):
            self.command_api_mode = "auto"
        self.ack_include_snapshot = bool(ack_include_snapshot)

        self.session = requests.Session()
        self.session.headers.update({
            "X-Collector-Key": api_key,
            "X-Site-ID": site_id,
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        })
        if self.device_id:
            self.session.headers["X-Device-ID"] = str(self.device_id)
            # common alias that some servers use
            self.session.headers["X-Edge-ID"] = str(self.device_id)
        if self.zone_id:
            self.session.headers["X-Zone-ID"] = str(self.zone_id)

        self.stats = {
            "commands_fetched": 0,
            "commands_executed": 0,
            "commands_failed": 0,
            "acks_sent": 0,
            "acks_cached": 0,
            "acks_pending": 0,
            "last_poll": None,
            "last_poll_http": None,
            "last_poll_error": None,
            "last_ack_http": None,
            "last_ack_error": None,
            "auth_failed": False,
        }

    # -------------------------
    # Replay cached ACKs
    # -------------------------
    def flush_pending_acks(self, *, max_retry: int = 10, limit: int = 50) -> int:
        if not self.offline_cache:
            return 0
        sent = 0
        pending = self.offline_cache.get_pending_acks(max_retry=max_retry, limit=limit)
        self.stats["acks_pending"] = len(pending)
        for ack_id, protocol, endpoint, payload_json in pending:
            try:
                url = _join_url(self.api_url, str(endpoint))
                payload = json.loads(payload_json) if payload_json else {}
                resp = self.session.post(url, json=payload, timeout=10)
                self.stats["last_ack_http"] = int(resp.status_code)
                if resp.status_code in (401, 403):
                    self.stats["auth_failed"] = True
                    self.stats["last_ack_error"] = f"AUTH_HTTP_{resp.status_code}"
                    return sent
                if resp.status_code == 200:
                    self.offline_cache.mark_ack_sent(str(ack_id))
                    sent += 1
                    self.stats["acks_sent"] += 1
                else:
                    self.offline_cache.increment_ack_retry(str(ack_id), last_error=f"HTTP {resp.status_code}")
            except Exception as e:
                self.offline_cache.increment_ack_retry(str(ack_id), last_error=f"{type(e).__name__}: {e}")
        return sent

    # -------------------------
    # Fetch commands
    # -------------------------
    def _fetch_v1(self) -> Tuple[List[Dict], Optional[int], Optional[str]]:
        url = _join_url(self.api_url, "api/edge/v1/commands/poll")
        try:
            resp = self.session.get(url, timeout=10)
            self.stats["last_poll_http"] = int(resp.status_code)
            if resp.status_code in (401, 403):
                self.stats["auth_failed"] = True
                return [], int(resp.status_code), f"AUTH_HTTP_{resp.status_code}"
            if resp.status_code == 204:
                return [], int(resp.status_code), None
            if resp.status_code == 404 or resp.status_code == 405:
                return [], int(resp.status_code), "NOT_SUPPORTED"
            if resp.status_code != 200:
                return [], int(resp.status_code), f"HTTP_{resp.status_code}"
            data = resp.json()
            if isinstance(data, list):
                return data, 200, None
            if isinstance(data, dict):
                cmds = data.get("commands") or data.get("data") or []
                if isinstance(cmds, list):
                    return cmds, 200, None
            return [], 200, None
        except requests.exceptions.ConnectionError:
            return [], None, "NETWORK"
        except Exception as e:
            return [], None, f"{type(e).__name__}: {e}"

    def _fetch_legacy(self) -> Tuple[List[Dict], Optional[int], Optional[str]]:
        url = _join_url(self.api_url, "api/collector/commands/pending")
        try:
            resp = self.session.get(url, timeout=10)
            self.stats["last_poll_http"] = int(resp.status_code)
            if resp.status_code in (401, 403):
                self.stats["auth_failed"] = True
                return [], int(resp.status_code), f"AUTH_HTTP_{resp.status_code}"
            if resp.status_code != 200:
                return [], int(resp.status_code), f"HTTP_{resp.status_code}"
            data = resp.json()
            if isinstance(data, dict) and data.get("success"):
                cmds = data.get("commands", []) or []
                return cmds if isinstance(cmds, list) else [], 200, None
            # Some legacy servers may return bare list
            if isinstance(data, list):
                return data, 200, None
            return [], 200, None
        except requests.exceptions.ConnectionError:
            return [], None, "NETWORK"
        except Exception as e:
            return [], None, f"{type(e).__name__}: {e}"

    def fetch_pending_commands(self) -> Tuple[List[Dict], str]:
        """Return (commands, protocol_used)."""
        self.stats["last_poll"] = _iso_utc_now()
        self.stats["last_poll_error"] = None
        protocol_used = "legacy"

        if self.command_api_mode in ("v1", "auto"):
            cmds, http, err = self._fetch_v1()
            if err == "NOT_SUPPORTED" and self.command_api_mode == "auto":
                # fall back
                pass
            else:
                protocol_used = "v1"
                if err:
                    self.stats["last_poll_error"] = err
                return cmds, protocol_used

        cmds, http, err = self._fetch_legacy()
        if err:
            self.stats["last_poll_error"] = err
        return cmds, protocol_used

    # -------------------------
    # ACK / result reporting
    # -------------------------
    def _ack_endpoint(self, protocol: str, command_id: Any) -> str:
        if protocol == "v1":
            return f"api/edge/v1/commands/{command_id}/ack"
        return f"api/collector/commands/{command_id}/result"

    def report_result(
        self,
        protocol: str,
        command_id: Any,
        status: str,
        result_code: int,
        message: str,
        *,
        miner_id: Optional[str] = None,
        miner_key: Optional[str] = None,
        command: Optional[str] = None,
        duration_ms: Optional[int] = None,
        before: Optional[Dict[str, Any]] = None,
        after: Optional[Dict[str, Any]] = None,
        error_class: Optional[str] = None,
    ) -> None:
        """Report command execution result back to cloud.

        If cloud is unreachable, ACK is spooled to OfflineCache.pending_acks for replay.
        """
        endpoint = self._ack_endpoint(protocol, command_id)
        payload: Dict[str, Any] = {
            "status": status,
            "result_code": int(result_code),
            "result_message": message,
            "site_id": self.site_id,
            "executed_at": _iso_utc_now(),
        }
        if miner_id:
            payload["miner_id"] = str(miner_id)
        if miner_key:
            payload["miner_key"] = str(miner_key)
        if command:
            payload["command"] = str(command)
        if self.device_id:
            payload["device_id"] = str(self.device_id)
        if duration_ms is not None:
            payload["duration_ms"] = int(duration_ms)
        if self.zone_id:
            payload["zone_id"] = str(self.zone_id)
        if error_class:
            payload["error_class"] = str(error_class)
        if self.ack_include_snapshot:
            if before is not None:
                payload["before"] = before
            if after is not None:
                payload["after"] = after

        url = _join_url(self.api_url, endpoint)
        try:
            resp = self.session.post(url, json=payload, timeout=10)
            self.stats["last_ack_http"] = int(resp.status_code)
            if resp.status_code in (401, 403):
                self.stats["auth_failed"] = True
                self.stats["last_ack_error"] = f"AUTH_HTTP_{resp.status_code}"
            if resp.status_code == 200:
                self.stats["acks_sent"] += 1
                self.stats["last_ack_error"] = None
            else:
                self.stats["last_ack_error"] = f"HTTP_{resp.status_code}"
                if self.offline_cache and command_id:
                    self.offline_cache.save_ack(str(command_id), protocol, endpoint, json.dumps(payload))
                    self.stats["acks_cached"] += 1
        except requests.exceptions.ConnectionError as e:
            if self.offline_cache and command_id:
                self.offline_cache.save_ack(str(command_id), protocol, endpoint, json.dumps(payload))
                self.stats["acks_cached"] += 1
            self.stats["last_ack_error"] = f"NETWORK: {e}"
        except Exception as e:
            if self.offline_cache and command_id:
                self.offline_cache.save_ack(str(command_id), protocol, endpoint, json.dumps(payload))
                self.stats["acks_cached"] += 1
            self.stats["last_ack_error"] = f"{type(e).__name__}: {e}"

    # -------------------------
    # Snapshot helper
    # -------------------------
    def _snapshot_from_api(self, api: CGMinerAPI, miner_id: str, miner_type: str) -> Optional[Dict[str, Any]]:
        try:
            summary = api.get_summary()
            stats = api.get_stats()
            pools = api.get_pools()
            if not summary:
                return None
            # Reuse telemetry parser so we keep consistent field extraction.
            if miner_type == "whatsminer":
                md = MinerDataParser.parse_whatsminer(summary, stats, pools, api.host, miner_id)
            elif miner_type == "avalon":
                md = MinerDataParser.parse_avalon(summary, stats, pools, api.host, miner_id)
            else:
                md = MinerDataParser.parse_antminer(summary, stats, pools, api.host, miner_id)

            snap = {
                "online": bool(md.online),
                "hashrate_ghs": float(md.hashrate_ghs or 0.0),
                "hashrate_5s_ghs": float(md.hashrate_5s_ghs or 0.0),
                "temp_avg": float(md.temperature_avg or 0.0),
                "temp_max": float(md.temperature_max or 0.0),
                "fan_speeds": md.fan_speeds or [],
                "pool_url": md.pool_url or "",
                "worker_name": md.worker_name or "",
            }
            return snap
        except Exception:
            return None

    def execute_command(self, cmd: Dict) -> Tuple[str, int, str, int, Optional[Dict[str, Any]], Optional[Dict[str, Any]], Optional[str]]:
        """Execute a single command.

        Security model:
        - The cloud is NEVER trusted to provide miner IPs. We only accept miner_id and resolve
          to ip:port using the local miner_map (whitelist).
        - Optionally enforce cmd.site_id == self.site_id.
        - Idempotency is enforced via OfflineCache.executed_commands when available.
        """
        command_id = cmd.get("command_id") or cmd.get("id")
        miner_id = str(cmd.get("miner_id") or "").strip()
        miner_key = str(cmd.get("miner_key") or cmd.get("target_miner_key") or cmd.get("device_key") or "").strip()
        command_type = str(cmd.get("command") or cmd.get("action") or "").strip()
        params = cmd.get("params") or {}
        cmd_site_id = cmd.get("site_id")
        cmd_zone_id = cmd.get("zone_id")

        now_utc = datetime.utcnow()

        # Enforce site isolation (defense-in-depth; poll endpoint should already be site-scoped)
        if self.enforce_site_id and cmd_site_id and str(cmd_site_id) != str(self.site_id):
            status, code, message = "rejected", 3, f"SITE_MISMATCH: cmd.site_id={cmd_site_id} expected={self.site_id}"
            if self.offline_cache and command_id:
                self.offline_cache.mark_command_executed(str(command_id), str(self.site_id), miner_id, command_type, status, code, message, _iso_utc_now())
            return status, code, message, 0, None, None, "site_mismatch"

        # Enforce zone isolation (single-zone edge should refuse cross-zone commands)
        if getattr(self, "enforce_zone_id", True) and self.zone_id and cmd_zone_id and str(cmd_zone_id) != str(self.zone_id):
            status, code, message = "rejected", 3, f"ZONE_MISMATCH: cmd.zone_id={cmd_zone_id} expected={self.zone_id}"
            if self.offline_cache and command_id:
                self.offline_cache.mark_command_executed(str(command_id), str(self.site_id), miner_id, command_type, status, code, message, _iso_utc_now())
            return status, code, message, 0, None, None, "zone_mismatch"

        # TTL / expiration checks (best-effort; cloud should still cancel/expire commands server-side)
        def _parse_iso(ts: Any) -> Optional[datetime]:
            if not ts:
                return None
            try:
                s = str(ts).strip()
                if not s:
                    return None
                if s.endswith("Z"):
                    s = s[:-1] + "+00:00"
                dt = datetime.fromisoformat(s)
                if dt.tzinfo is not None:
                    dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
                return dt
            except Exception:
                return None

        expires_at = _parse_iso(cmd.get("expires_at"))
        if not expires_at:
            ttl_sec = cmd.get("ttl_sec") or cmd.get("ttl_seconds")
            issued_at = _parse_iso(cmd.get("issued_at"))
            if ttl_sec and issued_at:
                try:
                    expires_at = issued_at + timedelta(seconds=int(ttl_sec))
                except Exception:
                    expires_at = None

        if expires_at and expires_at <= now_utc:
            status, code, message = "rejected", 3, "COMMAND_EXPIRED"
            if self.offline_cache and command_id:
                self.offline_cache.mark_command_executed(str(command_id), str(self.site_id), miner_id, command_type, status, code, message, _iso_utc_now())
            return status, code, message, 0, None, None, "expired"

        # Idempotency / de-duplication
        if self.offline_cache and command_id and self.offline_cache.is_command_executed(str(command_id)):
            return "skipped", 2, "DUPLICATE_IGNORED", 0, None, None, "duplicate"

        # Resolve target miner by miner_id or miner_key (miner_key preferred).
        resolved_miner: Optional[Dict[str, Any]] = None
        if miner_key:
            try:
                resolved_miner = (self.miner_key_map or {}).get(str(miner_key))
            except Exception:
                resolved_miner = None
            if resolved_miner:
                resolved_id = str(resolved_miner.get("id") or resolved_miner.get("asset_id") or "").strip()
                if miner_id and resolved_id and resolved_id != miner_id:
                    status, code, message = "failed", 1, "MINER_ID_MISMATCH_FOR_MINER_KEY"
                    if self.offline_cache and command_id:
                        self.offline_cache.mark_command_executed(
                            str(command_id),
                            str(self.site_id),
                            resolved_id or miner_id,
                            command_type,
                            status,
                            code,
                            message,
                            _iso_utc_now(),
                        )
                    return status, code, message, 0, None, None, "invalid_target"
                if resolved_id:
                    miner_id = resolved_id

        if not miner_id:
            status, code, message = "failed", 1, "MISSING_MINER_TARGET"
            if self.offline_cache and command_id:
                self.offline_cache.mark_command_executed(
                    str(command_id),
                    str(self.site_id),
                    miner_id,
                    command_type,
                    status,
                    code,
                    message,
                    _iso_utc_now(),
                )
            return status, code, message, 0, None, None, "bad_request"

        miner = resolved_miner or self.miner_map.get(miner_id)
        if not miner:
            status, code, message = "failed", 1, (
                f"MINER_KEY_NOT_REGISTERED_ON_EDGE: {miner_key}" if miner_key else f"MINER_NOT_REGISTERED_ON_EDGE: {miner_id}"
            )
            if self.offline_cache and command_id:
                self.offline_cache.mark_command_executed(
                    str(command_id),
                    str(self.site_id),
                    miner_id,
                    command_type,
                    status,
                    code,
                    message,
                    _iso_utc_now(),
                )
            return status, code, message, 0, None, None, "not_found"

        miner = self.miner_map.get(miner_id)
        if not miner:
            status, code, message = "failed", 1, f"MINER_NOT_REGISTERED_ON_EDGE: {miner_id}"
            if self.offline_cache and command_id:
                self.offline_cache.mark_command_executed(str(command_id), str(self.site_id), miner_id, command_type, status, code, message, _iso_utc_now())
            return status, code, message, 0, None, None, "unknown_miner"

        ip_address = miner.get("ip")
        port = int(miner.get("port", 4028) or 4028)
        miner_type = str(miner.get("type") or "antminer").strip().lower()

        # Zone isolation (defense-in-depth): reject commands for miners outside this edge's zone
        miner_zone_id = miner.get("zone_id")
        if getattr(self, "enforce_zone_id", True) and self.zone_id and miner_zone_id and str(miner_zone_id) != str(self.zone_id):
            status, code, message = "failed", 1, f"MINER_ZONE_MISMATCH: miner_zone_id={miner_zone_id} edge_zone_id={self.zone_id}"
            if self.offline_cache and command_id:
                self.offline_cache.mark_command_executed(str(command_id), str(self.site_id), miner_id, command_type, status, code, message, _iso_utc_now())
            return status, code, message, 0, None, None, "zone_mismatch"

        protocol = str(miner.get("protocol") or "cgminer").strip().lower()
        # Guardrail: control actions must never be executed over HTTP fallback paths.
        # Whatsminer HTTP support is telemetry-only (best-effort) to avoid credential exposure and unintended actions.
        if protocol in ("http", "https", "whatsminer_http"):
            status, code, message = "failed", 1, "CONTROL_NOT_SUPPORTED_OVER_HTTP"
            if self.offline_cache and command_id:
                self.offline_cache.mark_command_executed(str(command_id), str(self.site_id), miner_id, command_type, status, code, message, _iso_utc_now())
            return status, code, message, 0, None, None, "unsupported_protocol"

        cap = miner.get("capability") or {}
        supported_actions = set(cap.get("supported_actions") or [])
        if supported_actions and command_type and command_type not in supported_actions:
            status, code, message = "failed", 1, f"UNSUPPORTED_ACTION: {command_type}"
            if self.offline_cache and command_id:
                self.offline_cache.mark_command_executed(str(command_id), str(self.site_id), miner_id, command_type, status, code, message, _iso_utc_now())
            return status, code, message, 0, None, None, "unsupported_action"

        if not ip_address:
            status, code, message = "failed", 1, f"NO_IP_FOR_MINER_ID: {miner_id}"
            if self.offline_cache and command_id:
                self.offline_cache.mark_command_executed(str(command_id), str(self.site_id), miner_id, command_type, status, code, message, _iso_utc_now())
            return status, code, message, 0, None, None, "bad_edge_state"

        logger.info("Executing command %s: %s on %s (%s:%s)", command_id, command_type, miner_id, mask_ip(ip_address), port)

        t0 = time.time()
        api = CGMinerAPI(ip_address, port)
        before = self._snapshot_from_api(api, miner_id, miner_type) if self.ack_include_snapshot else None

        success, msg = api.execute_control_command(command_type, params)
        duration_ms = int((time.time() - t0) * 1000)

        # Best-effort after snapshot. For reboot-like commands the miner may temporarily disappear.
        after = None
        if self.ack_include_snapshot:
            try:
                wait_sec = float(params.get("post_wait_sec", 2.0))
            except Exception:
                wait_sec = 2.0
            if wait_sec > 0:
                time.sleep(min(wait_sec, 10.0))
            after = self._snapshot_from_api(api, miner_id, miner_type)

        if success:
            self.stats["commands_executed"] += 1
            status, code, err_class = "completed", 0, None
            logger.info("Command %s succeeded: %s", command_id, msg)
        else:
            self.stats["commands_failed"] += 1
            status, code, err_class = "failed", 1, "execution_failed"
            logger.warning("Command %s failed: %s", command_id, msg)

        if self.offline_cache and command_id:
            self.offline_cache.mark_command_executed(str(command_id), str(self.site_id), miner_id, command_type, status, code, msg, _iso_utc_now())

        return status, code, msg, duration_ms, before, after, err_class

    def process_commands(self) -> int:
        """Process pending control commands."""
        # Replay cached ACKs first to keep cloud state correct.
        try:
            self.flush_pending_acks()
        except Exception:
            pass

        commands, protocol = self.fetch_pending_commands()

        if not commands:
            return 0

        for cmd in commands:
            command_id = cmd.get("command_id") or cmd.get("id")
            miner_id = cmd.get("miner_id")
            command_type = cmd.get("command") or cmd.get("action")

            try:
                status, code, message, duration_ms, before, after, err_class = self.execute_command(cmd)
                self.report_result(
                    protocol,
                    command_id,
                    status=status,
                    result_code=code,
                    message=message,
                    miner_id=str(miner_id) if miner_id is not None else None,
                    miner_key=(str(cmd.get("miner_key") or cmd.get("target_miner_key") or cmd.get("device_key") or "").strip() or None),
                    command=str(command_type) if command_type is not None else None,
                    duration_ms=duration_ms,
                    before=before,
                    after=after,
                    error_class=err_class,
                )
            except Exception as e:
                logger.error("Command %s execution error: %s", command_id, e)
                self.report_result(
                    protocol,
                    command_id,
                    status="failed",
                    result_code=1,
                    message=str(e),
                    miner_id=str(miner_id) if miner_id is not None else None,
                    miner_key=(str(cmd.get("miner_key") or cmd.get("target_miner_key") or cmd.get("device_key") or "").strip() or None),
                    command=str(command_type) if command_type is not None else None,
                    duration_ms=0,
                    before=None,
                    after=None,
                    error_class="exception",
                )

        # Update pending ACK count for UI
        if self.offline_cache:
            try:
                self.stats["acks_pending"] = self.offline_cache.count_pending_acks()
            except Exception:
                pass

        return len(commands)


class EdgeCollector:
    """边缘采集器主类"""
    
    def __init__(self, config: Dict):
        self.config = config

        # Inventory sources (merge order): miners | binding | ip_ranges
        inv_raw = config.get("inventory_sources")
        inv: List[str] = []
        if isinstance(inv_raw, list):
            inv = [str(x).strip().lower() for x in inv_raw if str(x).strip()]
        elif isinstance(inv_raw, str):
            inv = [s.strip().lower() for s in inv_raw.split(",") if s.strip()]
        if not inv:
            inv = ["miners", "binding", "ip_ranges"]
        self.inventory_sources = inv

        self.miners = config.get('miners', []) if "miners" in self.inventory_sources else []

        # Identity / scope (site + zone)
        # Note: self.site_id is also set later for backward compatibility; set it early
        # so local-only inventory (CSV bindings) can use defaults.
        self.site_id = config.get('site_id', 'default')
        self.zone_id = str(config.get('zone_id') or '').strip()

        # Privacy toggles
        self.mask_ip_in_logs = bool(config.get('mask_ip_in_logs', True))
        self.enable_whatsminer_http = bool(config.get('enable_whatsminer_http', True))

        # Local-only CSV -> SQLite binding store (preferred inventory source)
        self.binding_enable = bool(config.get('binding_enable', True))
        self.binding_csv_path = str(config.get('binding_csv_path') or './miners.csv')
        self.binding_db_path = str(config.get('binding_db_path') or '')
        if not self.binding_db_path:
            # Fallback: keep it alongside cache_dir for single-folder deployments
            try:
                cache_dir = Path(config.get('cache_dir', './cache'))
                self.binding_db_path = str((cache_dir.parent / 'data' / 'binding_store.db').resolve())
            except Exception:
                self.binding_db_path = './data/binding_store.db'

        self.binding_store: Optional[BindingStore] = None
        self.capability_probe = CapabilityProbe(http_enabled=self.enable_whatsminer_http)
        self._binding_inventory_active = False

        try:
            csv_p = Path(self.binding_csv_path)
            if ('binding' in self.inventory_sources) and self.binding_enable and csv_p.exists():
                Path(self.binding_db_path).parent.mkdir(parents=True, exist_ok=True)
                self.binding_store = BindingStore(self.binding_db_path)
                # Import (upsert) and load inventory filtered by site/zone
                self.binding_store.import_from_csv(
                    str(csv_p),
                    default_site_id=self.site_id,
                    default_zone_id=self.zone_id,
                    encrypt_credentials=bool(config.get('binding_encrypt_credentials', True)),
                )
                bindings = self.binding_store.list_bindings(site_id=self.site_id, zone_id=self.zone_id)
                if bindings:
                    existing_ids = {str(m.get("id")) for m in (self.miners or []) if m.get("id")}
                    existing_ips = {(str(m.get("ip") or ""), int(m.get("port", 4028) or 4028)) for m in (self.miners or []) if m.get("ip")}
                    added = 0
                    for b in bindings:
                        mid = str(b.get("asset_id") or "").strip()
                        ip = str(b.get("ip") or "").strip()
                        if not mid or not ip:
                            continue
                        port = int(b.get("port") or 4028)
                        key = (ip, port)
                        if mid in existing_ids or key in existing_ips:
                            continue
                        self.miners.append({
                            'id': mid,
                            'ip': ip,
                            'port': port,
                            'type': (b.get('vendor') or 'antminer'),
                            'vendor': (b.get('vendor') or 'antminer'),
                            'protocol': (b.get('protocol') or 'cgminer'),
                            'site_id': b.get('site_id') or self.site_id,
                            'zone_id': b.get('zone_id') or self.zone_id,
                            # Credentials stay local; never uploaded.
                            'credentials': b.get('credentials') or {},
                            'capability': b.get('capability') or {},
                        })
                        existing_ids.add(mid)
                        existing_ips.add(key)
                        added += 1

                    self._binding_inventory_active = True
                    logger.info("Loaded %s bindings from CSV (added=%s, total_miners=%s, site_id=%s, zone_id=%s)",
                                len(bindings), added, len(self.miners), self.site_id, self.zone_id)
        except Exception as e:
            logger.warning("Binding inventory disabled due to error: %s", e)

        # Optional: expand ip_ranges into miners automatically.
        # This enables large-fleet deployments without materializing 10k miners in the UI.
        # Supported formats: CIDR (e.g. 192.168.10.0/24) and range (e.g. 192.168.10.10-192.168.10.250).
        # Config example:
        #   ip_ranges: [{"range":"192.168.1.0/24", "prefix":"S21_", "type":"antminer", "port":4028}]
        ip_ranges = config.get('ip_ranges') or []
        allow_with_binding = bool(config.get('ip_ranges_allow_with_binding', False)) or ('ip_ranges' in self.inventory_sources)
        if ('ip_ranges' in self.inventory_sources) and isinstance(ip_ranges, list) and ip_ranges and (not self._binding_inventory_active or allow_with_binding):
            parser = IPRangeParser()
            expanded: List[Dict[str, Any]] = []
            total_cap = int(config.get('ip_ranges_total_cap', 20000))
            per_range_cap = int(config.get('ip_ranges_cap_per_range', 20000))
            total_so_far = 0

            for entry in ip_ranges:
                if not isinstance(entry, dict):
                    continue
                r = str(entry.get('range', '')).strip()
                if not r:
                    continue
                prefix = str(entry.get('prefix', 'miner_'))
                mtype = str(entry.get('type', 'antminer'))
                port = int(entry.get('port', 4028))
                id_format = str(entry.get('id_format', 'seq')).lower()  # 'seq' | 'ip'

                try:
                    start_ip, end_ip, total = parser.parse(r)
                except IPRangeError as e:
                    logger.warning(f"Invalid ip_ranges entry '{r}': {e}")
                    continue
                except Exception as e:
                    logger.warning(f"Invalid ip_ranges entry '{r}': {type(e).__name__}: {e}")
                    continue

                if total > per_range_cap:
                    logger.warning(
                        f"ip_ranges entry '{r}' expands to {total} IPs; cap is {per_range_cap}. "
                        f"Increase ip_ranges_cap_per_range to allow."
                    )
                    continue
                if (total_so_far + total) > total_cap:
                    logger.warning(
                        f"ip_ranges total would exceed cap ({total_cap}). "
                        f"Processed so far={total_so_far}, entry={total}."
                    )
                    break

                idx = 1
                for ip in parser.enumerate_ips(start_ip, end_ip):
                    if id_format == 'ip':
                        mid = f"{prefix}{ip.replace('.', '_')}"
                    else:
                        mid = f"{prefix}{idx:04d}"
                    expanded.append({'id': mid, 'ip': ip, 'port': port, 'type': mtype})
                    idx += 1
                total_so_far += total

            # Merge expanded list into miners, without duplicating by (ip,port) or id.
            if expanded:
                existing_ips = set()
                existing_ids = set()
                for m in (self.miners or []):
                    try:
                        existing_ids.add(str(m.get('id') or ''))
                        existing_ips.add((str(m.get('ip') or ''), int(m.get('port', 4028))))
                    except Exception:
                        continue

                for m in expanded:
                    try:
                        mid = str(m.get('id') or '')
                        key = (str(m.get('ip') or ''), int(m.get('port', 4028)))
                        if (mid and mid in existing_ids) or (key in existing_ips):
                            continue
                        self.miners.append(m)
                        if mid:
                            existing_ids.add(mid)
                        existing_ips.add(key)
                    except Exception:
                        continue

        # Scheduling (two-loop polling)
        # - latest: near-real-time lightweight fields
        # - raw: heavier fields required for 24h monitor / history
        self.latest_interval = int(config.get('latest_interval', config.get('collection_interval', 30)))
        self.raw_interval = int(config.get('raw_interval', max(self.latest_interval, config.get('collection_interval', 30))))

        # Backward compatible alias
        self.collection_interval = self.latest_interval

        self.command_poll_interval = config.get('command_poll_interval', 5)
        self.max_workers = config.get('max_workers', 50)

        # Miner connection behavior (plumbed from HashInsight Remote UI)
        # Use separate timeouts for latest vs raw to avoid long tail blocks.
        self.miner_timeout_fast = float(config.get('miner_timeout_fast', config.get('miner_timeout', 5.0)))
        self.miner_timeout_slow = float(config.get('miner_timeout_slow', config.get('miner_timeout', 5.0)))
        # Keep for backward compatibility
        self.miner_timeout = self.miner_timeout_slow
        self.miner_max_retries = int(config.get('miner_max_retries', 1))
        # If the first attempt indicates the miner is offline/unreachable, do not keep retrying
        # in the same cycle (prevents long-tail delays across large fleets).
        # Set to True to restore the old retry behavior.
        self.retry_on_first_offline = bool(config.get('retry_on_first_offline', False))

        # Offline backoff (avoid re-timeouting the same dead miners every 5-10s)
        self.offline_backoff_base = float(config.get('offline_backoff_base', 10.0))
        self.offline_backoff_max = float(config.get('offline_backoff_max', 300.0))

        # Latest sampling (site-level near real-time): if miner count is huge,
        # poll a rolling window each latest tick.
        self.latest_max_miners = int(config.get('latest_max_miners', 2000))
        self._latest_cursor = 0

        # Sharding (run multiple collectors in parallel for 5k-10k miners)
        self.shard_total = max(1, int(config.get('shard_total', 1)))
        self.shard_index = int(config.get('shard_index', 0))
        if self.shard_index < 0 or self.shard_index >= self.shard_total:
            self.shard_index = 0

        self.api_url = config.get('api_url', 'http://localhost:5000')
        self.api_key = config.get('api_key', '')
        self.site_id = config.get('site_id', 'default')

        # Upload tuning
        self.batch_size = max(1, int(config.get('batch_size', 1000)))
        self.upload_connect_timeout = float(config.get('upload_connect_timeout', 5.0))
        self.upload_read_timeout = float(config.get('upload_read_timeout', 60.0))

        # Cached retry cadence
        self.retry_interval_sec = float(config.get('retry_interval_sec', 300.0))
        self._last_retry_ts = time.time()
        # Upload retry policy
        self.max_retries = int(config.get('max_retries', 5))
        self.max_retry_batches_per_tick = int(config.get('max_retry_batches_per_tick', 1))
        
        self.cache = OfflineCache(
            config.get('cache_dir', './cache'),
            max_age_hours=int(config.get('offline_spool_max_age_hours', 24)),
            max_total_bytes=int(config.get('offline_spool_max_total_bytes', 10 * 1024 * 1024 * 1024)),
        )

        # Stable edge device identity for audit/claim. Persist in cache_dir/device_id
        self.device_id = str(config.get('device_id') or '').strip()
        if not self.device_id:
            try:
                did_path = Path(config.get('cache_dir', './cache')) / 'device_id'
                if did_path.exists():
                    self.device_id = did_path.read_text(encoding='utf-8').strip()
                if not self.device_id:
                    self.device_id = str(uuid.uuid4())
                    did_path.write_text(self.device_id, encoding='utf-8')
            except Exception:
                self.device_id = str(uuid.uuid4())

        if bool(config.get("upload_include_ip", False)):
            logger.warning("Config upload_include_ip=True is ignored: miner IP addresses are never uploaded to cloud.")

        self.uploader = CloudUploader(
            self.api_url,
            self.api_key,
            self.site_id,
            include_ip=False,
            connect_timeout=self.upload_connect_timeout,
            read_timeout=self.upload_read_timeout,
        )

        # Miner health state
        # miner_id -> {fails:int, next_allowed:float}
        self._miner_health: Dict[str, Dict[str, float]] = {}

        # Apply sharding to miners list
        if self.shard_total > 1:
            def _keep(m: Dict) -> bool:
                mid = str(m.get('id') or m.get('ip') or '')
                return (hash(mid) % self.shard_total) == self.shard_index
            self.miners = [m for m in self.miners if _keep(m)]
        
        # Device identity (miner_key): stable per-miner token stored locally.
        # Cloud should target miners by miner_key; Edge resolves miner_key -> ip locally.
        self.device_identity_enable = bool(config.get("device_identity_enable", True))
        self._miner_by_key: Dict[str, Dict] = {}

        if self.device_identity_enable:
            try:
                # Ensure a local binding store exists to persist miner_key (even if binding CSV is not used).
                if self.binding_store is None:
                    Path(self.binding_db_path).parent.mkdir(parents=True, exist_ok=True)
                    self.binding_store = BindingStore(self.binding_db_path)

                for m in (self.miners or []):
                    asset_id = str(m.get("id") or m.get("asset_id") or m.get("miner_id") or m.get("ip") or "").strip()
                    ip = str(m.get("ip") or "").strip()
                    if not asset_id or not ip:
                        continue

                    vendor = str(m.get("vendor") or m.get("type") or "antminer").lower()
                    protocol = str(m.get("protocol") or "cgminer").lower()
                    try:
                        port = int(m.get("port", 4028) or 4028)
                    except Exception:
                        port = 4028

                    mk_pref = str(m.get("miner_key") or m.get("device_key") or "").strip()
                    creds = m.get("credentials") or m.get("cred") or {}
                    mk = self.binding_store.upsert_binding(
                        asset_id=asset_id,
                        ip=ip,
                        port=port,
                        vendor=vendor,
                        protocol=protocol,
                        zone_id=str(m.get("zone_id") or self.zone_id or ""),
                        site_id=str(m.get("site_id") or self.site_id or ""),
                        miner_key=mk_pref,
                        credentials=creds,
                        encrypt_credentials=bool(config.get("binding_encrypt_credentials", True)),
                    )
                    m["id"] = asset_id
                    m["miner_key"] = mk
            except Exception as e:
                logger.warning("Device identity (miner_key) initialization failed; continuing without miner_key. err=%s", e)
                self.device_identity_enable = False

        # Enrich miner inventory records (local-only; do NOT upload IP/creds)
        enriched: Dict[str, Dict] = {}
        for m in self.miners:
            mid = m.get('id') or m.get('ip')
            if not mid or not m.get('ip'):
                continue
            vendor = str(m.get('vendor') or m.get('type') or 'antminer').lower()
            protocol = str(m.get('protocol') or 'cgminer').lower()
            creds = m.get('credentials') or m.get('cred') or {}
            cap = m.get('capability') or self.capability_probe.infer(vendor=vendor, protocol=protocol)
            enriched[str(mid)] = {
                **m,
                'vendor': vendor,
                'protocol': protocol,
                'credentials': creds,
                'capability': cap,
                'site_id': m.get('site_id') or self.site_id,
                'zone_id': m.get('zone_id') or self.zone_id,
            }

        self.miner_map = enriched
        self._miner_by_id = dict(self.miner_map)
        self._miner_by_key = {str(v.get('miner_key')): v for v in self.miner_map.values() if v.get('miner_key')}
        self.command_executor = CommandExecutor(
            self.api_url,
            self.api_key,
            self.site_id,
            self.miner_map,
            miner_key_map=self._miner_by_key,
            offline_cache=self.cache,
            device_id=self.device_id,
            enforce_site_id=bool(config.get('enforce_site_id_in_commands', True)),
        )
        
        self.running = False
        # Used to request a fast stop without waiting for long network timeouts.
        self._stop_event = threading.Event()
        self.enable_commands = config.get('enable_commands', True)
        self.stats = {
            'total_collected': 0,
            'successful': 0,
            'failed': 0,
            'last_collection': None
        }
    
    def _is_miner_due(self, miner_id: str, now: 'Optional[float]' = None) -> bool:
        """Return True if this miner should be attempted now (offline backoff gate).

        Supports both call styles:
          - _is_miner_due(miner_id)
          - _is_miner_due(miner_id, now)
        """
        st = self._miner_health.get(miner_id)
        if not st:
            return True
        if now is None:
            now = time.time()
        return float(now) >= float(st.get('next_allowed', 0.0))

    def _mark_miner_failure(self, miner_id: str) -> None:
        st = self._miner_health.setdefault(miner_id, {'fails': 0, 'next_allowed': 0.0})
        st['fails'] = float(st.get('fails', 0.0)) + 1.0
        backoff = min(self.offline_backoff_max, self.offline_backoff_base * (2 ** int(st['fails'] - 1)))
        st['next_allowed'] = time.time() + float(backoff)

    def _mark_miner_success(self, miner_id: str) -> None:
        if miner_id in self._miner_health:
            self._miner_health[miner_id]['fails'] = 0.0
            self._miner_health[miner_id]['next_allowed'] = 0.0

    def collect_single_miner(self, miner_config: Dict, *, mode: str = "raw") -> Optional[MinerData]:
        """采集单个矿机数据"""
        ip = miner_config.get('ip')
        miner_id = miner_config.get('id', ip)
        miner_key = str(miner_config.get('miner_key') or miner_config.get('device_key') or '').strip()
        # type/vendor/protocol: used to select TCP(4028) vs HTTP fallback
        miner_type = str(miner_config.get('type', 'antminer') or 'antminer').lower()
        vendor = str(miner_config.get('vendor') or miner_type or 'antminer').lower()
        protocol = str(miner_config.get('protocol') or 'cgminer').lower()
        credentials = miner_config.get('credentials') or miner_config.get('cred') or {}
        port = miner_config.get('port', 4028)

        # Fast stop: do not start new miner probes once stop is requested
        if getattr(self, '_stop_event', None) is not None and self._stop_event.is_set():
            return None

        # Skip miners that are still in offline backoff
        if not self._is_miner_due(miner_id):
            return None

        timeout = self.miner_timeout_slow if mode == "raw" else self.miner_timeout_fast

        # Protocol selection:
        # - cgminer/tcp(4028) is primary for Antminer and most Whatsminer.
        # - Whatsminer HTTP is optional fallback for telemetry only.
        attempts = 0
        api: Optional[CGMinerAPI] = None
        summary: Optional[Dict] = None
        http_ok = False
        http_payload: Optional[Dict] = None

        def _try_cgminer() -> Optional[Dict]:
            nonlocal attempts, api
            api = CGMinerAPI(ip, port, timeout=timeout)
            attempts = 1
            s = api.get_summary()
            if (not s) and self.retry_on_first_offline and self.miner_max_retries > 1:
                for _ in range(1, max(1, self.miner_max_retries)):
                    time.sleep(0.15)
                    attempts += 1
                    s = api.get_summary()
                    if s:
                        break
            return s

        if protocol in ("cgminer", "tcp", "4028", "auto", ""):
            summary = _try_cgminer()

        # If TCP is down, allow Whatsminer HTTP best-effort fallback (telemetry only)
        if (not summary) and bool(getattr(self, "enable_whatsminer_http", True)) and vendor in ("whatsminer", "microbt"):
            try:
                client = WhatsminerHTTPClient(
                    host=str(ip),
                    username=str(credentials.get("username") or ""),
                    password=str(credentials.get("password") or ""),
                    timeout=timeout,
                )
                r = client.fetch_best_effort()
                http_ok = bool(r and r.get("ok"))
                http_payload = r.get("data") if isinstance(r, dict) else None
            except Exception:
                http_ok = False
                http_payload = None

        if not summary and http_ok and isinstance(http_payload, dict):
            self._mark_miner_success(miner_id)
            if self.binding_store is not None:
                try:
                    self.binding_store.touch_last_seen(str(miner_id))
                except Exception:
                    pass
            return MinerDataParser.parse_whatsminer_http(http_payload, ip, str(miner_id), miner_key)

        if not summary:
            self._mark_miner_failure(miner_id)
            return MinerData(
            miner_id=miner_id,
            miner_key=miner_key,
            ip_address=ip,
                timestamp=datetime.utcnow().isoformat(),
                online=False,
                error_message=(
                    f"Connection failed (protocol={protocol}, timeout={timeout}s, attempts={attempts}, "
                    f"retry_on_first_offline={self.retry_on_first_offline})"
                )
            )

        self._mark_miner_success(miner_id)

        if self.binding_store is not None:
            try:
                self.binding_store.touch_last_seen(str(miner_id))
            except Exception:
                pass

        # Lightweight vs heavy collection
        stats = api.get_stats() if mode in ("latest", "raw") else {}
        pools = api.get_pools() if mode == "raw" else []
        
        if miner_type == 'whatsminer':
            return MinerDataParser.parse_whatsminer(summary, stats, pools, ip, miner_id, miner_key)
        elif miner_type == 'avalon':
            return MinerDataParser.parse_avalon(summary, stats, pools, ip, miner_id, miner_key)
        else:
            return MinerDataParser.parse_antminer(summary, stats, pools, ip, miner_id, miner_key)
    
    def collect_all(self, *, mode: str = "raw") -> List[MinerData]:
        """并行采集矿机数据

        Stop behavior:
          - If stop is requested, do not enqueue new miner probes.
          - If stop is requested mid-cycle, return early without waiting for all workers.
            (Running socket calls will still time out based on miner_timeout.)
        """
        if getattr(self, "_stop_event", None) is not None and self._stop_event.is_set():
            return []

        results: List[MinerData] = []
        start_time = time.time()

        miners = self.miners
        # For very large fleets: latest mode polls a rolling window only.
        if mode == "latest" and len(miners) > self.latest_max_miners:
            window = self.latest_max_miners
            start = self._latest_cursor % len(miners)
            end = start + window
            if end <= len(miners):
                miners = miners[start:end]
            else:
                miners = miners[start:] + miners[: (end % len(miners))]
            self._latest_cursor = (start + window) % len(self.miners)

        # Filter miners by offline backoff before enqueueing worker tasks. This avoids
        # burning threadpool slots on miners that are intentionally skipped and makes
        # logs/UI easier to interpret.
        now = time.time()
        due_miners: List[Dict] = []
        skipped_backoff = 0
        for m in miners:
            miner_id = m.get('id') or m.get('miner_id') or m.get('name')
            # If we cannot identify the miner deterministically, probe it.
            if not miner_id:
                due_miners.append(m)
                continue
            if self._is_miner_due(str(miner_id), now):
                due_miners.append(m)
            else:
                skipped_backoff += 1

        # Persist last-cycle counts for UI/status endpoints
        self._last_window_total = len(miners)
        self._last_due_total = len(due_miners)
        self._last_skipped_backoff = skipped_backoff

        miners = due_miners
        logger.info(
            f"Starting {mode} collection for {len(miners)} due miners "
            f"(skipped_backoff={skipped_backoff}, window_total={self._last_window_total}, "
            f"total_configured={len(self.miners)})..."
        )

        # If nothing is due, exit quickly.
        if not miners:
            return []

        executor: Optional[ThreadPoolExecutor] = None
        future_to_miner: Dict[Any, Dict] = {}
        try:
            executor = ThreadPoolExecutor(max_workers=self.max_workers)

            # Submit jobs (stop-aware)
            for m in miners:
                if getattr(self, "_stop_event", None) is not None and self._stop_event.is_set():
                    break
                future = executor.submit(self.collect_single_miner, m, mode=mode)
                future_to_miner[future] = m

            # Collect results (stop-aware)
            for future in as_completed(list(future_to_miner.keys())):
                if getattr(self, "_stop_event", None) is not None and self._stop_event.is_set():
                    break
                miner = future_to_miner.get(future, {})
                try:
                    data = future.result()
                    if data is None:
                        continue
                    results.append(data)
                    if data.online:
                        self.stats['successful'] += 1
                    else:
                        self.stats['failed'] += 1
                except Exception as e:
                    logger.error(f"Collection error for {mask_ip(miner.get('ip'))}: {e}")
                    self.stats['failed'] += 1
        finally:
            # Non-blocking shutdown to support fast stop.
            if executor is not None:
                try:
                    executor.shutdown(wait=False, cancel_futures=True)
                except TypeError:
                    executor.shutdown(wait=False)

        elapsed = time.time() - start_time
        self.stats['total_collected'] += len(results)
        self.stats['last_collection'] = datetime.utcnow().isoformat()

        online_count = sum(1 for r in results if r.online)
        logger.info(f"Collected {len(results)} miners ({online_count} online) in {elapsed:.2f}s [{mode}]")

        return results

    
    def upload_data(self, data: List[MinerData], *, mode: str = "raw") -> bool:
        """Upload telemetry to cloud; cache gzipped batches on failure (offline spool).

        Security invariant:
        - IP addresses and credentials are never uploaded and never written into cached batches,
          unless upload_include_ip=True (default False).
        """
        if not data:
            return True

        if getattr(self, '_stop_event', None) is not None and self._stop_event.is_set():
            return False

        all_ok = True
        ts = datetime.utcnow().strftime('%Y%m%d%H%M%S')

        for idx in range(0, len(data), self.batch_size):
            chunk = data[idx: idx + self.batch_size]

            compressed = self.uploader.build_payload(chunk)
            ok = self.uploader.upload_compressed(compressed, mode=mode)

            if not ok:
                all_ok = False
                batch_id = f"{mode}_{self.site_id}_{ts}_{idx // self.batch_size}"
                self.cache.save_batch(batch_id, compressed)

        return all_ok

    def retry_pending_uploads(self):
        """Retry cached telemetry batches.

        Notes:
        - Uses CloudUploader.upload_compressed(), which also applies payload scrubbing so older cached
          batches cannot leak IP addresses.
        - Caps the number of retries per tick to avoid blocking near-real-time loops.
        """
        pending = self.cache.get_pending_batches(max_retry=self.max_retries)
        if not pending:
            return

        if getattr(self, '_stop_event', None) is not None and self._stop_event.is_set():
            return

        total = len(pending)
        cap = max(0, int(getattr(self, 'max_retry_batches_per_tick', 1)))
        if cap and total > cap:
            pending = pending[:cap]

        logger.info(f"Retrying {len(pending)} cached batches (of {total})...")

        for batch_id, compressed_data in pending:
            if getattr(self, '_stop_event', None) is not None and self._stop_event.is_set():
                return
            try:
                # Parse mode from batch_id prefix (e.g. "latest_site_..." / "raw_site_...")
                mode = "raw"
                if isinstance(batch_id, str) and batch_id.startswith("latest_"):
                    mode = "latest"

                ok = self.uploader.upload_compressed(compressed_data, mode=mode)

                if ok:
                    self.cache.mark_uploaded(batch_id)
                    logger.info(f"Cached batch {batch_id} uploaded successfully")
                else:
                    self.cache.increment_retry(batch_id)
            except Exception as e:
                logger.error(f"Retry upload error for {batch_id}: {e}")
                self.cache.increment_retry(batch_id)
    def run_once(self, *, mode: str = "raw") -> Dict:
            """执行单次采集和上传"""
            t0 = time.time()
            if getattr(self, '_stop_event', None) is not None and self._stop_event.is_set():
                return {
                    'mode': mode,
                    'collected': 0,
                    'online': 0,
                    'offline': 0,
                    'upload_success': False,
                    'processing_time_ms': 0,
                    'timestamp': datetime.utcnow().isoformat(),
                    'stopped': True,
                }
            data = self.collect_all(mode=mode)
            if getattr(self, '_stop_event', None) is not None and self._stop_event.is_set():
                elapsed_ms = int((time.time() - t0) * 1000)
                return {
                    'mode': mode,
                    'collected': len(data),
                    'online': sum(1 for d in data if d.online),
                    'offline': sum(1 for d in data if not d.online),
                    'upload_success': False,
                    'processing_time_ms': elapsed_ms,
                    'timestamp': datetime.utcnow().isoformat(),
                    'stopped': True,
                }
            success = self.upload_data(data, mode=mode)

            # Avoid retrying cached uploads on every near-real-time tick
            now = time.time()
            if (getattr(self, '_stop_event', None) is None or (not self._stop_event.is_set())) and (now - self._last_retry_ts) >= self.retry_interval_sec:
                self.retry_pending_uploads()
                self._last_retry_ts = now

            # Expose helpful counters for diagnostics/UI.
            pending_cached = self.cache.count_pending_batches(max_retry=self.max_retries)
            configured = len(self.miners)
            window_total = getattr(self, '_last_window_total', configured)
            due = getattr(self, '_last_due_total', configured)
            skipped_backoff = getattr(self, '_last_skipped_backoff', 0)

            elapsed_ms = int((time.time() - t0) * 1000)
            
            return {
                'mode': mode,
                'configured': configured,
                'window_total': window_total,
                'due': due,
                'skipped_backoff': skipped_backoff,
                'collected': len(data),
                'online': sum(1 for d in data if d.online),
                'offline': sum(1 for d in data if not d.online),
                'upload_success': success,
                'pending_cached': pending_cached,
                'processing_time_ms': elapsed_ms,
                'timestamp': datetime.utcnow().isoformat()
            }
        
    def _command_poll_loop(self):
        """命令轮询线程"""
        logger.info(f"Command polling started. Interval: {self.command_poll_interval}s")
        
        while self.running:
            try:
                processed = self.command_executor.process_commands()
                if processed > 0:
                    logger.info(f"Processed {processed} commands")
            except Exception as e:
                logger.error(f"Command poll error: {e}")
            
            time.sleep(self.command_poll_interval)
    
    def run(self):
        """持续运行采集循环"""
        self.running = True
        logger.info(f"HashInsight Remote started. Site: {self.site_id}, Miners: {len(self.miners)}")
        logger.info(f"Collection interval: {self.collection_interval}s, Workers: {self.max_workers}")
        
        if self.enable_commands:
            command_thread = threading.Thread(target=self._command_poll_loop, daemon=True)
            command_thread.start()
            logger.info("Command execution enabled - polling for control commands")
        
        while self.running:
            try:
                result = self.run_once()
                logger.info(f"Collection cycle complete: {result}")
                
                time.sleep(self.collection_interval)
                
            except KeyboardInterrupt:
                logger.info("Collector stopped by user")
                self.running = False
            except Exception as e:
                logger.error(f"Collection cycle error: {e}")
                time.sleep(10)
    
    def request_stop(self):
        """Request a fast stop (used by UI Stop button)."""
        try:
            self._stop_event.set()
        except Exception:
            pass
        self.running = False
        # Best-effort: close sessions so future calls fail fast
        try:
            self.uploader.session.close()
        except Exception:
            pass
        try:
            self.command_executor.session.close()
        except Exception:
            pass

    def stop(self):
        """停止采集器"""
        self.request_stop()
    def get_command_stats(self) -> Dict:
        """获取命令执行统计"""
        return self.command_executor.stats


def generate_miner_list(ip_range: str, id_prefix: str = "miner") -> List[Dict]:
    """从IP范围生成矿机列表
    
    示例: generate_miner_list("192.168.1.100-192.168.1.200", "S19_")
    """
    miners = []
    
    parts = ip_range.split('-')
    if len(parts) != 2:
        return miners
    
    start_ip = parts[0].strip()
    end_ip = parts[1].strip()
    
    start_parts = list(map(int, start_ip.split('.')))
    end_parts = list(map(int, end_ip.split('.')))
    
    current = start_parts.copy()
    index = 1
    
    while current <= end_parts:
        ip = '.'.join(map(str, current))
        miners.append({
            'id': f"{id_prefix}{index:04d}",
            'ip': ip,
            'port': 4028,
            'type': 'antminer'
        })
        index += 1
        
        current[3] += 1
        for i in range(3, 0, -1):
            if current[i] > 255:
                current[i] = 0
                current[i-1] += 1
    
    return miners


def load_config(config_path: str) -> Dict:
    """加载配置文件"""
    if os.path.exists(config_path):
        with open(config_path, 'r') as f:
            return json.load(f)
    return {}


def create_sample_config(output_path: str = "collector_config.json"):
    """创建示例配置文件"""
    config = {
        "api_url": "https://your-replit-app.replit.app",
        "api_key": "your-collector-api-key",
        "site_id": "site_001",
        "collection_interval": 30,
        "max_workers": 50,
        "cache_dir": "./cache",
        "miners": [
            {"id": "S19_0001", "ip": "192.168.1.100", "port": 4028, "type": "antminer"},
            {"id": "S19_0002", "ip": "192.168.1.101", "port": 4028, "type": "antminer"},
            {"id": "M30_0001", "ip": "192.168.2.100", "port": 4028, "type": "whatsminer"}
        ],
        "ip_ranges": [
            {"range": "192.168.1.100-192.168.1.199", "prefix": "S19_", "type": "antminer"},
            {"range": "192.168.2.100-192.168.2.199", "prefix": "M30_", "type": "whatsminer"}
        ]
    }
    
    with open(output_path, 'w') as f:
        json.dump(config, f, indent=2)
    
    print(f"Sample config created: {output_path}")
    return config


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='HashInsight HashInsight Remote')
    parser.add_argument('-c', '--config', default='collector_config.json', help='Config file path')
    parser.add_argument('--init', action='store_true', help='Create sample config file')
    parser.add_argument('--test', help='Test connection to a single miner IP')
    parser.add_argument('--once', action='store_true', help='Run single collection cycle')
    
    args = parser.parse_args()
    
    if args.init:
        create_sample_config()
        exit(0)
    
    if args.test:
        print(f"Testing connection to {args.test}...")
        api = CGMinerAPI(args.test)
        summary = api.get_summary()
        if summary:
            print("Connection successful!")
            print(json.dumps(summary, indent=2))
        else:
            print("Connection failed!")
        exit(0)
    
    config = load_config(args.config)
    if not config:
        print(f"Config file not found: {args.config}")
        print("Run with --init to create a sample config")
        exit(1)
    
    if config.get('ip_ranges'):
        for ip_range in config['ip_ranges']:
            miners = generate_miner_list(
                ip_range['range'],
                ip_range.get('prefix', 'miner_')
            )
            for m in miners:
                m['type'] = ip_range.get('type', 'antminer')
            config.setdefault('miners', []).extend(miners)
    
    collector = EdgeCollector(config)
    
    if args.once:
        result = collector.run_once()
        print(json.dumps(result, indent=2))
    else:
        collector.run()