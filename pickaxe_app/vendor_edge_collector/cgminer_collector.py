#!/usr/bin/env python3
"""
HashInsight Edge Collector - 矿场边缘数据采集器
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
from .ip_scanner import IPRangeParser, IPRangeError
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('EdgeCollector')


@dataclass
class MinerData:
    """矿机数据结构"""
    miner_id: str
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
            return json.loads(data) if data else None
            
        except socket.timeout:
            logger.debug(f"Timeout connecting to {self.host}:{self.port}")
            return None
        except ConnectionRefusedError:
            logger.debug(f"Connection refused: {self.host}:{self.port}")
            return None
        except Exception as e:
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
    def parse_antminer(summary: Dict, stats: Dict, pools: Dict, ip: str, miner_id: str) -> MinerData:
        """解析Antminer数据 (S19/S21/T19等)"""
        data = MinerData(
            miner_id=miner_id,
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
            logger.error(f"Error parsing Antminer data for {ip}: {e}")
            data.error_message = str(e)
        
        return data
    
    @staticmethod
    def parse_whatsminer(summary: Dict, stats: Dict, pools: Dict, ip: str, miner_id: str) -> MinerData:
        """解析Whatsminer数据 (M30/M50等)"""
        return MinerDataParser.parse_antminer(summary, stats, pools, ip, miner_id)
    
    @staticmethod
    def parse_avalon(summary: Dict, stats: Dict, pools: Dict, ip: str, miner_id: str) -> MinerData:
        """解析Avalon数据"""
        return MinerDataParser.parse_antminer(summary, stats, pools, ip, miner_id)


class OfflineCache:
    """离线缓存管理器 - 使用SQLite存储"""
    
    def __init__(self, cache_dir: str = "./cache"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.cache_dir / "offline_cache.db"
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
        conn.commit()
        conn.close()
    
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


class CloudUploader:
    """云端数据上传器"""
    
    def __init__(self, api_url: str, api_key: str, site_id: str, include_ip: bool = False, *, connect_timeout: float = 5.0, read_timeout: float = 30.0):
        self.api_url = api_url.rstrip('/')
        self.api_key = api_key
        self.site_id = site_id
        self.include_ip = include_ip
        self.session = requests.Session()
        self.session.headers.update({
            'X-Collector-Key': api_key,
            'X-Site-ID': site_id,
            'Content-Type': 'application/octet-stream',
            'Content-Encoding': 'gzip'
        })
        # Use a tuple timeout so connect vs read are controlled independently.
        self.timeout = (float(connect_timeout), float(read_timeout))
    
    def upload(self, data: List[MinerData], *, mode: str = "raw") -> bool:
        """上传矿机数据到云端"""
        try:
            rows = []
            for d in data:
                dd = asdict(d)
                # Security: do NOT upload internal miner IP to cloud (keep IP local in Pickaxe config)
                if not self.include_ip:
                    dd.pop("ip_address", None)
                rows.append(dd)
            json_data = json.dumps(rows)
            compressed = gzip.compress(json_data.encode('utf-8'))
            # Optional hint for the cloud side (it can ignore this header if not implemented).
            self.session.headers['X-Upload-Mode'] = mode
            
            response = self.session.post(
                f"{self.api_url}/api/collector/upload",
                data=compressed,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                result = response.json()
                if result.get('success'):
                    logger.info(f"Uploaded {len(data)} miner records successfully")
                    return True
                else:
                    logger.error(f"Upload failed: {result.get('error')}")
                    return False
            else:
                logger.error(f"Upload HTTP error: {response.status_code}")
                return False
                
        except requests.exceptions.ConnectionError:
            logger.warning("Network unavailable, data will be cached")
            return False
        except Exception as e:
            logger.error(f"Upload error: {e}")
            return False


class CommandExecutor:
    """命令执行器 - 从云端获取并执行控制命令"""
    
    def __init__(self, api_url: str, api_key: str, site_id: str, miner_map: Dict[str, Dict]):
        self.api_url = api_url.rstrip('/')
        self.api_key = api_key
        self.site_id = site_id
        self.miner_map = miner_map
        self.session = requests.Session()
        self.session.headers.update({
            'X-Collector-Key': api_key,
            'X-Site-ID': site_id,
            'Content-Type': 'application/json'
        })
        
        self.stats = {
            'commands_fetched': 0,
            'commands_executed': 0,
            'commands_failed': 0,
            'last_poll': None
        }
    
    def fetch_pending_commands(self) -> List[Dict]:
        """从云端获取待执行命令"""
        try:
            response = self.session.get(
                f"{self.api_url}/api/collector/commands/pending",
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                if result.get('success'):
                    commands = result.get('commands', [])
                    self.stats['commands_fetched'] += len(commands)
                    self.stats['last_poll'] = datetime.utcnow().isoformat()
                    if commands:
                        logger.info(f"Fetched {len(commands)} pending commands")
                    return commands
            else:
                logger.warning(f"Fetch commands failed: HTTP {response.status_code}")
            
            return []
            
        except requests.exceptions.ConnectionError:
            logger.debug("Cannot reach cloud server for commands")
            return []
        except Exception as e:
            logger.error(f"Fetch commands error: {e}")
            return []
    
    def report_result(self, command_id: int, success: bool, message: str):
        """报告命令执行结果"""
        try:
            response = self.session.post(
                f"{self.api_url}/api/collector/commands/{command_id}/result",
                json={
                    'status': 'completed' if success else 'failed',
                    'result_code': 0 if success else 1,
                    'result_message': message
                },
                timeout=10
            )
            
            if response.status_code == 200:
                logger.debug(f"Command {command_id} result reported: {success}")
            else:
                logger.warning(f"Report result failed: HTTP {response.status_code}")
                
        except Exception as e:
            logger.error(f"Report result error: {e}")
    
    def execute_command(self, cmd: Dict) -> Tuple[bool, str]:
        """执行单个命令"""
        command_id = cmd.get('command_id')
        miner_id = cmd.get('miner_id')
        ip_address = cmd.get('ip_address')
        command_type = cmd.get('command')
        params = cmd.get('params', {})
        
        if not ip_address and miner_id in self.miner_map:
            ip_address = self.miner_map[miner_id].get('ip')
        
        if not ip_address:
            return False, f"Cannot find IP for miner {miner_id}"
        
        logger.info(f"Executing command {command_id}: {command_type} on {miner_id} ({ip_address})")
        
        port = self.miner_map.get(miner_id, {}).get('port', 4028)
        api = CGMinerAPI(ip_address, port)
        
        success, message = api.execute_control_command(command_type, params)
        
        if success:
            self.stats['commands_executed'] += 1
            logger.info(f"Command {command_id} succeeded: {message}")
        else:
            self.stats['commands_failed'] += 1
            logger.error(f"Command {command_id} failed: {message}")
        
        return success, message
    
    def process_commands(self) -> int:
        """处理所有待执行命令"""
        commands = self.fetch_pending_commands()
        
        if not commands:
            return 0
        
        for cmd in commands:
            command_id = cmd.get('command_id')
            try:
                success, message = self.execute_command(cmd)
                self.report_result(command_id, success, message)
            except Exception as e:
                logger.error(f"Command {command_id} execution error: {e}")
                self.report_result(command_id, False, str(e))
        
        return len(commands)


class EdgeCollector:
    """边缘采集器主类"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.miners = config.get('miners', [])

        # Optional: expand ip_ranges into miners automatically.
        # This enables large-fleet deployments without materializing 10k miners in the UI.
        # Supported formats: CIDR (e.g. 192.168.10.0/24) and range (e.g. 192.168.10.10-192.168.10.250).
        # Config example:
        #   ip_ranges: [{"range":"192.168.1.0/24", "prefix":"S21_", "type":"antminer", "port":4028}]
        ip_ranges = config.get('ip_ranges') or []
        if isinstance(ip_ranges, list) and ip_ranges:
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

        # Miner connection behavior (plumbed from Pickaxe UI)
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
        
        self.cache = OfflineCache(config.get('cache_dir', './cache'))

        self.uploader = CloudUploader(
            self.api_url,
            self.api_key,
            self.site_id,
            include_ip=bool(config.get("upload_include_ip", False)),
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
        
        self.miner_map = {m.get('id', m.get('ip')): m for m in self.miners}
        self.command_executor = CommandExecutor(
            self.api_url, self.api_key, self.site_id, self.miner_map
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
    
    def _is_miner_due(self, miner_id: str) -> bool:
        st = self._miner_health.get(miner_id)
        if not st:
            return True
        return time.time() >= float(st.get('next_allowed', 0.0))

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
        miner_type = miner_config.get('type', 'antminer').lower()
        port = miner_config.get('port', 4028)

        # Fast stop: do not start new miner probes once stop is requested
        if getattr(self, '_stop_event', None) is not None and self._stop_event.is_set():
            return None

        # Skip miners that are still in offline backoff
        if not self._is_miner_due(miner_id):
            return None

        timeout = self.miner_timeout_slow if mode == "raw" else self.miner_timeout_fast
        
        api = CGMinerAPI(ip, port, timeout=timeout)

        # First attempt: if it's offline, default behavior is to skip retries and move on.
        attempts = 1
        summary = api.get_summary()
        if (not summary) and self.retry_on_first_offline and self.miner_max_retries > 1:
            # Optional retry loop to handle transient timeouts during boot/network jitter.
            for attempt in range(1, max(1, self.miner_max_retries)):
                time.sleep(0.15)
                attempts += 1
                summary = api.get_summary()
                if summary:
                    break

        if not summary:
            self._mark_miner_failure(miner_id)
            return MinerData(
                miner_id=miner_id,
                ip_address=ip,
                timestamp=datetime.utcnow().isoformat(),
                online=False,
                error_message=(
                    f"Connection failed (timeout={timeout}s, attempts={attempts}, "
                    f"retry_on_first_offline={self.retry_on_first_offline})"
                )
            )

        self._mark_miner_success(miner_id)

        # Lightweight vs heavy collection
        stats = api.get_stats() if mode in ("latest", "raw") else {}
        pools = api.get_pools() if mode == "raw" else []
        
        if miner_type == 'whatsminer':
            return MinerDataParser.parse_whatsminer(summary, stats, pools, ip, miner_id)
        elif miner_type == 'avalon':
            return MinerDataParser.parse_avalon(summary, stats, pools, ip, miner_id)
        else:
            return MinerDataParser.parse_antminer(summary, stats, pools, ip, miner_id)
    
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
                    logger.error(f"Collection error for {miner.get('ip')}: {e}")
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
        """上传数据到云端，失败时缓存"""
        if not data:
            return True

        if getattr(self, '_stop_event', None) is not None and self._stop_event.is_set():
            return False

        # Chunk uploads to keep server processing bounded.
        all_ok = True
        ts = datetime.utcnow().strftime('%Y%m%d%H%M%S')
        for idx in range(0, len(data), self.batch_size):
            chunk = data[idx : idx + self.batch_size]
            ok = self.uploader.upload(chunk, mode=mode)
            if not ok:
                all_ok = False
                batch_id = f"{mode}_{self.site_id}_{ts}_{idx//self.batch_size}"
                json_data = json.dumps([asdict(d) for d in chunk])
                compressed = gzip.compress(json_data.encode('utf-8'))
                self.cache.save_batch(batch_id, compressed)
        return all_ok
    
    def retry_pending_uploads(self):
        """重试待上传的缓存数据"""
        pending = self.cache.get_pending_batches(max_retry=self.max_retries)
        if not pending:
            return

        if getattr(self, '_stop_event', None) is not None and self._stop_event.is_set():
            return
        
        total = len(pending)
        # Cap how many cached batches we retry per tick to avoid blocking collection loops
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
                response = self.uploader.session.post(
                    f"{self.uploader.api_url}/api/collector/upload",
                    data=compressed_data,
                    timeout=self.uploader.timeout,
                    headers={"X-Upload-Mode": mode},
                )
                
                if response.status_code == 200 and response.json().get('success'):
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
        logger.info(f"Edge Collector started. Site: {self.site_id}, Miners: {len(self.miners)}")
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
    
    parser = argparse.ArgumentParser(description='HashInsight Edge Collector')
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
