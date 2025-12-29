"""
HashInsight Edge Collector - 数据模型
Data Models for Mining Farm Telemetry

Board-level health tracking with dynamic chip detection
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from enum import Enum
from datetime import datetime


class HealthStatus(Enum):
    """板卡健康状态 / Board Health Status"""
    HEALTHY = "healthy"      # chips_ok == chips_total
    WARNING = "warning"      # chips_ok >= 95% of chips_total
    CRITICAL = "critical"    # chips_ok < 95% OR temp > 90°C
    OFFLINE = "offline"      # 无法获取数据


@dataclass
class BoardStatus:
    """
    单个哈希板状态
    Single Hash Board Status
    
    Attributes:
        board_index: 板卡索引 (0, 1, 2, ...)
        hashrate_ths: 板卡算力 (TH/s)
        temperature_c: 板卡温度 (°C) 
        chips_total: 总芯片数
        chips_ok: 正常芯片数
        chips_failed: 故障芯片数
        chip_status: 芯片状态字符串 (x = OK, - = failed)
        frequency_mhz: 频率 (MHz)
        voltage_mv: 电压 (mV)
        health: 健康状态
    """
    board_index: int
    hashrate_ths: float = 0.0
    temperature_c: float = 0.0
    chips_total: int = 0
    chips_ok: int = 0
    chips_failed: int = 0
    chip_status: str = ""
    frequency_mhz: float = 0.0
    voltage_mv: float = 0.0
    health: HealthStatus = HealthStatus.OFFLINE
    
    def __post_init__(self):
        """自动计算 chips_failed 并确定健康状态"""
        if self.chips_total > 0:
            self.chips_failed = self.chips_total - self.chips_ok
            self.health = self._determine_health()
    
    def _determine_health(self) -> HealthStatus:
        """
        根据芯片状态和温度判定健康度
        Health determination rules:
        - temp > 90°C → CRITICAL
        - chips_ok == chips_total → HEALTHY  
        - chips_ok >= 95% → WARNING
        - chips_ok < 95% → CRITICAL
        """
        if self.temperature_c > 90.0:
            return HealthStatus.CRITICAL
        
        if self.chips_total == 0:
            return HealthStatus.OFFLINE
        
        ratio = self.chips_ok / self.chips_total
        
        if ratio >= 1.0:
            return HealthStatus.HEALTHY
        elif ratio >= 0.95:
            return HealthStatus.WARNING
        else:
            return HealthStatus.CRITICAL
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            "board_index": self.board_index,
            "hashrate_ths": round(self.hashrate_ths, 2),
            "temperature_c": round(self.temperature_c, 1),
            "chips_total": self.chips_total,
            "chips_ok": self.chips_ok,
            "chips_failed": self.chips_failed,
            "chip_status": self.chip_status,
            "frequency_mhz": round(self.frequency_mhz, 1),
            "voltage_mv": round(self.voltage_mv, 1),
            "health": self.health.value
        }


@dataclass  
class MinerSnapshot:
    """
    矿机完整快照 - 包含所有板卡数据
    Complete Miner Snapshot with All Boards
    
    Supports arbitrary number of boards (typically 3-4)
    """
    miner_id: str
    ip_address: str
    timestamp: datetime
    online: bool = True
    
    # 总体指标
    hashrate_total_ths: float = 0.0
    hashrate_5s_ths: float = 0.0
    hashrate_expected_ths: float = 0.0
    power_watts: float = 0.0
    efficiency_jths: float = 0.0
    
    # 温度汇总
    temp_min_c: float = 0.0
    temp_max_c: float = 0.0
    temp_avg_c: float = 0.0
    
    # 风扇
    fan_speeds_rpm: List[int] = field(default_factory=list)
    fan_count: int = 0
    
    # 板卡数据 - 动态数量
    boards: List[BoardStatus] = field(default_factory=list)
    boards_total: int = 0
    boards_healthy: int = 0
    
    # 矿池信息
    pool_url: str = ""
    pool_user: str = ""
    pool_latency_ms: float = 0.0
    shares_accepted: int = 0
    shares_rejected: int = 0
    shares_rejected_rate: float = 0.0
    
    # 运行时间
    uptime_seconds: int = 0
    hardware_errors: int = 0
    
    # 固件/型号
    model: str = ""
    firmware: str = ""
    
    # 错误信息
    error_message: str = ""
    
    def __post_init__(self):
        """自动计算汇总数据"""
        self._calculate_summaries()
    
    def _calculate_summaries(self):
        """根据板卡数据计算汇总指标"""
        if self.boards:
            self.boards_total = len(self.boards)
            self.boards_healthy = sum(
                1 for b in self.boards 
                if b.health in (HealthStatus.HEALTHY, HealthStatus.WARNING)
            )
            
            # 温度统计
            temps = [b.temperature_c for b in self.boards if b.temperature_c > 0]
            if temps:
                self.temp_min_c = min(temps)
                self.temp_max_c = max(temps)
                self.temp_avg_c = sum(temps) / len(temps)
            
            # 总算力 (如果未提供)
            if self.hashrate_total_ths == 0:
                self.hashrate_total_ths = sum(b.hashrate_ths for b in self.boards)
        
        # 风扇数量
        self.fan_count = len(self.fan_speeds_rpm)
        
        # Rejected rate
        total_shares = self.shares_accepted + self.shares_rejected
        if total_shares > 0:
            self.shares_rejected_rate = (self.shares_rejected / total_shares) * 100
    
    def add_board(self, board: BoardStatus):
        """添加板卡并重新计算汇总"""
        self.boards.append(board)
        self._calculate_summaries()
    
    def get_overall_health(self) -> HealthStatus:
        """
        获取整体健康状态
        Overall health is the worst status across all boards
        """
        if not self.online:
            return HealthStatus.OFFLINE
        
        if not self.boards:
            return HealthStatus.OFFLINE
        
        # 找出最差状态
        has_critical = any(b.health == HealthStatus.CRITICAL for b in self.boards)
        has_warning = any(b.health == HealthStatus.WARNING for b in self.boards)
        
        if has_critical:
            return HealthStatus.CRITICAL
        elif has_warning:
            return HealthStatus.WARNING
        else:
            return HealthStatus.HEALTHY
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为可JSON序列化的字典"""
        return {
            "miner_id": self.miner_id,
            "ip_address": self.ip_address,
            "timestamp": self.timestamp.isoformat() if isinstance(self.timestamp, datetime) else str(self.timestamp),
            "online": self.online,
            
            # 算力
            "hashrate_total_ths": round(self.hashrate_total_ths, 2),
            "hashrate_5s_ths": round(self.hashrate_5s_ths, 2),
            "hashrate_expected_ths": round(self.hashrate_expected_ths, 2),
            
            # 功率效率
            "power_watts": round(self.power_watts, 1),
            "efficiency_jths": round(self.efficiency_jths, 2),
            
            # 温度
            "temp_min_c": round(self.temp_min_c, 1),
            "temp_max_c": round(self.temp_max_c, 1),
            "temp_avg_c": round(self.temp_avg_c, 1),
            
            # 风扇
            "fan_speeds_rpm": self.fan_speeds_rpm,
            "fan_count": self.fan_count,
            
            # 板卡
            "boards": [b.to_dict() for b in self.boards],
            "boards_total": self.boards_total,
            "boards_healthy": self.boards_healthy,
            "overall_health": self.get_overall_health().value,
            
            # 矿池
            "pool_url": self.pool_url,
            "pool_user": self.pool_user,
            "pool_latency_ms": round(self.pool_latency_ms, 1),
            "shares_accepted": self.shares_accepted,
            "shares_rejected": self.shares_rejected,
            "shares_rejected_rate": round(self.shares_rejected_rate, 2),
            
            # 运行时间
            "uptime_seconds": self.uptime_seconds,
            "hardware_errors": self.hardware_errors,
            
            # 设备信息
            "model": self.model,
            "firmware": self.firmware,
            "error_message": self.error_message
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'MinerSnapshot':
        """从字典创建实例"""
        boards = []
        for b_data in data.get('boards', []):
            board = BoardStatus(
                board_index=b_data.get('board_index', 0),
                hashrate_ths=b_data.get('hashrate_ths', 0),
                temperature_c=b_data.get('temperature_c', 0),
                chips_total=b_data.get('chips_total', 0),
                chips_ok=b_data.get('chips_ok', 0),
                chip_status=b_data.get('chip_status', ''),
                frequency_mhz=b_data.get('frequency_mhz', 0),
                voltage_mv=b_data.get('voltage_mv', 0)
            )
            boards.append(board)
        
        ts = data.get('timestamp')
        if isinstance(ts, str):
            try:
                ts = datetime.fromisoformat(ts.replace('Z', '+00:00'))
            except:
                ts = datetime.now()
        elif not isinstance(ts, datetime):
            ts = datetime.now()
        
        return cls(
            miner_id=data.get('miner_id', ''),
            ip_address=data.get('ip_address', ''),
            timestamp=ts,
            online=data.get('online', True),
            hashrate_total_ths=data.get('hashrate_total_ths', 0),
            hashrate_5s_ths=data.get('hashrate_5s_ths', 0),
            hashrate_expected_ths=data.get('hashrate_expected_ths', 0),
            power_watts=data.get('power_watts', 0),
            efficiency_jths=data.get('efficiency_jths', 0),
            fan_speeds_rpm=data.get('fan_speeds_rpm', []),
            boards=boards,
            pool_url=data.get('pool_url', ''),
            pool_user=data.get('pool_user', ''),
            pool_latency_ms=data.get('pool_latency_ms', 0),
            shares_accepted=data.get('shares_accepted', 0),
            shares_rejected=data.get('shares_rejected', 0),
            uptime_seconds=data.get('uptime_seconds', 0),
            hardware_errors=data.get('hardware_errors', 0),
            model=data.get('model', ''),
            firmware=data.get('firmware', ''),
            error_message=data.get('error_message', '')
        )
