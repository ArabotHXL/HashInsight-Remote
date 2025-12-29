"""
HashInsight Edge Collector - CGMiner数据解析器
CGMiner Data Parsers for Board-Level Health

支持多种矿机型号:
- Antminer S19/S19 Pro/S19 XP/S21
- Whatsminer M30/M50/M60
- Avalon A12/A14
- Canaan AvalonMiner

解析 CGMiner stats 响应中的板级数据:
- chain_acn{N}: 检测到的芯片数
- chain_acs{N}: 芯片状态字符串 (x=正常, -=故障, o=离线)
- temp_chip{N}: 芯片温度
- chain_rate{N}: 板卡算力
- freq_avg{N}: 平均频率
"""

import re
import logging
from typing import Dict, List, Optional, Any, Tuple
from .models import BoardStatus, MinerSnapshot, HealthStatus
from datetime import datetime

logger = logging.getLogger('BoardParser')


def extract_board_indices(stats_data: Dict[str, Any]) -> List[int]:
    """
    从stats响应中提取所有板卡索引
    Dynamically detect board indices from stats response
    
    CGMiner返回的键名格式:
    - chain_acn0, chain_acn1, chain_acn2 (Antminer)
    - Chain ID, Chain0 Rate, Chain1 Rate (Whatsminer)
    - CHAIN0, CHAIN1, CHAIN2 (Avalon)
    
    Returns:
        排序后的板卡索引列表, e.g. [0, 1, 2]
    """
    indices = set()
    
    if not stats_data:
        return []
    
    stats_list = stats_data.get('STATS', [])
    
    for stat in stats_list:
        if not isinstance(stat, dict):
            continue
        
        for key in stat.keys():
            match = re.match(r'chain_acn(\d+)', key, re.IGNORECASE)
            if match:
                indices.add(int(match.group(1)))
                continue
            
            match = re.match(r'chain(\d+)\s*rate', key, re.IGNORECASE)
            if match:
                indices.add(int(match.group(1)))
                continue
            
            match = re.match(r'CHAIN(\d+)', key)
            if match:
                indices.add(int(match.group(1)))
                continue
            
            match = re.match(r'temp_chip(\d+)', key, re.IGNORECASE)
            if match:
                indices.add(int(match.group(1)))
    
    return sorted(indices)


def determine_board_status(chips_ok: int, chips_total: int, 
                          temperature: float) -> HealthStatus:
    """
    根据芯片和温度判定健康状态
    
    Rules:
    - temp > 90°C → CRITICAL (过热保护)
    - chips_ok == chips_total → HEALTHY
    - chips_ok >= 95% → WARNING  
    - chips_ok < 95% → CRITICAL
    - chips_total == 0 → OFFLINE
    """
    if chips_total == 0:
        return HealthStatus.OFFLINE
    
    if temperature > 90.0:
        return HealthStatus.CRITICAL
    
    ratio = chips_ok / chips_total
    
    if ratio >= 1.0:
        return HealthStatus.HEALTHY
    elif ratio >= 0.95:
        return HealthStatus.WARNING
    else:
        return HealthStatus.CRITICAL


def _parse_chip_status_string(status_str: str) -> Tuple[int, int]:
    """
    解析芯片状态字符串
    
    Antminer格式: "xxxxxxxxxxxxxx--xxxxx" 
    - x = 正常芯片
    - - = 故障芯片
    - o = 离线芯片
    - 空格 = 无芯片
    
    Returns:
        (chips_ok, chips_total)
    """
    if not status_str:
        return 0, 0
    
    status_str = status_str.strip().replace(' ', '')
    
    chips_ok = status_str.lower().count('x') + status_str.lower().count('o')
    chips_failed = status_str.count('-')
    chips_total = chips_ok + chips_failed
    
    chips_ok = status_str.lower().count('x')
    
    return chips_ok, chips_total


def _get_stat_value(stat: Dict, key_patterns: List[str], 
                   default: Any = 0) -> Any:
    """
    从stats字典获取值，支持多种键名格式
    
    Args:
        stat: 单个STATS字典
        key_patterns: 可能的键名列表
        default: 默认值
    """
    for pattern in key_patterns:
        for key in stat.keys():
            if key.lower() == pattern.lower():
                return stat[key]
            if re.match(pattern, key, re.IGNORECASE):
                return stat[key]
    return default


def parse_single_board(stat: Dict, board_index: int) -> BoardStatus:
    """
    解析单个板卡数据
    
    Args:
        stat: CGMiner STATS字典
        board_index: 板卡索引
        
    Returns:
        BoardStatus 实例
    """
    idx = board_index
    
    hashrate_patterns = [
        f'chain_rate{idx}',
        f'chain_rateideal{idx}',
        f'chain{idx} rate',
        f'Chain{idx}Rate',
        f'rate_{idx}'
    ]
    hashrate_ghs = _get_stat_value(stat, hashrate_patterns, 0)
    
    if isinstance(hashrate_ghs, str):
        try:
            hashrate_ghs = float(hashrate_ghs.replace(',', ''))
        except:
            hashrate_ghs = 0
    
    hashrate_ths = float(hashrate_ghs) / 1000.0 if hashrate_ghs else 0
    
    temp_patterns = [
        f'temp_chip{idx}',
        f'temp{idx}',
        f'chain_temp{idx}',
        f'temp_pcb{idx}',
        f'Temperature{idx}'
    ]
    temperature = _get_stat_value(stat, temp_patterns, 0)
    
    if isinstance(temperature, str):
        match = re.search(r'[\d.]+', temperature)
        temperature = float(match.group()) if match else 0
    temperature = float(temperature) if temperature else 0
    
    acn_patterns = [
        f'chain_acn{idx}',
        f'chain_num{idx}',
        f'chips{idx}'
    ]
    chips_detected = int(_get_stat_value(stat, acn_patterns, 0))
    
    acs_patterns = [
        f'chain_acs{idx}',
        f'chain_status{idx}',
        f'chipstatus{idx}'
    ]
    chip_status_str = str(_get_stat_value(stat, acs_patterns, ''))
    
    if chip_status_str:
        chips_ok, chips_total = _parse_chip_status_string(chip_status_str)
        if chips_total == 0:
            chips_total = chips_detected
            chips_ok = chips_detected
    else:
        chips_total = chips_detected
        chips_ok = chips_detected
    
    freq_patterns = [
        f'freq_avg{idx}',
        f'chain_freq{idx}',
        f'frequency{idx}'
    ]
    frequency = float(_get_stat_value(stat, freq_patterns, 0))
    
    volt_patterns = [
        f'chain_voltage{idx}',
        f'voltage{idx}',
        f'chain_vol{idx}'
    ]
    voltage = float(_get_stat_value(stat, volt_patterns, 0))
    
    health = determine_board_status(chips_ok, chips_total, temperature)
    
    return BoardStatus(
        board_index=board_index,
        hashrate_ths=hashrate_ths,
        temperature_c=temperature,
        chips_total=chips_total,
        chips_ok=chips_ok,
        chips_failed=chips_total - chips_ok,
        chip_status=chip_status_str,
        frequency_mhz=frequency,
        voltage_mv=voltage,
        health=health
    )


def parse_board_health(stats_data: Dict[str, Any]) -> List[BoardStatus]:
    """
    从CGMiner stats响应解析所有板卡健康数据
    
    Main parsing function - call this to get all board statuses
    
    Args:
        stats_data: CGMiner get_stats() 响应
        
    Returns:
        BoardStatus 列表
    """
    boards = []
    
    if not stats_data:
        return boards
    
    indices = extract_board_indices(stats_data)
    
    if not indices:
        logger.debug("No board indices detected in stats response")
        return boards
    
    stats_list = stats_data.get('STATS', [])
    
    miner_stat = None
    for stat in stats_list:
        if isinstance(stat, dict):
            if any(k.startswith('chain_acn') or k.startswith('temp_chip') 
                   for k in stat.keys()):
                miner_stat = stat
                break
    
    if not miner_stat:
        for stat in stats_list:
            if isinstance(stat, dict) and len(stat) > 10:
                miner_stat = stat
                break
    
    if not miner_stat:
        logger.warning("No valid miner stats found in response")
        return boards
    
    for idx in indices:
        try:
            board = parse_single_board(miner_stat, idx)
            boards.append(board)
        except Exception as e:
            logger.error(f"Error parsing board {idx}: {e}")
    
    return boards


def parse_pool_info(pools_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    解析矿池信息
    
    Returns:
        {
            'url': 'stratum+tcp://pool.example.com:3333',
            'user': 'user.worker',
            'status': 'Alive',
            'latency_ms': 45.0,
            'accepted': 12456,
            'rejected': 23,
            'rejected_rate': 0.18,
            'difficulty': 65536.0,
            'stratum_active': True
        }
    """
    result = {
        'url': '',
        'user': '',
        'status': 'Unknown',
        'latency_ms': 0.0,
        'accepted': 0,
        'rejected': 0,
        'rejected_rate': 0.0,
        'difficulty': 0.0,
        'stratum_active': False
    }
    
    if not pools_data:
        return result
    
    pools = pools_data.get('POOLS', [])
    
    active_pool = None
    for pool in pools:
        if pool.get('Status', '') == 'Alive':
            active_pool = pool
            break
    
    if not active_pool and pools:
        active_pool = pools[0]
    
    if not active_pool:
        return result
    
    result['url'] = active_pool.get('URL', active_pool.get('Stratum URL', ''))
    result['user'] = active_pool.get('User', '')
    result['status'] = active_pool.get('Status', 'Unknown')
    result['accepted'] = int(active_pool.get('Accepted', 0))
    result['rejected'] = int(active_pool.get('Rejected', 0))
    result['difficulty'] = float(active_pool.get('Diff', active_pool.get('Last Share Difficulty', 0)))
    result['stratum_active'] = active_pool.get('Stratum Active', False)
    
    last_share_time = active_pool.get('Last Share Time', 0)
    if last_share_time:
        result['latency_ms'] = float(last_share_time)
    
    total = result['accepted'] + result['rejected']
    if total > 0:
        result['rejected_rate'] = (result['rejected'] / total) * 100
    
    return result


def parse_summary_info(summary_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    解析摘要信息
    
    Returns:
        {
            'hashrate_ghs': 195000.0,
            'hashrate_5s_ghs': 194800.0,
            'accepted': 12456,
            'rejected': 23,
            'hardware_errors': 0,
            'uptime': 3600,
            'difficulty_accepted': 123456789.0
        }
    """
    result = {
        'hashrate_ghs': 0.0,
        'hashrate_5s_ghs': 0.0,
        'accepted': 0,
        'rejected': 0,
        'hardware_errors': 0,
        'uptime': 0,
        'difficulty_accepted': 0.0
    }
    
    if not summary_data:
        return result
    
    summary_list = summary_data.get('SUMMARY', [])
    if not summary_list:
        return result
    
    summary = summary_list[0] if summary_list else {}
    
    result['hashrate_ghs'] = float(summary.get('GHS av', summary.get('MHS av', 0) / 1000))
    result['hashrate_5s_ghs'] = float(summary.get('GHS 5s', summary.get('MHS 5s', 0) / 1000))
    result['accepted'] = int(summary.get('Accepted', 0))
    result['rejected'] = int(summary.get('Rejected', 0))
    result['hardware_errors'] = int(summary.get('Hardware Errors', 0))
    result['uptime'] = int(summary.get('Elapsed', 0))
    result['difficulty_accepted'] = float(summary.get('Difficulty Accepted', 0))
    
    return result


def create_miner_snapshot(miner_id: str, ip_address: str,
                         summary_data: Dict, stats_data: Dict, 
                         pools_data: Dict,
                         expected_hashrate_ths: float = 0) -> MinerSnapshot:
    """
    创建完整的矿机快照
    
    Combines summary, stats, and pools data into a single MinerSnapshot
    
    Args:
        miner_id: 矿机ID
        ip_address: IP地址
        summary_data: CGMiner summary响应
        stats_data: CGMiner stats响应
        pools_data: CGMiner pools响应
        expected_hashrate_ths: 预期算力 (TH/s)
        
    Returns:
        MinerSnapshot 实例
    """
    boards = parse_board_health(stats_data)
    pool_info = parse_pool_info(pools_data)
    summary_info = parse_summary_info(summary_data)
    
    fan_speeds = []
    stats_list = stats_data.get('STATS', []) if stats_data else []
    for stat in stats_list:
        if isinstance(stat, dict):
            for i in range(10):
                fan_key = f'fan{i + 1}'
                if fan_key in stat:
                    try:
                        fan_speeds.append(int(stat[fan_key]))
                    except:
                        pass
            if fan_speeds:
                break
    
    model = ""
    firmware = ""
    for stat in stats_list:
        if isinstance(stat, dict):
            model = stat.get('Type', stat.get('Model', ''))
            firmware = stat.get('Firmware', stat.get('CompileTime', ''))
            if model:
                break
    
    hashrate_total_ths = summary_info['hashrate_ghs'] / 1000.0
    hashrate_5s_ths = summary_info['hashrate_5s_ghs'] / 1000.0
    
    snapshot = MinerSnapshot(
        miner_id=miner_id,
        ip_address=ip_address,
        timestamp=datetime.now(),
        online=True,
        hashrate_total_ths=hashrate_total_ths,
        hashrate_5s_ths=hashrate_5s_ths,
        hashrate_expected_ths=expected_hashrate_ths,
        fan_speeds_rpm=fan_speeds,
        boards=boards,
        pool_url=pool_info['url'],
        pool_user=pool_info['user'],
        pool_latency_ms=pool_info['latency_ms'],
        shares_accepted=pool_info['accepted'],
        shares_rejected=pool_info['rejected'],
        uptime_seconds=summary_info['uptime'],
        hardware_errors=summary_info['hardware_errors'],
        model=model,
        firmware=firmware
    )
    
    return snapshot
