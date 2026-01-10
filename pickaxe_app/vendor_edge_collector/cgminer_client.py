"""
HashInsight HashInsight Remote - CGMiner TCP客户端
CGMiner TCP Client with Retry Mechanism

支持:
- 自动重试 (3次 + 指数退避)
- 连接超时处理
- 自定义异常
"""

import socket
import json
import time
import logging
import re
from typing import Dict, Optional, Any, Tuple

logger = logging.getLogger('CGMinerClient')


class CGMinerError(Exception):
    """CGMiner通信错误 / CGMiner Communication Error"""
    
    def __init__(self, message: str, host: str = "", port: int = 4028, 
                 error_type: str = "unknown"):
        self.message = message
        self.host = host
        self.port = port
        self.error_type = error_type  # timeout, connection, parse, command
        super().__init__(f"[{error_type}] {message} (host={host}:{port})")


class CGMinerClient:
    """
    CGMiner API TCP客户端
    带有自动重试机制和指数退避
    
    Usage:
        client = CGMinerClient("192.168.1.100")
        summary = client.get_summary()
        stats = client.get_stats()
    """
    
    DEFAULT_PORT = 4028
    DEFAULT_TIMEOUT = 5.0
    MAX_RETRIES = 3
    RETRY_BACKOFF_BASE = 0.5  # 500ms, 1s, 2s
    
    def __init__(self, host: str, port: int = DEFAULT_PORT, 
                 timeout: float = DEFAULT_TIMEOUT,
                 max_retries: int = MAX_RETRIES):
        """
        初始化客户端
        
        Args:
            host: 矿机IP地址
            port: CGMiner API端口 (默认4028)
            timeout: 连接超时秒数
            max_retries: 最大重试次数
        """
        self.host = host
        self.port = port
        self.timeout = timeout
        self.max_retries = max_retries
        self._last_latency_ms: float = 0.0
    
    @property
    def last_latency_ms(self) -> float:
        """上次请求的延迟(毫秒)"""
        return self._last_latency_ms
    
    def send_command(self, command: str, parameter: str = "") -> Dict[str, Any]:
        """
        发送CGMiner命令并获取响应
        带自动重试机制
        
        Args:
            command: 命令名 (summary, stats, pools, devs, version等)
            parameter: 可选参数
            
        Returns:
            解析后的JSON响应
            
        Raises:
            CGMinerError: 通信失败
        """
        last_error = None
        
        for attempt in range(self.max_retries):
            try:
                return self._send_once(command, parameter)
            except CGMinerError as e:
                last_error = e
                if attempt < self.max_retries - 1:
                    wait_time = self.RETRY_BACKOFF_BASE * (2 ** attempt)
                    logger.debug(f"Retry {attempt + 1}/{self.max_retries} "
                               f"after {wait_time}s: {e.message}")
                    time.sleep(wait_time)
        
        raise last_error or CGMinerError(
            "Unknown error", self.host, self.port, "unknown"
        )
    
    def _send_once(self, command: str, parameter: str = "") -> Dict[str, Any]:
        """单次发送命令（无重试）"""
        sock = None
        start_time = time.time()
        
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
            
            self._last_latency_ms = (time.time() - start_time) * 1000
            
            data = response.rstrip(b'\x00').decode('utf-8', errors='ignore')
            data = data.strip()
            
            if not data:
                raise CGMinerError(
                    "Empty response", self.host, self.port, "parse"
                )
            
            # Try parsing as-is first
            try:
                return json.loads(data)
            except json.JSONDecodeError:
                pass
            
            # Fix malformed JSON from some miner firmware
            # Handles concatenated objects: {"A":1}{"B":2} -> {"A":1},{"B":2}
            data = re.sub(r'}\s*{', '},{', data)
            data = re.sub(r']\s*\[', '],[', data)
            
            try:
                return json.loads(data)
            except json.JSONDecodeError:
                pass
            
            # Last resort: fix missing brackets
            if not data.startswith('{'):
                data = '{' + data
            if not data.endswith('}'):
                data = data + '}'
            
            try:
                return json.loads(data)
            except json.JSONDecodeError as e:
                raise CGMinerError(
                    f"Invalid JSON: {str(e)[:100]}", 
                    self.host, self.port, "parse"
                )
                
        except socket.timeout:
            raise CGMinerError(
                f"Connection timeout ({self.timeout}s)",
                self.host, self.port, "timeout"
            )
        except ConnectionRefusedError:
            raise CGMinerError(
                "Connection refused",
                self.host, self.port, "connection"
            )
        except OSError as e:
            raise CGMinerError(
                f"Network error: {str(e)}",
                self.host, self.port, "connection"
            )
        finally:
            if sock:
                try:
                    sock.close()
                except:
                    pass
    
    def get_summary(self) -> Dict[str, Any]:
        """获取矿机摘要信息 / Get miner summary"""
        return self.send_command("summary")
    
    def get_stats(self) -> Dict[str, Any]:
        """获取详细统计信息(温度、芯片状态等) / Get detailed stats"""
        return self.send_command("stats")
    
    def get_pools(self) -> Dict[str, Any]:
        """获取矿池信息 / Get pool info"""
        return self.send_command("pools")
    
    def get_devs(self) -> Dict[str, Any]:
        """获取设备信息 / Get device info"""
        return self.send_command("devs")
    
    def get_version(self) -> Dict[str, Any]:
        """获取版本信息 / Get version info"""
        return self.send_command("version")
    
    def get_all_data(self) -> Dict[str, Any]:
        """
        获取所有数据（合并调用）
        Returns combined data from summary, stats, pools
        """
        return {
            "summary": self.get_summary(),
            "stats": self.get_stats(),
            "pools": self.get_pools(),
            "latency_ms": self._last_latency_ms
        }
    
    def is_alive(self) -> bool:
        """
        快速检查矿机是否在线
        Quick connectivity check
        """
        try:
            result = self.send_command("version")
            return result is not None
        except CGMinerError:
            return False
    
    def execute_control(self, command: str, params: Optional[Dict] = None) -> Tuple[bool, str]:
        """
        执行控制命令
        
        Args:
            command: enable/disable/restart/set_pool/set_fan/set_frequency
            params: 命令参数
            
        Returns:
            (success, message)
        """
        params = params or {}
        
        try:
            if command == 'enable':
                result = self.send_command("ascunlock")
            elif command == 'disable':
                result = self.send_command("asclock")
            elif command == 'restart':
                result = self.send_command("restart")
            elif command == 'set_pool':
                if params.get('pool_url') and params.get('pool_user'):
                    param = f"{params['pool_url']},{params['pool_user']},{params.get('pool_password', 'x')}"
                    result = self.send_command("addpool", param)
                else:
                    result = self.send_command("switchpool", str(params.get('pool_id', 0)))
            elif command == 'set_fan':
                result = self.send_command("fanctrl", str(params.get('speed', 100)))
            elif command == 'set_frequency':
                result = self.send_command("setconfig", f"freq={params.get('freq', 500)}")
            else:
                return False, f"Unknown command: {command}"
            
            status = result.get('STATUS', [{}])[0].get('STATUS', '')
            if status in ('S', 'I'):
                return True, f"Command {command} executed successfully"
            else:
                return False, f"Command failed: {result}"
                
        except CGMinerError as e:
            return False, str(e)


def quick_probe(host: str, port: int = 4028, timeout: float = 2.0) -> Optional[Dict]:
    """
    快速探测矿机
    Returns basic info or None if offline
    """
    try:
        client = CGMinerClient(host, port, timeout, max_retries=1)
        return client.get_summary()
    except CGMinerError:
        return None
