"""
IP Scanner Module for Miner Discovery
Provides IP range parsing and async miner detection functionality.

Features:
- Parse CIDR notation (e.g., "192.168.1.0/24")
- Parse range notation (e.g., "192.168.1.1-192.168.1.254")
- Enumerate all IPs in a range
- Validate IP addresses
- Async concurrent probing with configurable concurrency

Usage:
    from edge_collector.ip_scanner import IPRangeParser, MinerScanner
    
    # Parse IP range
    parser = IPRangeParser()
    ips = parser.parse("192.168.1.0/24")
    
    # Scan for miners
    scanner = MinerScanner(max_concurrent=50)
    results = await scanner.scan_range(ips, progress_callback=my_callback)
"""

import asyncio
import ipaddress
import logging
import re
import socket
import json
from typing import List, Optional, Dict, Any, Callable, Tuple, Iterator
from dataclasses import dataclass
from datetime import datetime

logger = logging.getLogger(__name__)

DEFAULT_CGMINER_PORT = 4028
DEFAULT_HTTP_PORT = 80
DEFAULT_TIMEOUT = 3.0
MAX_CONCURRENT = 50


class IPRangeError(Exception):
    """Exception for IP range parsing errors"""
    pass


@dataclass
class MinerProbeResult:
    """Result of probing a single IP for miners"""
    ip_address: str
    is_miner: bool
    api_port: int = 0
    detected_model: Optional[str] = None
    detected_firmware: Optional[str] = None
    detected_hashrate_ghs: Optional[float] = None
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    raw_response: Optional[Dict] = None
    probe_time_ms: float = 0
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            'ip_address': self.ip_address,
            'is_miner': self.is_miner,
            'api_port': self.api_port,
            'detected_model': self.detected_model,
            'detected_firmware': self.detected_firmware,
            'detected_hashrate_ghs': self.detected_hashrate_ghs,
            'mac_address': self.mac_address,
            'hostname': self.hostname,
            'raw_response': self.raw_response,
            'probe_time_ms': self.probe_time_ms,
            'error': self.error,
        }


class IPRangeParser:
    """
    Parse and validate IP address ranges
    
    Supports:
    - CIDR notation: 192.168.1.0/24
    - Range notation: 192.168.1.1-192.168.1.254
    - Single IP: 192.168.1.1
    - Comma-separated: 192.168.1.1,192.168.1.2,192.168.1.3
    """
    
    @staticmethod
    def validate_ip(ip: str) -> bool:
        """Validate a single IP address"""
        try:
            ipaddress.ip_address(ip.strip())
            return True
        except ValueError:
            return False
    
    @staticmethod
    def validate_cidr(cidr: str) -> bool:
        """Validate CIDR notation"""
        try:
            ipaddress.ip_network(cidr.strip(), strict=False)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def ip_to_int(ip: str) -> int:
        """Convert IP address to integer for comparison"""
        return int(ipaddress.ip_address(ip.strip()))
    
    @staticmethod
    def int_to_ip(num: int) -> str:
        """Convert integer back to IP address string"""
        return str(ipaddress.ip_address(num))
    
    def parse_cidr(self, cidr: str) -> Tuple[str, str, int]:
        """
        Parse CIDR notation and return start IP, end IP, and count
        
        Args:
            cidr: CIDR notation string (e.g., "192.168.1.0/24")
            
        Returns:
            Tuple of (start_ip, end_ip, total_ips)
        """
        try:
            network = ipaddress.ip_network(cidr.strip(), strict=False)
            hosts = list(network.hosts())
            if not hosts:
                hosts = [network.network_address]
            return str(hosts[0]), str(hosts[-1]), len(hosts)
        except ValueError as e:
            raise IPRangeError(f"Invalid CIDR notation: {cidr}") from e
    
    def parse_range(self, range_str: str) -> Tuple[str, str, int]:
        """
        Parse range notation (e.g., "192.168.1.1-192.168.1.254")
        
        Args:
            range_str: Range string with dash separator
            
        Returns:
            Tuple of (start_ip, end_ip, total_ips)
        """
        if '-' not in range_str:
            raise IPRangeError(f"Invalid range notation: {range_str}")
        
        parts = range_str.strip().split('-')
        if len(parts) != 2:
            raise IPRangeError(f"Invalid range notation: {range_str}")
        
        start_ip = parts[0].strip()
        end_part = parts[1].strip()
        
        if not self.validate_ip(start_ip):
            raise IPRangeError(f"Invalid start IP: {start_ip}")
        
        if '.' in end_part:
            end_ip = end_part
        else:
            start_parts = start_ip.split('.')
            start_parts[-1] = end_part
            end_ip = '.'.join(start_parts)
        
        if not self.validate_ip(end_ip):
            raise IPRangeError(f"Invalid end IP: {end_ip}")
        
        start_int = self.ip_to_int(start_ip)
        end_int = self.ip_to_int(end_ip)
        
        if start_int > end_int:
            raise IPRangeError(f"Start IP must be less than or equal to end IP")
        
        total = end_int - start_int + 1
        return start_ip, end_ip, total
    
    def parse(self, input_str: str) -> Tuple[str, str, int]:
        """
        Parse any supported IP range format
        
        Args:
            input_str: IP range in any supported format
            
        Returns:
            Tuple of (start_ip, end_ip, total_ips)
        """
        input_str = input_str.strip()
        
        if '/' in input_str:
            return self.parse_cidr(input_str)
        elif '-' in input_str:
            return self.parse_range(input_str)
        elif self.validate_ip(input_str):
            return input_str, input_str, 1
        else:
            raise IPRangeError(f"Unsupported IP range format: {input_str}")
    
    def enumerate_ips(self, start_ip: str, end_ip: str) -> Iterator[str]:
        """
        Enumerate all IPs between start and end (inclusive)
        
        Args:
            start_ip: Starting IP address
            end_ip: Ending IP address
            
        Yields:
            IP addresses as strings
        """
        start_int = self.ip_to_int(start_ip)
        end_int = self.ip_to_int(end_ip)
        
        for ip_int in range(start_int, end_int + 1):
            yield self.int_to_ip(ip_int)
    
    def enumerate_from_input(self, input_str: str) -> Iterator[str]:
        """
        Parse input and enumerate all IPs
        
        Args:
            input_str: IP range in any supported format
            
        Yields:
            IP addresses as strings
        """
        start_ip, end_ip, _ = self.parse(input_str)
        return self.enumerate_ips(start_ip, end_ip)


class MinerDetector:
    """
    Detect miner type and extract information from API responses
    
    Supports detection of:
    - Bitmain Antminer (S19, S21, T19, etc.)
    - MicroBT Whatsminer (M30, M50, M60, etc.)
    - Canaan Avalon miners
    - Other CGMiner-compatible miners
    """
    
    MINER_PATTERNS = {
        'antminer': {
            'pattern': re.compile(r'Antminer\s*(S\d+|T\d+|L\d+)', re.IGNORECASE),
            'manufacturer': 'Bitmain',
        },
        'whatsminer': {
            'pattern': re.compile(r'(M\d+S?|M\d+S\+?\+?)', re.IGNORECASE),
            'manufacturer': 'MicroBT',
        },
        'avalon': {
            'pattern': re.compile(r'Avalon\s*(\d+)', re.IGNORECASE),
            'manufacturer': 'Canaan',
        },
    }
    
    @classmethod
    def detect_from_cgminer_response(cls, response: Dict) -> Dict[str, Any]:
        """
        Extract miner information from CGMiner API response
        
        Args:
            response: CGMiner API response dictionary
            
        Returns:
            Dict with detected_model, detected_firmware, detected_hashrate_ghs
        """
        result = {
            'detected_model': None,
            'detected_firmware': None,
            'detected_hashrate_ghs': None,
            'mac_address': None,
        }
        
        try:
            summary = response.get('SUMMARY', [{}])
            if isinstance(summary, list) and summary:
                summary_data = summary[0]
                ghs_5s = summary_data.get('GHS 5s', 0)
                ghs_av = summary_data.get('GHS av', 0)
                result['detected_hashrate_ghs'] = float(ghs_5s or ghs_av or 0)
            
            stats = response.get('STATS', [])
            if isinstance(stats, list):
                for stat in stats:
                    if isinstance(stat, dict):
                        stat_type = stat.get('Type', '')
                        
                        for miner_type, info in cls.MINER_PATTERNS.items():
                            match = info['pattern'].search(stat_type)
                            if match:
                                result['detected_model'] = f"{info['manufacturer']} {stat_type}"
                                break
                        
                        if not result['detected_model'] and stat_type:
                            result['detected_model'] = stat_type
                        
                        if 'CompileTime' in stat:
                            result['detected_firmware'] = stat.get('CompileTime')
                        elif 'Firmware' in stat:
                            result['detected_firmware'] = stat.get('Firmware')
                        
                        if 'MAC' in stat:
                            result['mac_address'] = stat.get('MAC')
            
            version = response.get('VERSION', [{}])
            if isinstance(version, list) and version:
                version_data = version[0]
                if not result['detected_model']:
                    result['detected_model'] = version_data.get('Type', version_data.get('Miner', ''))
                if not result['detected_firmware']:
                    result['detected_firmware'] = version_data.get('CGMiner', version_data.get('API', ''))
                    
        except Exception as e:
            logger.debug(f"Error parsing CGMiner response: {e}")
        
        return result
    
    @classmethod
    def detect_from_http_response(cls, content: str, headers: Dict = None) -> Dict[str, Any]:
        """
        Try to detect miner from HTTP response (web interface)
        
        Args:
            content: HTTP response body
            headers: HTTP response headers
            
        Returns:
            Dict with detected_model, detected_firmware
        """
        result = {
            'detected_model': None,
            'detected_firmware': None,
            'detected_hashrate_ghs': None,
        }
        
        content_lower = content.lower()
        
        if 'antminer' in content_lower:
            for pattern in [r'Antminer\s*(S\d+[A-Za-z]*\s*[A-Za-z+]*)', r'Antminer\s*(T\d+[A-Za-z]*)']:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    result['detected_model'] = f"Bitmain Antminer {match.group(1)}"
                    break
        elif 'whatsminer' in content_lower or 'microbt' in content_lower:
            match = re.search(r'(M\d+S?\+*)', content, re.IGNORECASE)
            if match:
                result['detected_model'] = f"MicroBT Whatsminer {match.group(1)}"
        elif 'avalon' in content_lower:
            match = re.search(r'Avalon\s*(\d+)', content, re.IGNORECASE)
            if match:
                result['detected_model'] = f"Canaan Avalon {match.group(1)}"
        
        return result


class MinerScanner:
    """
    Async network scanner for miner discovery
    
    Uses asyncio for concurrent probing with configurable limits
    """
    
    def __init__(
        self,
        max_concurrent: int = MAX_CONCURRENT,
        cgminer_port: int = DEFAULT_CGMINER_PORT,
        http_port: int = DEFAULT_HTTP_PORT,
        timeout: float = DEFAULT_TIMEOUT,
        try_http: bool = True
    ):
        """
        Initialize scanner
        
        Args:
            max_concurrent: Maximum concurrent connections
            cgminer_port: CGMiner API port (default 4028)
            http_port: HTTP port for web interface detection
            timeout: Connection timeout in seconds
            try_http: Whether to try HTTP if CGMiner fails
        """
        self.max_concurrent = max_concurrent
        self.cgminer_port = cgminer_port
        self.http_port = http_port
        self.timeout = timeout
        self.try_http = try_http
        self._semaphore = None
    
    async def _probe_cgminer(self, ip: str) -> Optional[Dict]:
        """Probe CGMiner API on given IP"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, self.cgminer_port),
                timeout=self.timeout
            )
            
            request = json.dumps({"command": "summary+stats+version"}).encode('utf-8')
            writer.write(request)
            await writer.drain()
            
            response = b''
            try:
                while True:
                    chunk = await asyncio.wait_for(reader.read(4096), timeout=self.timeout)
                    if not chunk:
                        break
                    response += chunk
                    if b'\x00' in chunk:
                        break
            except asyncio.TimeoutError:
                pass
            
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            
            if response:
                data = response.rstrip(b'\x00').decode('utf-8', errors='ignore')
                return json.loads(data)
                
        except Exception as e:
            logger.debug(f"CGMiner probe failed for {ip}: {e}")
        
        return None
    
    async def _probe_http(self, ip: str) -> Optional[Tuple[str, Dict]]:
        """Probe HTTP interface on given IP"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, self.http_port),
                timeout=self.timeout
            )
            
            request = f"GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
            writer.write(request.encode('utf-8'))
            await writer.drain()
            
            response = b''
            try:
                while True:
                    chunk = await asyncio.wait_for(reader.read(4096), timeout=self.timeout)
                    if not chunk:
                        break
                    response += chunk
                    if len(response) > 16384:
                        break
            except asyncio.TimeoutError:
                pass
            
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            
            if response:
                content = response.decode('utf-8', errors='ignore')
                return content, {}
                
        except Exception as e:
            logger.debug(f"HTTP probe failed for {ip}: {e}")
        
        return None
    
    async def probe_ip(self, ip: str) -> MinerProbeResult:
        """
        Probe a single IP for miners
        
        Args:
            ip: IP address to probe
            
        Returns:
            MinerProbeResult with detection results
        """
        start_time = asyncio.get_event_loop().time()
        
        async with self._semaphore:
            cgminer_response = await self._probe_cgminer(ip)
            
            if cgminer_response:
                probe_time = (asyncio.get_event_loop().time() - start_time) * 1000
                detected = MinerDetector.detect_from_cgminer_response(cgminer_response)
                
                return MinerProbeResult(
                    ip_address=ip,
                    is_miner=True,
                    api_port=self.cgminer_port,
                    detected_model=detected.get('detected_model'),
                    detected_firmware=detected.get('detected_firmware'),
                    detected_hashrate_ghs=detected.get('detected_hashrate_ghs'),
                    mac_address=detected.get('mac_address'),
                    raw_response=cgminer_response,
                    probe_time_ms=probe_time,
                )
            
            if self.try_http:
                http_result = await self._probe_http(ip)
                if http_result:
                    content, headers = http_result
                    detected = MinerDetector.detect_from_http_response(content, headers)
                    
                    if detected.get('detected_model'):
                        probe_time = (asyncio.get_event_loop().time() - start_time) * 1000
                        return MinerProbeResult(
                            ip_address=ip,
                            is_miner=True,
                            api_port=self.http_port,
                            detected_model=detected.get('detected_model'),
                            detected_firmware=detected.get('detected_firmware'),
                            probe_time_ms=probe_time,
                        )
            
            probe_time = (asyncio.get_event_loop().time() - start_time) * 1000
            return MinerProbeResult(
                ip_address=ip,
                is_miner=False,
                probe_time_ms=probe_time,
            )
    
    async def scan_range(
        self,
        ips: List[str],
        progress_callback: Optional[Callable[[int, int, Optional[MinerProbeResult]], None]] = None
    ) -> List[MinerProbeResult]:
        """
        Scan a list of IPs for miners
        
        Args:
            ips: List of IP addresses to scan
            progress_callback: Optional callback(scanned, total, result)
            
        Returns:
            List of MinerProbeResult for each IP
        """
        self._semaphore = asyncio.Semaphore(self.max_concurrent)
        total = len(ips)
        results = []
        scanned = 0
        
        async def scan_with_progress(ip: str) -> MinerProbeResult:
            nonlocal scanned
            result = await self.probe_ip(ip)
            scanned += 1
            if progress_callback:
                try:
                    progress_callback(scanned, total, result if result.is_miner else None)
                except Exception as e:
                    logger.warning(f"Progress callback error: {e}")
            return result
        
        tasks = [scan_with_progress(ip) for ip in ips]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        valid_results = []
        for r in results:
            if isinstance(r, MinerProbeResult):
                valid_results.append(r)
            else:
                logger.warning(f"Scan task exception: {r}")
        
        return valid_results
    
    def scan_range_sync(
        self,
        ips: List[str],
        progress_callback: Optional[Callable[[int, int, Optional[MinerProbeResult]], None]] = None
    ) -> List[MinerProbeResult]:
        """
        Synchronous wrapper for scan_range
        
        Args:
            ips: List of IP addresses to scan
            progress_callback: Optional callback(scanned, total, result)
            
        Returns:
            List of MinerProbeResult for each IP
        """
        return asyncio.run(self.scan_range(ips, progress_callback))


def parse_ip_range(input_str: str) -> Tuple[str, str, int]:
    """
    Convenience function to parse IP range
    
    Args:
        input_str: IP range in CIDR, range, or single IP format
        
    Returns:
        Tuple of (start_ip, end_ip, total_ips)
    """
    parser = IPRangeParser()
    return parser.parse(input_str)


def enumerate_ips(input_str: str) -> List[str]:
    """
    Convenience function to enumerate IPs from range string
    
    Args:
        input_str: IP range in any supported format
        
    Returns:
        List of IP addresses
    """
    parser = IPRangeParser()
    return list(parser.enumerate_from_input(input_str))


async def quick_scan(
    ip_range: str,
    max_concurrent: int = 50,
    timeout: float = 3.0,
    progress_callback: Optional[Callable] = None
) -> List[MinerProbeResult]:
    """
    Quick scan convenience function
    
    Args:
        ip_range: IP range string (CIDR, range, or single IP)
        max_concurrent: Maximum concurrent connections
        timeout: Connection timeout in seconds
        progress_callback: Optional progress callback
        
    Returns:
        List of MinerProbeResult for discovered miners only
    """
    ips = enumerate_ips(ip_range)
    scanner = MinerScanner(max_concurrent=max_concurrent, timeout=timeout)
    results = await scanner.scan_range(ips, progress_callback)
    return [r for r in results if r.is_miner]
