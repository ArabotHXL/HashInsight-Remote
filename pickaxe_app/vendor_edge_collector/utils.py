import re

_IP_RE = re.compile(r"(\b\d{1,3}(?:\.\d{1,3}){3}\b)")

def mask_ip(ip: str, *, keep_last: bool = True) -> str:
    """Mask an IPv4 string for logs.
    Example: 192.168.1.23 -> 192.168.x.x (keep_last=False) or 192.168.x.23 (keep_last=True)
    """
    if not ip:
        return ""
    parts = ip.split(".")
    if len(parts) != 4:
        return ip
    if keep_last:
        return ".".join([parts[0], parts[1], "x", parts[3]])
    return ".".join([parts[0], parts[1], "x", "x"])

def redact_ips(text: str, *, keep_last: bool = True) -> str:
    """Redact any IPv4s found in arbitrary text."""
    if not text:
        return text
    def _sub(m):
        return mask_ip(m.group(1), keep_last=keep_last)
    return _IP_RE.sub(_sub, text)
