from typing import Any, Dict

DEFAULT_ACTIONS = {
    "antminer": ["enable", "disable", "restart", "reboot", "set_pool", "set_fan", "set_frequency", "set_power", "set_temp_target"],
    "whatsminer": ["enable", "disable", "restart", "reboot", "set_pool"],
    "avalon": ["restart", "reboot", "set_pool"],
    "other": ["restart", "reboot"],
}

class CapabilityProbe:
    """Best-effort capability model used for guardrails.

    This is NOT a guarantee; execution-time validation still applies.
    """

    def __init__(self, *, http_enabled: bool = True):
        self.http_enabled = http_enabled

    def infer(self, vendor: str, protocol: str) -> Dict[str, Any]:
        vendor = (vendor or "other").lower()
        protocol = (protocol or "cgminer").lower()
        actions = list(DEFAULT_ACTIONS.get(vendor, DEFAULT_ACTIONS["other"]))
        if protocol == "http" and vendor == "whatsminer":
            actions = []
        return {
            "vendor": vendor,
            "protocol": protocol,
            "supported_actions": actions,
        }

    def is_supported(self, capability: Dict[str, Any], action: str) -> bool:
        if not capability:
            return False
        return str(action) in set(capability.get("supported_actions") or [])
