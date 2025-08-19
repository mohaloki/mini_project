from __future__ import annotations
from typing import Dict, Any
import random


class ThreatIntelService:
    def __init__(self) -> None:
        self._bad_ips = {"45.83.23.10", "185.220.101.1"}

    def reputation(self, ip: str) -> Dict[str, Any]:
        return {
            "ip": ip,
            "malicious": ip in self._bad_ips,
            "geo": random.choice(["US", "DE", "RU", "CN", "BR", "IN"]) if ip else None,
        }

    def port_scan(self, ip: str) -> Dict[str, Any]:
        open_ports = sorted(random.sample([22, 53, 80, 123, 443, 8080, 8443], k=random.randint(1, 4)))
        return {"ip": ip, "open_ports": open_ports}