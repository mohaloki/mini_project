from __future__ import annotations
from typing import Optional


class GeoIPService:
    def country_for_ip(self, ip: Optional[str]) -> Optional[str]:
        if not ip:
            return None
        parts = ip.split(".")
        try:
            last = int(parts[-1])
        except Exception:
            last = 0
        countries = [
            "US", "DE", "GB", "FR", "NL", "SE", "NO", "FI",
            "RU", "CN", "JP", "SG", "BR", "AR", "CL", "IN",
        ]
        return countries[last % len(countries)]