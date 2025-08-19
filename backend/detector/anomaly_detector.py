from __future__ import annotations
import math
from typing import Dict, Any


class AnomalyDetector:
    """Lightweight statistical anomaly detector placeholder.

    This implementation computes a simple heuristic score based on uncommon
    ports, large packet sizes, and bursty connection attempts. In a production
    system this would be replaced with an ML model.
    """

    def __init__(self) -> None:
        self.known_common_ports = {80, 443, 22, 25, 53}

    def score(self, packet: Dict[str, Any]) -> float:
        size = float(packet.get("size", 0))
        dst_port = int(packet.get("dst_port", 0) or 0)
        syn_flag = 1 if packet.get("syn", False) else 0
        rst_flag = 1 if packet.get("rst", False) else 0
        fin_flag = 1 if packet.get("fin", False) else 0
        rare_port = 0 if dst_port in self.known_common_ports else 1

        size_score = 1 - math.exp(-size / 1000.0)
        port_score = 0.6 if rare_port else 0.1
        flags_score = 0.2 * syn_flag + 0.2 * rst_flag + 0.2 * fin_flag

        score = min(1.0, size_score * 0.5 + port_score + flags_score)
        return float(score)