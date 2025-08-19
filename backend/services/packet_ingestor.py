from __future__ import annotations
from typing import Dict, Any, List
from datetime import datetime
import json
import os


class PacketIngestor:
    def __init__(self) -> None:
        self._incidents: List[Dict[str, Any]] = []
        self._data_path = "/workspace/backend/data/incidents.json"
        os.makedirs(os.path.dirname(self._data_path), exist_ok=True)
        self._load_from_disk()

    def _load_from_disk(self) -> None:
        try:
            if os.path.exists(self._data_path):
                with open(self._data_path, "r", encoding="utf-8") as fh:
                    self._incidents = json.load(fh) or []
        except Exception:
            self._incidents = []

    def _save_to_disk(self) -> None:
        try:
            with open(self._data_path, "w", encoding="utf-8") as fh:
                json.dump(self._incidents, fh)
        except Exception:
            pass

    def ingest(self, packet: Dict[str, Any]) -> None:
        if not packet:
            return
        record = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "src_ip": packet.get("src_ip"),
            "dst_ip": packet.get("dst_ip"),
            "src_port": packet.get("src_port"),
            "dst_port": packet.get("dst_port"),
            "size": packet.get("size"),
        }
        self._incidents.append(record)
        self._save_to_disk()

    def get_incidents(self) -> List[Dict[str, Any]]:
        return list(self._incidents)