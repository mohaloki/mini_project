from __future__ import annotations
from typing import Optional, Dict, Any
from datetime import datetime
import subprocess
import os


class FirewallService:
    def __init__(self, dry_run: bool = True, log_path: str = "/workspace/backend/data/actions.log") -> None:
        self.dry_run = dry_run
        self.log_path = log_path
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)

    def _log(self, message: str) -> None:
        timestamp = datetime.utcnow().isoformat() + "Z"
        line = f"{timestamp} | {message}\n"
        try:
            with open(self.log_path, "a", encoding="utf-8") as fh:
                fh.write(line)
        except Exception:
            pass

    def block_ip(self, ip: str, reason: Optional[str] = None) -> Dict[str, Any]:
        if not ip:
            return {"error": "ip required"}
        cmd = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
        if self.dry_run:
            self._log(f"DRY_RUN BLOCK {ip} reason={reason or ''}")
            return {"ip": ip, "blocked": False, "dry_run": True, "cmd": " ".join(cmd)}
        try:
            subprocess.run(cmd, check=True)
            self._log(f"BLOCK {ip} reason={reason or ''}")
            return {"ip": ip, "blocked": True, "dry_run": False}
        except Exception as exc:
            self._log(f"ERROR blocking {ip}: {exc}")
            return {"ip": ip, "blocked": False, "dry_run": False, "error": str(exc)}