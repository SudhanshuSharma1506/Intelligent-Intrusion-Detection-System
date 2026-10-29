"""
Blocklist Manager Module
------------------------
Thread-safe IP firewall blocklist and quarantine management.
"""

from typing import Dict, Any, List
from datetime import datetime
import threading
import json
import os


class BlocklistManager:
    """Manages active IP blocklist with JSON persistence."""

    def __init__(self, filepath: str = "data/blocklist.json"):
        self.filepath = filepath
        self._lock = threading.Lock()
        self._blocked_ips: Dict[str, Dict[str, Any]] = {}
        self._load()

    def _load(self) -> None:
        """Load blocklist entries from disk."""
        if os.path.exists(self.filepath):
            try:
                with open(self.filepath, "r", encoding="utf-8") as f:
                    self._blocked_ips = json.load(f)
            except Exception:
                self._blocked_ips = {}
        else:
            self._blocked_ips = {}

    def _save(self) -> None:
        """Persist blocklist entries to disk."""
        os.makedirs(os.path.dirname(os.path.abspath(self.filepath)), exist_ok=True)
        with open(self.filepath, "w", encoding="utf-8") as f:
            json.dump(self._blocked_ips, f, indent=2)

    def is_blocked(self, ip: str) -> bool:
        """Check if an IP address is currently blocked."""
        with self._lock:
            if ip in self._blocked_ips:
                self._blocked_ips[ip]["hits"] = self._blocked_ips[ip].get("hits", 0) + 1
                self._save()
                return True
            return False

    def block_ip(self, ip: str, reason: str = "Manual Quarantine", severity: str = "HIGH") -> bool:
        """Add an IP address to the blocklist."""
        with self._lock:
            if ip not in self._blocked_ips:
                self._blocked_ips[ip] = {
                    "ip": ip,
                    "reason": reason,
                    "severity": severity,
                    "blocked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "hits": 0,
                }
                self._save()
                return True
            return False

    def unblock_ip(self, ip: str) -> bool:
        """Remove an IP address from the blocklist."""
        with self._lock:
            if ip in self._blocked_ips:
                del self._blocked_ips[ip]
                self._save()
                return True
            return False

    def get_all(self) -> List[Dict[str, Any]]:
        """Return a list of all blocked IP entries."""
        with self._lock:
            return list(self._blocked_ips.values())

    def count(self) -> int:
        """Return total count of blocked IPs."""
        with self._lock:
            return len(self._blocked_ips)
