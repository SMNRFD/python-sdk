"""SMCP Discovery - Peer and service discovery."""
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field
import threading


class DiscoveryError(Exception):
    pass


@dataclass
class DiscoveryResult:
    peer_id: str
    address: str
    port: int
    services: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "peer_id": self.peer_id,
            "address": self.address,
            "port": self.port,
            "services": self.services,
            "metadata": self.metadata,
        }


class DiscoveryService:
    def __init__(self):
        self._peers: Dict[str, DiscoveryResult] = {}
        self._lock = threading.RLock()
    
    def register_peer(self, result: DiscoveryResult) -> None:
        with self._lock:
            self._peers[result.peer_id] = result
    
    def get_peer(self, peer_id: str) -> Optional[DiscoveryResult]:
        with self._lock:
            return self._peers.get(peer_id)
    
    def list_peers(self) -> List[DiscoveryResult]:
        with self._lock:
            return list(self._peers.values())
    
    def find_by_service(self, service: str) -> List[DiscoveryResult]:
        with self._lock:
            return [p for p in self._peers.values() if service in p.services]
    
    def clear(self) -> None:
        with self._lock:
            self._peers.clear()


__all__ = ["DiscoveryError", "DiscoveryResult", "DiscoveryService"]
