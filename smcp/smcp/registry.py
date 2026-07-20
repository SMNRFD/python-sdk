"""SMCP Registry - Tool registry and discovery."""
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field
import threading


class RegistryError(Exception):
    pass


@dataclass
class ToolManifest:
    id: str
    name: str
    description: str = ""
    version: str = "1.0.0"
    actions: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "actions": self.actions,
            "metadata": self.metadata,
        }


class ToolRegistry:
    def __init__(self):
        self._tools: Dict[str, ToolManifest] = {}
        self._lock = threading.RLock()
    
    def register(self, manifest: ToolManifest) -> None:
        with self._lock:
            self._tools[manifest.id] = manifest
    
    def get(self, tool_id: str) -> Optional[ToolManifest]:
        with self._lock:
            return self._tools.get(tool_id)
    
    def list_tools(self) -> List[ToolManifest]:
        with self._lock:
            return list(self._tools.values())
    
    def unregister(self, tool_id: str) -> None:
        with self._lock:
            self._tools.pop(tool_id, None)
    
    def clear(self) -> None:
        with self._lock:
            self._tools.clear()


__all__ = ["RegistryError", "ToolManifest", "ToolRegistry"]
