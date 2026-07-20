"""SMCP Runtime."""
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field


class RuntimeError(Exception):
    pass


@dataclass
class PluginInfo:
    id: str
    name: str
    version: str = "1.0.0"
    enabled: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RuntimeConfig:
    debug: bool = False
    log_level: str = "INFO"
    plugins: List[PluginInfo] = field(default_factory=list)


class Runtime:
    def __init__(self, config: Optional[RuntimeConfig] = None):
        self._config = config or RuntimeConfig()
        self._initialized = False
    
    def initialize(self) -> None:
        self._initialized = True
    
    def shutdown(self) -> None:
        self._initialized = False
    
    @property
    def is_initialized(self) -> bool:
        return self._initialized


__all__ = ["RuntimeError", "PluginInfo", "RuntimeConfig", "Runtime"]
