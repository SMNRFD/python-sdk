"""SMCP Server."""
import asyncio
from typing import Optional, Dict, Any
from dataclasses import dataclass


class ServerError(Exception):
    pass


@dataclass
class ServerConfig:
    host: str = "0.0.0.0"
    port: int = 8443
    use_tls: bool = True
    cert_path: Optional[str] = None
    key_path: Optional[str] = None


class Server:
    def __init__(self, config: ServerConfig):
        self._config = config
        self._server = None
        self._running = False
    
    async def start(self) -> None:
        self._running = True
    
    async def stop(self) -> None:
        self._running = False
        if self._server:
            self._server.close()
    
    @property
    def is_running(self) -> bool:
        return self._running


__all__ = ["ServerError", "ServerConfig", "Server"]
