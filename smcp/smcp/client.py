"""SMCP Client."""
import asyncio
from typing import Optional, Dict, Any
from dataclasses import dataclass


class ClientError(Exception):
    pass


@dataclass
class ClientConfig:
    host: str = "localhost"
    port: int = 8443
    use_tls: bool = True
    timeout: float = 30.0


class Client:
    def __init__(self, config: ClientConfig):
        self._config = config
        self._connected = False
    
    async def connect(self) -> None:
        self._connected = True
    
    async def disconnect(self) -> None:
        self._connected = False
    
    @property
    def is_connected(self) -> bool:
        return self._connected


__all__ = ["ClientError", "ClientConfig", "Client"]
