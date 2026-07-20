"""SMCP Transport Layer - Abstract transport with TLS, TCP, WebSocket implementations."""
import asyncio
from typing import Optional, Dict, Any, Protocol
from dataclasses import dataclass
import threading


class TransportError(Exception):
    """Base exception for transport errors."""
    pass


@dataclass
class TransportConfig:
    """Transport configuration."""
    host: str = "localhost"
    port: int = 8443
    use_tls: bool = True
    timeout: float = 30.0
    max_message_size: int = 10 * 1024 * 1024  # 10MB


class Transport(Protocol):
    """Abstract transport interface."""
    
    async def connect(self) -> None: ...
    async def disconnect(self) -> None: ...
    async def send(self, data: bytes) -> None: ...
    async def receive(self) -> bytes: ...
    @property
    def is_connected(self) -> bool: ...


class TcpTransport:
    """TCP transport implementation."""
    
    def __init__(self, config: TransportConfig):
        self._config = config
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._connected = False
        self._lock = threading.Lock()
    
    async def connect(self) -> None:
        """Establish TCP connection."""
        try:
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(self._config.host, self._config.port),
                timeout=self._config.timeout
            )
            self._connected = True
        except Exception as e:
            raise TransportError(f"Failed to connect: {e}")
    
    async def disconnect(self) -> None:
        """Close connection."""
        if self._writer:
            self._writer.close()
            try:
                await self._writer.wait_closed()
            except Exception:
                pass
        self._connected = False
    
    async def send(self, data: bytes) -> None:
        """Send data."""
        if not self._connected or not self._writer:
            raise TransportError("Not connected")
        
        try:
            self._writer.write(len(data).to_bytes(4, 'big'))
            self._writer.write(data)
            await self._writer.drain()
        except Exception as e:
            self._connected = False
            raise TransportError(f"Send failed: {e}")
    
    async def receive(self) -> bytes:
        """Receive data."""
        if not self._connected or not self._reader:
            raise TransportError("Not connected")
        
        try:
            length_bytes = await asyncio.wait_for(
                self._reader.readexactly(4),
                timeout=self._config.timeout
            )
            length = int.from_bytes(length_bytes, 'big')
            
            if length > self._config.max_message_size:
                raise TransportError(f"Message too large: {length}")
            
            return await asyncio.wait_for(
                self._reader.readexactly(length),
                timeout=self._config.timeout
            )
        except Exception as e:
            self._connected = False
            raise TransportError(f"Receive failed: {e}")
    
    @property
    def is_connected(self) -> bool:
        return self._connected and self._writer is not None


class TlsTransport(TcpTransport):
    """TLS-wrapped TCP transport."""
    
    def __init__(self, config: TransportConfig, cert_path: Optional[str] = None,
                 key_path: Optional[str] = None, ca_path: Optional[str] = None):
        super().__init__(config)
        self._cert_path = cert_path
        self._key_path = key_path
        self._ca_path = ca_path
    
    async def connect(self) -> None:
        """Establish TLS connection."""
        import ssl
        
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        
        if self._ca_path:
            ctx.load_verify_locations(self._ca_path)
        
        if self._cert_path and self._key_path:
            ctx.load_cert_chain(self._cert_path, self._key_path)
        
        try:
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(
                    self._config.host, 
                    self._config.port,
                    ssl=ctx
                ),
                timeout=self._config.timeout
            )
            self._connected = True
        except Exception as e:
            raise TransportError(f"TLS connection failed: {e}")


class WebSocketTransport:
    """WebSocket transport implementation."""
    
    def __init__(self, config: TransportConfig):
        self._config = config
        self._ws = None
        self._connected = False
    
    async def connect(self) -> None:
        """Establish WebSocket connection."""
        try:
            import websockets
            
            scheme = "wss" if self._config.use_tls else "ws"
            uri = f"{scheme}://{self._config.host}:{self._config.port}"
            
            self._ws = await asyncio.wait_for(
                websockets.connect(uri),
                timeout=self._config.timeout
            )
            self._connected = True
        except Exception as e:
            raise TransportError(f"WebSocket connection failed: {e}")
    
    async def disconnect(self) -> None:
        """Close connection."""
        if self._ws:
            await self._ws.close()
        self._connected = False
    
    async def send(self, data: bytes) -> None:
        """Send data."""
        if not self._connected or not self._ws:
            raise TransportError("Not connected")
        
        try:
            await self._ws.send(data)
        except Exception as e:
            self._connected = False
            raise TransportError(f"Send failed: {e}")
    
    async def receive(self) -> bytes:
        """Receive data."""
        if not self._connected or not self._ws:
            raise TransportError("Not connected")
        
        try:
            data = await asyncio.wait_for(
                self._ws.recv(),
                timeout=self._config.timeout
            )
            return data if isinstance(data, bytes) else data.encode()
        except Exception as e:
            self._connected = False
            raise TransportError(f"Receive failed: {e}")
    
    @property
    def is_connected(self) -> bool:
        return self._connected and self._ws is not None


__all__ = [
    "TransportError",
    "TransportConfig",
    "Transport",
    "TcpTransport",
    "TlsTransport",
    "WebSocketTransport",
]
