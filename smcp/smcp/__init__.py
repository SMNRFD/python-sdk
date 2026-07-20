"""
SMCP - Secure Model Communication Protocol
Reference Implementation in Python

This is the official reference implementation of SMCP, a zero-trust,
capability-based secure communication protocol for model-to-model
and human-to-model interactions.
"""

__version__ = "1.0.0"
__author__ = "SMCP Project"
__license__ = "Apache-2.0"

from smcp.crypto import (
    CryptoError,
    KeyPair,
    ExchangeKeyPair,
    AesGcmCipher,
    ChaChaCipher,
    Hasher,
    KeyDeriver,
    SignedMessage,
    CryptoBox,
    generate_nonce,
    random_bytes,
)
from smcp.identity import (
    Identity,
    IdentityType,
    IdentityError,
    IdentityManager,
)
from smcp.capability import (
    Capability,
    CapabilityError,
    CapabilityManager,
    Constraints,
)
from smcp.policy import (
    Policy,
    PolicyEngine,
    PolicyDecision,
    PolicyError,
)
from smcp.consent import (
    ConsentRequest,
    ConsentResponse,
    ConsentStatus,
    ConsentManager,
    ConsentError,
)
from smcp.audit import (
    AuditRecord,
    AuditReceipt,
    AuditManager,
    AuditError,
)
from smcp.protocol import (
    Message,
    MessageType,
    ProtocolError,
    ProtocolHandler,
)
from smcp.transport import (
    Transport,
    TransportConfig,
    TransportError,
    TlsTransport,
    TcpTransport,
    WebSocketTransport,
)
from smcp.session import (
    Session,
    SessionState,
    SessionManager,
    SessionError,
)
from smcp.registry import (
    ToolRegistry,
    ToolManifest,
    RegistryError,
)
from smcp.discovery import (
    DiscoveryService,
    DiscoveryResult,
    DiscoveryError,
)
from smcp.server import (
    Server,
    ServerConfig,
    ServerError,
)
from smcp.client import (
    Client,
    ClientConfig,
    ClientError,
)
from smcp.runtime import (
    Runtime,
    RuntimeConfig,
    PluginInfo,
    RuntimeError as SmcpRuntimeError,
)

__all__ = [
    "__version__",
    "CryptoError", "KeyPair", "ExchangeKeyPair", "AesGcmCipher", "ChaChaCipher",
    "Hasher", "KeyDeriver", "SignedMessage", "CryptoBox", "generate_nonce", "random_bytes",
    "Identity", "IdentityType", "IdentityError", "IdentityManager",
    "Capability", "CapabilityError", "CapabilityManager", "Constraints",
    "Policy", "PolicyEngine", "PolicyDecision", "PolicyError",
    "ConsentRequest", "ConsentResponse", "ConsentStatus", "ConsentManager", "ConsentError",
    "AuditRecord", "AuditReceipt", "AuditManager", "AuditError",
    "Message", "MessageType", "ProtocolError", "ProtocolHandler",
    "Transport", "TransportConfig", "TransportError", "TlsTransport", "TcpTransport", "WebSocketTransport",
    "Session", "SessionState", "SessionManager", "SessionError",
    "ToolRegistry", "ToolManifest", "RegistryError",
    "DiscoveryService", "DiscoveryResult", "DiscoveryError",
    "Server", "ServerConfig", "ServerError",
    "Client", "ClientConfig", "ClientError",
    "Runtime", "RuntimeConfig", "PluginInfo", "SmcpRuntimeError",
]
