"""
SMCP Protocol Layer

Protocol message definitions and handling for all SMCP messages:
- HELLO, NEGOTIATE, AUTH
- SESSION_OPEN, SESSION_CLOSE
- PING, PONG, HEARTBEAT
- DISCOVER, LIST_TOOLS, GET_TOOL, INVOKE
- RESULT, ERROR
- CONSENT_REQUEST, CONSENT_RESPONSE
- CAPABILITY_REQUEST, CAPABILITY_GRANT, CAPABILITY_REVOKE
- AUDIT_RECEIPT, POLICY_DECISION

Security Properties:
- All messages are signed
- Replay protection via nonces
- Clock skew validation
- Strict message validation
"""

import uuid
from enum import Enum
from typing import Optional, List, Dict, Any, Union
from dataclasses import dataclass, field
from datetime import datetime
import threading
import cbor2

from smcp.crypto import KeyPair, SignedMessage, CryptoError, Hasher


class MessageType(Enum):
    """All SMCP protocol message types."""
    # Connection
    HELLO = "hello"
    NEGOTIATE = "negotiate"
    AUTH = "auth"
    
    # Session
    SESSION_OPEN = "session_open"
    SESSION_CLOSE = "session_close"
    
    # Keepalive
    PING = "ping"
    PONG = "pong"
    HEARTBEAT = "heartbeat"
    
    # Discovery
    DISCOVER = "discover"
    LIST_TOOLS = "list_tools"
    GET_TOOL = "get_tool"
    
    # Invocation
    INVOKE = "invoke"
    RESULT = "result"
    ERROR = "error"
    
    # Consent
    CONSENT_REQUEST = "consent_request"
    CONSENT_RESPONSE = "consent_response"
    
    # Capability
    CAPABILITY_REQUEST = "capability_request"
    CAPABILITY_GRANT = "capability_grant"
    CAPABILITY_REVOKE = "capability_revoke"
    
    # Audit & Policy
    AUDIT_RECEIPT = "audit_receipt"
    POLICY_DECISION = "policy_decision"


class ProtocolError(Exception):
    """Base exception for protocol errors."""
    pass


@dataclass
class Message:
    """An SMCP protocol message."""
    id: str
    type: MessageType
    payload: Dict[str, Any]
    sender_id: str
    recipient_id: Optional[str] = None
    nonce: str = ""  # For replay protection
    timestamp: int = 0  # Unix epoch seconds
    signature: Optional[str] = None
    version: str = "1.0"
    
    @classmethod
    def create(cls, msg_type: MessageType, sender_id: str,
               payload: Optional[Dict[str, Any]] = None,
               recipient_id: Optional[str] = None) -> 'Message':
        """Create a new message."""
        now = datetime.utcnow()
        return cls(
            id=str(uuid.uuid4()),
            type=msg_type,
            payload=payload or {},
            sender_id=sender_id,
            recipient_id=recipient_id,
            nonce=Hasher.sha256(uuid.uuid4().bytes).hex()[:16],
            timestamp=int(now.timestamp()),
            version="1.0",
        )
    
    def sign(self, keypair: KeyPair) -> None:
        """Sign the message."""
        canonical = self._canonical_bytes()
        signature = keypair.sign(canonical)
        self.signature = signature.hex()
    
    def verify(self, public_key: bytes) -> bool:
        """Verify the message signature."""
        if not self.signature:
            raise ProtocolError("Message not signed")
        
        from nacl.signing import VerifyKey, BadSignatureError
        
        try:
            verify_key = VerifyKey(public_key)
            signature = bytes.fromhex(self.signature)
            verify_key.verify(self._canonical_bytes(), signature)
            return True
        except BadSignatureError:
            raise ProtocolError("Signature verification failed")
    
    def _canonical_bytes(self) -> bytes:
        """Get canonical bytes for signing."""
        data = {
            "id": self.id,
            "type": self.type.value,
            "payload": self.payload,
            "sender_id": self.sender_id,
            "recipient_id": self.recipient_id,
            "nonce": self.nonce,
            "timestamp": self.timestamp,
            "version": self.version,
        }
        return cbor2.dumps(data)
    
    def validate(self, max_clock_skew: int = 300) -> bool:
        """Validate the message (timestamp, nonce, etc.)."""
        now = int(datetime.utcnow().timestamp())
        
        # Check clock skew
        if abs(now - self.timestamp) > max_clock_skew:
            raise ProtocolError(f"Message timestamp outside acceptable clock skew")
        
        # Validate nonce format
        if not self.nonce or len(self.nonce) < 8:
            raise ProtocolError("Invalid nonce")
        
        return True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "type": self.type.value,
            "payload": self.payload,
            "sender_id": self.sender_id,
            "recipient_id": self.recipient_id,
            "nonce": self.nonce,
            "timestamp": self.timestamp,
            "signature": self.signature,
            "version": self.version,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Message':
        """Create from dictionary."""
        return cls(
            id=data["id"],
            type=MessageType(data["type"]),
            payload=data["payload"],
            sender_id=data["sender_id"],
            recipient_id=data.get("recipient_id"),
            nonce=data.get("nonce", ""),
            timestamp=data.get("timestamp", 0),
            signature=data.get("signature"),
            version=data.get("version", "1.0"),
        )
    
    def serialize(self) -> bytes:
        """Serialize message to bytes."""
        return cbor2.dumps(self.to_dict())
    
    @classmethod
    def deserialize(cls, data: bytes) -> 'Message':
        """Deserialize message from bytes."""
        return cls.from_dict(cbor2.loads(data))


# Message builders for specific message types
def hello_message(sender_id: str, protocol_version: str = "1.0",
                  capabilities: Optional[List[str]] = None) -> Message:
    """Create a HELLO message."""
    return Message.create(
        MessageType.HELLO,
        sender_id,
        {
            "protocol_version": protocol_version,
            "capabilities": capabilities or [],
        }
    )


def negotiate_message(sender_id: str, options: Dict[str, Any]) -> Message:
    """Create a NEGOTIATE message."""
    return Message.create(MessageType.NEGOTIATE, sender_id, {"options": options})


def auth_message(sender_id: str, credentials: Dict[str, Any]) -> Message:
    """Create an AUTH message."""
    return Message.create(MessageType.AUTH, sender_id, {"credentials": credentials})


def session_open_message(sender_id: str, session_id: str) -> Message:
    """Create a SESSION_OPEN message."""
    return Message.create(MessageType.SESSION_OPEN, sender_id, {"session_id": session_id})


def session_close_message(sender_id: str, session_id: str, reason: str = "") -> Message:
    """Create a SESSION_CLOSE message."""
    return Message.create(
        MessageType.SESSION_CLOSE,
        sender_id,
        {"session_id": session_id, "reason": reason}
    )


def ping_message(sender_id: str) -> Message:
    """Create a PING message."""
    return Message.create(MessageType.PING, sender_id)


def pong_message(sender_id: str, ping_id: str) -> Message:
    """Create a PONG message."""
    return Message.create(MessageType.PONG, sender_id, {"ping_id": ping_id})


def heartbeat_message(sender_id: str, sequence: int) -> Message:
    """Create a HEARTBEAT message."""
    return Message.create(MessageType.HEARTBEAT, sender_id, {"sequence": sequence})


def discover_message(sender_id: str, query: str) -> Message:
    """Create a DISCOVER message."""
    return Message.create(MessageType.DISCOVER, sender_id, {"query": query})


def list_tools_message(sender_id: str) -> Message:
    """Create a LIST_TOOLS message."""
    return Message.create(MessageType.LIST_TOOLS, sender_id)


def get_tool_message(sender_id: str, tool_id: str) -> Message:
    """Create a GET_TOOL message."""
    return Message.create(MessageType.GET_TOOL, sender_id, {"tool_id": tool_id})


def invoke_message(sender_id: str, tool_id: str, action: str,
                   arguments: Dict[str, Any]) -> Message:
    """Create an INVOKE message."""
    return Message.create(
        MessageType.INVOKE,
        sender_id,
        {"tool_id": tool_id, "action": action, "arguments": arguments}
    )


def result_message(sender_id: str, request_id: str, result: Any) -> Message:
    """Create a RESULT message."""
    return Message.create(
        MessageType.RESULT,
        sender_id,
        {"request_id": request_id, "result": result}
    )


def error_message(sender_id: str, request_id: str, error_code: str,
                  error_message: str) -> Message:
    """Create an ERROR message."""
    return Message.create(
        MessageType.ERROR,
        sender_id,
        {
            "request_id": request_id,
            "error_code": error_code,
            "error_message": error_message,
        }
    )


def consent_request_message(sender_id: str, request_data: Dict[str, Any]) -> Message:
    """Create a CONSENT_REQUEST message."""
    return Message.create(MessageType.CONSENT_REQUEST, sender_id, request_data)


def consent_response_message(sender_id: str, request_id: str, granted: bool) -> Message:
    """Create a CONSENT_RESPONSE message."""
    return Message.create(
        MessageType.CONSENT_RESPONSE,
        sender_id,
        {"request_id": request_id, "granted": granted}
    )


def capability_grant_message(sender_id: str, capability_data: Dict[str, Any]) -> Message:
    """Create a CAPABILITY_GRANT message."""
    return Message.create(MessageType.CAPABILITY_GRANT, sender_id, capability_data)


def capability_revoke_message(sender_id: str, capability_id: str) -> Message:
    """Create a CAPABILITY_REVOKE message."""
    return Message.create(MessageType.CAPABILITY_REVOKE, sender_id, {"capability_id": capability_id})


def audit_receipt_message(sender_id: str, receipt_data: Dict[str, Any]) -> Message:
    """Create an AUDIT_RECEIPT message."""
    return Message.create(MessageType.AUDIT_RECEIPT, sender_id, receipt_data)


def policy_decision_message(sender_id: str, decision: str, reason: str) -> Message:
    """Create a POLICY_DECISION message."""
    return Message.create(
        MessageType.POLICY_DECISION,
        sender_id,
        {"decision": decision, "reason": reason}
    )


class ProtocolHandler:
    """Handles protocol message processing."""
    
    def __init__(self):
        self._seen_nonces: Dict[str, datetime] = {}
        self._lock = threading.RLock()
        self._nonce_expiry_seconds = 600
    
    def process(self, message: Message, public_keys: Dict[str, bytes]) -> bool:
        """Process and validate an incoming message."""
        with self._lock:
            # Validate timestamp
            message.validate()
            
            # Check for replay
            if message.nonce in self._seen_nonces:
                raise ProtocolError("Replay detected: duplicate nonce")
            
            # Verify signature
            public_key = public_keys.get(message.sender_id)
            if public_key:
                message.verify(public_key)
            
            # Record nonce
            self._seen_nonces[message.nonce] = datetime.utcnow()
            self._cleanup_nonces()
            
            return True
    
    def _cleanup_nonces(self) -> None:
        """Clean up expired nonces."""
        now = datetime.utcnow()
        expired = [
            nonce for nonce, ts in self._seen_nonces.items()
            if (now - ts).total_seconds() > self._nonce_expiry_seconds
        ]
        for nonce in expired:
            del self._seen_nonces[nonce]
    
    def clear(self) -> None:
        """Clear all state."""
        with self._lock:
            self._seen_nonces.clear()


__all__ = [
    "MessageType",
    "ProtocolError",
    "Message",
    "ProtocolHandler",
    # Message builders
    "hello_message",
    "negotiate_message",
    "auth_message",
    "session_open_message",
    "session_close_message",
    "ping_message",
    "pong_message",
    "heartbeat_message",
    "discover_message",
    "list_tools_message",
    "get_tool_message",
    "invoke_message",
    "result_message",
    "error_message",
    "consent_request_message",
    "consent_response_message",
    "capability_grant_message",
    "capability_revoke_message",
    "audit_receipt_message",
    "policy_decision_message",
]
