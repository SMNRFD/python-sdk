"""
SMCP Protocol Layer

This module implements the SMCP protocol messages and framing.
All protocol messages follow the standard format with proper validation.

Architecture:
- Message types for all protocol operations
- Proper message framing and parsing
- Version negotiation support
- Replay protection through nonces
- Timestamp validation with clock skew handling

Security Notes:
- All messages must be signed
- Nonces prevent replay attacks
- Timestamps validated with configurable skew tolerance
- Messages fail closed on validation errors
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Optional, Dict, List, Any, Union

from crypto import PrivateKey, PublicKey, hash_data, generate_nonce
from identity import Identity
from capability import Capability


class MessageType(Enum):
    """All SMCP message types."""
    # Connection Establishment
    HELLO = "hello"
    NEGOTIATE = "negotiate"
    AUTH = "auth"
    
    # Session Management
    SESSION_OPEN = "session_open"
    SESSION_CLOSE = "session_close"
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
    
    # Authorization
    CONSENT_REQUEST = "consent_request"
    CONSENT_RESPONSE = "consent_response"
    CAPABILITY_REQUEST = "capability_request"
    CAPABILITY_GRANT = "capability_grant"
    CAPABILITY_REVOKE = "capability_revoke"
    
    # Audit
    AUDIT_RECEIPT = "audit_receipt"
    POLICY_DECISION = "policy_decision"


class ProtocolVersion:
    """Protocol version handling."""
    MAJOR = 1
    MINOR = 0
    PATCH = 0
    
    @classmethod
    def current(cls) -> str:
        return f"{cls.MAJOR}.{cls.MINOR}.{cls.PATCH}"
    
    @classmethod
    def parse(cls, version_str: str) -> tuple[int, int, int]:
        parts = version_str.split('.')
        if len(parts) != 3:
            raise ValueError(f"Invalid version format: {version_str}")
        return int(parts[0]), int(parts[1]), int(parts[2])
    
    @classmethod
    def is_compatible(cls, version_str: str) -> bool:
        major, _, _ = cls.parse(version_str)
        return major == cls.MAJOR


@dataclass
class ProtocolMessage:
    """
    Base protocol message structure.
    
    All SMCP messages share this common structure.
    """
    version: str
    message_type: MessageType
    message_id: str
    timestamp: datetime
    nonce: bytes
    sender: str  # Identity ID
    receiver: str  # Identity ID
    payload: Dict[str, Any]
    signature: bytes = field(default=b'')
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert message to dictionary."""
        return {
            'version': self.version,
            'message_type': self.message_type.value,
            'message_id': self.message_id,
            'timestamp': self.timestamp.isoformat(),
            'nonce': self.nonce.hex(),
            'sender': self.sender,
            'receiver': self.receiver,
            'payload': self.payload,
            'signature': self.signature.hex() if self.signature else '',
        }
    
    def to_bytes_for_signing(self) -> bytes:
        """Get bytes representation for signing (excludes signature)."""
        from transport.serialization import canonical_cbor_encode
        data = {
            'version': self.version,
            'message_type': self.message_type.value,
            'message_id': self.message_id,
            'timestamp': self.timestamp.isoformat(),
            'nonce': self.nonce.hex(),
            'sender': self.sender,
            'receiver': self.receiver,
            'payload': self.payload,
        }
        return canonical_cbor_encode(data)
    
    def sign(self, private_key: PrivateKey) -> None:
        """Sign the message."""
        data = self.to_bytes_for_signing()
        self.signature = private_key.sign(data)
    
    def verify(self, public_key: PublicKey) -> bool:
        """Verify the message signature."""
        if not self.signature:
            return False
        data = self.to_bytes_for_signing()
        return public_key.verify(self.signature, data)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ProtocolMessage:
        """Create message from dictionary."""
        return cls(
            version=data['version'],
            message_type=MessageType(data['message_type']),
            message_id=data['message_id'],
            nonce=bytes.fromhex(data['nonce']),
            sender=data['sender'],
            receiver=data['receiver'],
            payload=data.get('payload', {}),
            signature=bytes.fromhex(data['signature']) if data.get('signature') else b'',
            timestamp=datetime.fromisoformat(data['timestamp'].replace('Z', '+00:00')) if isinstance(data['timestamp'], str) else data['timestamp']
        )


# Message type-specific payload builders

def create_hello_payload(
    supported_versions: List[str],
    supported_formats: List[str],
    supported_transports: List[str],
    capabilities: List[str]
) -> Dict[str, Any]:
    """Create HELLO message payload."""
    return {
        'supported_versions': supported_versions,
        'supported_formats': supported_formats,
        'supported_transports': supported_transports,
        'capabilities': capabilities,
    }


def create_negotiate_payload(
    selected_version: str,
    selected_format: str,
    selected_transport: str,
    compression: Optional[str] = None,
    encoding: Optional[str] = None
) -> Dict[str, Any]:
    """Create NEGOTIATE message payload."""
    payload = {
        'selected_version': selected_version,
        'selected_format': selected_format,
        'selected_transport': selected_transport,
    }
    if compression:
        payload['compression'] = compression
    if encoding:
        payload['encoding'] = encoding
    return payload


def create_auth_payload(
    auth_method: str,
    credentials: Dict[str, Any],
    challenge_response: Optional[bytes] = None
) -> Dict[str, Any]:
    """Create AUTH message payload."""
    payload = {
        'auth_method': auth_method,
        'credentials': credentials,
    }
    if challenge_response:
        payload['challenge_response'] = challenge_response.hex()
    return payload


def create_session_open_payload(
    session_id: str,
    session_type: str,
    ttl_seconds: int,
    initial_capabilities: Optional[List[Dict[str, Any]]] = None
) -> Dict[str, Any]:
    """Create SESSION_OPEN message payload."""
    payload = {
        'session_id': session_id,
        'session_type': session_type,
        'ttl_seconds': ttl_seconds,
    }
    if initial_capabilities:
        payload['initial_capabilities'] = initial_capabilities
    return payload


def create_session_close_payload(
    reason: str,
    code: int = 1000
) -> Dict[str, Any]:
    """Create SESSION_CLOSE message payload."""
    return {
        'reason': reason,
        'code': code,
    }


def create_discover_payload(
    query_type: str,
    filters: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Create DISCOVER message payload."""
    payload = {'query_type': query_type}
    if filters:
        payload['filters'] = filters
    return payload


def create_invoke_payload(
    tool_id: str,
    action: str,
    parameters: Dict[str, Any],
    capability_ref: Optional[str] = None
) -> Dict[str, Any]:
    """Create INVOKE message payload."""
    payload = {
        'tool_id': tool_id,
        'action': action,
        'parameters': parameters,
    }
    if capability_ref:
        payload['capability_ref'] = capability_ref
    return payload


def create_result_payload(
    result: Any,
    metadata: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Create RESULT message payload."""
    payload = {'result': result}
    if metadata:
        payload['metadata'] = metadata
    return payload


def create_error_payload(
    error_code: int,
    error_message: str,
    details: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Create ERROR message payload."""
    payload = {
        'error_code': error_code,
        'error_message': error_message,
    }
    if details:
        payload['details'] = details
    return payload


def create_consent_request_payload(
    consent_type: str,
    requested_action: str,
    resource: str,
    reason: str,
    expires_in_seconds: Optional[int] = None
) -> Dict[str, Any]:
    """Create CONSENT_REQUEST message payload."""
    payload = {
        'consent_type': consent_type,
        'requested_action': requested_action,
        'resource': resource,
        'reason': reason,
    }
    if expires_in_seconds:
        payload['expires_in_seconds'] = expires_in_seconds
    return payload


def create_consent_response_payload(
    granted: bool,
    reason: Optional[str] = None,
    conditions: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Create CONSENT_RESPONSE message payload."""
    payload = {'granted': granted}
    if reason:
        payload['reason'] = reason
    if conditions:
        payload['conditions'] = conditions
    return payload


def create_capability_grant_payload(
    capability_data: Dict[str, Any],
    delegation_allowed: bool = False
) -> Dict[str, Any]:
    """Create CAPABILITY_GRANT message payload."""
    return {
        'capability': capability_data,
        'delegation_allowed': delegation_allowed,
    }


def create_audit_receipt_payload(
    audit_id: str,
    action: str,
    actor: str,
    timestamp: str,
    previous_hash: str,
    current_hash: str
) -> Dict[str, Any]:
    """Create AUDIT_RECEIPT message payload."""
    return {
        'audit_id': audit_id,
        'action': action,
        'actor': actor,
        'timestamp': timestamp,
        'previous_hash': previous_hash,
        'current_hash': current_hash,
    }


def create_policy_decision_payload(
    decision: str,  # permit, deny, indeterminate
    policy_id: str,
    obligations: Optional[List[Dict[str, Any]]] = None,
    advice: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Create POLICY_DECISION message payload."""
    payload = {
        'decision': decision,
        'policy_id': policy_id,
    }
    if obligations:
        payload['obligations'] = obligations
    if advice:
        payload['advice'] = advice
    return payload


class MessageValidator:
    """Validates protocol messages."""
    
    MAX_CLOCK_SKEW = timedelta(minutes=5)
    MAX_MESSAGE_AGE = timedelta(hours=1)
    
    def __init__(self, seen_nonces: Optional[set] = None, max_nonce_cache: int = 10000):
        self._seen_nonces: set[str] = seen_nonces or set()
        self._max_nonce_cache = max_nonce_cache
    
    def validate(
        self,
        message: ProtocolMessage,
        expected_receiver: str,
        trusted_senders: List[str]
    ) -> tuple[bool, str]:
        """
        Validate a message.
        
        Returns:
            Tuple of (is_valid, error_message)
        """
        # Check version compatibility
        if not ProtocolVersion.is_compatible(message.version):
            return False, f"Incompatible protocol version: {message.version}"
        
        # Check timestamp
        now = datetime.now(timezone.utc)
        message_time = message.timestamp
        
        if message_time.tzinfo is None:
            message_time = message_time.replace(tzinfo=timezone.utc)
        
        time_diff = abs((now - message_time).total_seconds())
        
        if time_diff > self.MAX_CLOCK_SKEW.total_seconds():
            return False, f"Message timestamp outside acceptable clock skew ({time_diff}s)"
        
        # Check nonce for replay
        nonce_hex = message.nonce.hex()
        if nonce_hex in self._seen_nonces:
            return False, "Duplicate nonce detected (replay attack)"
        
        # Add to seen nonces
        self._seen_nonces.add(nonce_hex)
        if len(self._seen_nonces) > self._max_nonce_cache:
            # Remove oldest entries (simple approach)
            for _ in range(len(self._seen_nonces) - self._max_nonce_cache // 2):
                self._seen_nonces.pop()
        
        # Check receiver
        if message.receiver != expected_receiver:
            return False, f"Message not intended for this receiver"
        
        # Check sender is trusted
        if message.sender not in trusted_senders:
            return False, f"Untrusted sender: {message.sender}"
        
        # Check signature exists
        if not message.signature:
            return False, "Message not signed"
        
        return True, ""
    
    def clear_nonces(self) -> None:
        """Clear the nonce cache."""
        self._seen_nonces.clear()


class MessageFactory:
    """Factory for creating protocol messages."""
    
    def __init__(self, sender_id: str, private_key: PrivateKey):
        self.sender_id = sender_id
        self.private_key = private_key
    
    def create_message(
        self,
        message_type: MessageType,
        receiver_id: str,
        payload: Dict[str, Any]
    ) -> ProtocolMessage:
        """Create and sign a new message."""
        message = ProtocolMessage(
            version=ProtocolVersion.current(),
            message_type=message_type,
            message_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc),
            nonce=generate_nonce(32),
            sender=self.sender_id,
            receiver=receiver_id,
            payload=payload,
        )
        message.sign(self.private_key)
        return message
    
    def create_hello(self, receiver_id: str) -> ProtocolMessage:
        """Create HELLO message."""
        payload = create_hello_payload(
            supported_versions=[ProtocolVersion.current()],
            supported_formats=['canonical-cbor', 'canonical-json'],
            supported_transports=['tls-tcp', 'unix-socket', 'stdio'],
            capabilities=['agent', 'tool_invocation', 'discovery']
        )
        return self.create_message(MessageType.HELLO, receiver_id, payload)
    
    def create_ping(self, receiver_id: str) -> ProtocolMessage:
        """Create PING message."""
        return self.create_message(MessageType.PING, receiver_id, {})
    
    def create_pong(self, receiver_id: str) -> ProtocolMessage:
        """Create PONG message."""
        return self.create_message(MessageType.PONG, receiver_id, {})
    
    def create_heartbeat(self, receiver_id: str, sequence: int) -> ProtocolMessage:
        """Create HEARTBEAT message."""
        return self.create_message(MessageType.HEARTBEAT, receiver_id, {'sequence': sequence})
    
    def create_session_open(
        self,
        receiver_id: str,
        session_id: str,
        session_type: str = 'standard',
        ttl_seconds: int = 3600
    ) -> ProtocolMessage:
        """Create SESSION_OPEN message."""
        payload = create_session_open_payload(session_id, session_type, ttl_seconds)
        return self.create_message(MessageType.SESSION_OPEN, receiver_id, payload)
    
    def create_session_close(
        self,
        receiver_id: str,
        reason: str = "normal_closure",
        code: int = 1000
    ) -> ProtocolMessage:
        """Create SESSION_CLOSE message."""
        payload = create_session_close_payload(reason, code)
        return self.create_message(MessageType.SESSION_CLOSE, receiver_id, payload)
    
    def create_invoke(
        self,
        receiver_id: str,
        tool_id: str,
        action: str,
        parameters: Dict[str, Any]
    ) -> ProtocolMessage:
        """Create INVOKE message."""
        payload = create_invoke_payload(tool_id, action, parameters)
        return self.create_message(MessageType.INVOKE, receiver_id, payload)
    
    def create_result(
        self,
        receiver_id: str,
        result: Any,
        in_reply_to: str
    ) -> ProtocolMessage:
        """Create RESULT message."""
        payload = create_result_payload(result)
        payload['in_reply_to'] = in_reply_to
        return self.create_message(MessageType.RESULT, receiver_id, payload)
    
    def create_error(
        self,
        receiver_id: str,
        error_code: int,
        error_message: str,
        in_reply_to: Optional[str] = None
    ) -> ProtocolMessage:
        """Create ERROR message."""
        payload = create_error_payload(error_code, error_message)
        if in_reply_to:
            payload['in_reply_to'] = in_reply_to
        return self.create_message(MessageType.ERROR, receiver_id, payload)


# Export all public symbols
__all__ = [
    'MessageType',
    'ProtocolVersion',
    'ProtocolMessage',
    'MessageValidator',
    'MessageFactory',
    # Payload creators
    'create_hello_payload',
    'create_negotiate_payload',
    'create_auth_payload',
    'create_session_open_payload',
    'create_session_close_payload',
    'create_discover_payload',
    'create_invoke_payload',
    'create_result_payload',
    'create_error_payload',
    'create_consent_request_payload',
    'create_consent_response_payload',
    'create_capability_grant_payload',
    'create_audit_receipt_payload',
    'create_policy_decision_payload',
]
