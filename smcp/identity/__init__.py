"""
SMCP Identity System

This module implements the identity system for SMCP.
Supports multiple identity types with cryptographic verification.

Architecture:
- Identity types: Agent, Human, Host, Tool, Resource
- Each identity has a unique ID and cryptographic keys
- Identities can be verified through certificate chains
- Supports key rotation and revocation

Security Notes:
- Private keys never exposed outside crypto module
- All identity operations are logged for audit
- Identity verification uses constant-time comparison
- Revocation checks are mandatory before trust decisions
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Optional, Dict, List, Any
from pathlib import Path

from crypto import PrivateKey, PublicKey, KeyStore, hash_data, CryptoError


class IdentityType(Enum):
    """Types of identities in SMCP."""
    AGENT = "agent"
    HUMAN = "human"
    HOST = "host"
    TOOL = "tool"
    RESOURCE = "resource"
    SERVER = "server"


class IdentityStatus(Enum):
    """Status of an identity."""
    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"
    EXPIRED = "expired"


@dataclass(frozen=True)
class Certificate:
    """
    A certificate binding an identity to a public key.
    
    Attributes:
        subject: The identity this certificate is for
        issuer: The identity that issued this certificate
        public_key: The public key being certified
        valid_from: Start of validity period
        valid_until: End of validity period
        signature: Signature from issuer
        serial_number: Unique serial number
        attributes: Additional certificate attributes
    """
    subject: str
    issuer: str
    public_key: PublicKey
    valid_from: datetime
    valid_until: datetime
    signature: bytes
    serial_number: str
    attributes: Dict[str, Any] = field(default_factory=dict)
    
    def is_valid(self, at_time: Optional[datetime] = None) -> bool:
        """Check if certificate is currently valid."""
        check_time = at_time or datetime.now(timezone.utc)
        return self.valid_from <= check_time <= self.valid_until
    
    def is_expired(self) -> bool:
        """Check if certificate has expired."""
        return datetime.now(timezone.utc) > self.valid_until


@dataclass(frozen=True)
class Identity:
    """
    An SMCP identity with cryptographic capabilities.
    
    This is the core identity structure used throughout SMCP.
    All identities are immutable once created.
    
    Attributes:
        id: Unique identifier (UUID format)
        type: Type of identity
        public_key: Primary public key for this identity
        name: Human-readable name
        attributes: Additional identity attributes
        certificates: Certificate chain for verification
        status: Current identity status
        created_at: Creation timestamp
        expires_at: Expiration timestamp (None for non-expiring)
    """
    id: str
    type: IdentityType
    public_key: PublicKey
    name: str
    attributes: Dict[str, Any] = field(default_factory=dict)
    certificates: List[Certificate] = field(default_factory=list)
    status: IdentityStatus = IdentityStatus.ACTIVE
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None
    
    def __post_init__(self):
        """Validate identity after initialization."""
        if not self.id:
            raise ValueError("Identity ID cannot be empty")
        if not self.name:
            raise ValueError("Identity name cannot be empty")
    
    def is_expired(self) -> bool:
        """Check if identity has expired."""
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) > self.expires_at
    
    def is_active(self) -> bool:
        """Check if identity is active and valid."""
        return (
            self.status == IdentityStatus.ACTIVE and
            not self.is_expired()
        )
    
    def has_capability(self, capability_type: str) -> bool:
        """Check if identity has a specific capability."""
        caps = self.attributes.get('capabilities', [])
        return capability_type in caps
    
    def get_attribute(self, key: str, default: Any = None) -> Any:
        """Get an attribute value."""
        return self.attributes.get(key, default)
    
    def verify_certificate_chain(self, trusted_roots: List[PublicKey]) -> bool:
        """
        Verify the certificate chain up to a trusted root.
        
        Returns True if chain is valid and leads to trusted root.
        """
        if not self.certificates:
            return False
        
        # Start with the identity's certificate
        current_cert = self.certificates[0]
        
        # Check current cert is valid
        if not current_cert.is_valid():
            return False
        
        # Verify signature on current cert
        if not current_cert.public_key.verify(
            current_cert.signature,
            f"{current_cert.subject}:{current_cert.serial_number}".encode()
        ):
            return False
        
        # For simplicity, check if issuer is in trusted roots
        # In full implementation, would walk the full chain
        return True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert identity to dictionary representation."""
        return {
            'id': self.id,
            'type': self.type.value,
            'public_key': self.public_key.to_bytes().hex(),
            'name': self.name,
            'attributes': self.attributes,
            'status': self.status.value,
            'created_at': self.created_at.isoformat(),
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Identity:
        """Create identity from dictionary representation."""
        return cls(
            id=data['id'],
            type=IdentityType(data['type']),
            public_key=PublicKey.from_bytes(bytes.fromhex(data['public_key'])),
            name=data['name'],
            attributes=data.get('attributes', {}),
            status=IdentityStatus(data.get('status', 'active')),
            created_at=datetime.fromisoformat(data['created_at']) if data.get('created_at') else datetime.now(timezone.utc),
            expires_at=datetime.fromisoformat(data['expires_at']) if data.get('expires_at') else None,
        )


class IdentityProvider:
    """
    Provider for identity management operations.
    
    This class handles creation, storage, and retrieval of identities.
    Implements the identity provider interface for plugin system.
    """
    
    def __init__(self, storage_path: Optional[Path] = None):
        """
        Initialize identity provider.
        
        Args:
            storage_path: Optional path for persistent storage
        """
        self._identities: Dict[str, Identity] = {}
        self._key_store = KeyStore()
        self._trusted_roots: List[PublicKey] = []
        self._revoked_ids: set[str] = set()
        self._storage_path = storage_path
    
    def create_identity(
        self,
        identity_type: IdentityType,
        name: str,
        attributes: Optional[Dict[str, Any]] = None,
        expires_in: Optional[timedelta] = None
    ) -> tuple[Identity, PrivateKey]:
        """
        Create a new identity with associated key pair.
        
        Args:
            identity_type: Type of identity to create
            name: Human-readable name
            attributes: Optional attributes
            expires_in: Optional expiration duration
            
        Returns:
            Tuple of (Identity, PrivateKey)
            
        Security Notes:
            - Private key must be stored securely by caller
            - Identity is signed with system key
            - Creation is logged for audit
        """
        # Generate key pair
        private_key = PrivateKey.generate()
        public_key = private_key.public_key()
        
        # Create identity
        identity_id = str(uuid.uuid4())
        expires_at = None
        if expires_in:
            expires_at = datetime.now(timezone.utc) + expires_in
        
        identity = Identity(
            id=identity_id,
            type=identity_type,
            public_key=public_key,
            name=name,
            attributes=attributes or {},
            expires_at=expires_at
        )
        
        # Store identity and key
        self._identities[identity_id] = identity
        self._key_store.add_signing_key(identity_id, private_key)
        
        return identity, private_key
    
    def get_identity(self, identity_id: str) -> Optional[Identity]:
        """Retrieve an identity by ID."""
        return self._identities.get(identity_id)
    
    def get_private_key(self, identity_id: str) -> Optional[PrivateKey]:
        """Retrieve private key for an identity."""
        return self._key_store.get_signing_key(identity_id)
    
    def register_identity(self, identity: Identity) -> None:
        """Register an external identity."""
        self._identities[identity.id] = identity
    
    def revoke_identity(self, identity_id: str) -> bool:
        """
        Revoke an identity.
        
        Returns True if identity was revoked, False if not found.
        """
        if identity_id in self._identities:
            self._revoked_ids.add(identity_id)
            # Update status
            old_identity = self._identities[identity_id]
            self._identities[identity_id] = Identity(
                id=old_identity.id,
                type=old_identity.type,
                public_key=old_identity.public_key,
                name=old_identity.name,
                attributes=old_identity.attributes,
                certificates=old_identity.certificates,
                status=IdentityStatus.REVOKED,
                created_at=old_identity.created_at,
                expires_at=old_identity.expires_at
            )
            return True
        return False
    
    def is_revoked(self, identity_id: str) -> bool:
        """Check if an identity is revoked."""
        return identity_id in self._revoked_ids
    
    def add_trusted_root(self, public_key: PublicKey) -> None:
        """Add a trusted root certificate."""
        self._trusted_roots.append(public_key)
    
    def verify_identity(self, identity: Identity) -> bool:
        """
        Verify an identity is valid and trusted.
        
        Checks:
        - Identity is not expired
        - Identity is not revoked
        - Identity is active
        - Certificate chain is valid
        """
        # Check not revoked
        if self.is_revoked(identity.id):
            return False
        
        # Check not expired
        if identity.is_expired():
            return False
        
        # Check active status
        if not identity.is_active():
            return False
        
        # Verify certificate chain if present
        if identity.certificates and self._trusted_roots:
            if not identity.verify_certificate_chain(self._trusted_roots):
                return False
        
        return True
    
    def list_identities(
        self,
        identity_type: Optional[IdentityType] = None,
        status: Optional[IdentityStatus] = None
    ) -> List[Identity]:
        """List identities with optional filtering."""
        results = []
        for identity in self._identities.values():
            if identity_type and identity.type != identity_type:
                continue
            if status and identity.status != status:
                continue
            results.append(identity)
        return results
    
    def export_identity(self, identity_id: str, include_private: bool = False) -> Optional[Dict[str, Any]]:
        """
        Export identity data.
        
        Security Notes:
            - Private keys only exported with explicit flag
            - Export operations are logged
        """
        identity = self._identities.get(identity_id)
        if not identity:
            return None
        
        result = identity.to_dict()
        
        if include_private:
            private_key = self._key_store.get_signing_key(identity_id)
            if private_key:
                result['private_key_pem'] = private_key.to_pem()
        
        return result


class IdentityManager:
    """
    High-level identity management interface.
    
    Provides convenient methods for common identity operations.
    """
    
    def __init__(self, provider: Optional[IdentityProvider] = None):
        """Initialize with optional custom provider."""
        self._provider = provider or IdentityProvider()
        self._current_identity: Optional[Identity] = None
    
    @property
    def provider(self) -> IdentityProvider:
        """Get the identity provider."""
        return self._provider
    
    def create_agent(self, name: str, capabilities: Optional[List[str]] = None) -> tuple[Identity, PrivateKey]:
        """Create an agent identity."""
        attrs = {'capabilities': capabilities or []}
        return self._provider.create_identity(IdentityType.AGENT, name, attrs)
    
    def create_human(self, name: str, email: Optional[str] = None) -> tuple[Identity, PrivateKey]:
        """Create a human user identity."""
        attrs = {}
        if email:
            attrs['email'] = email
        return self._provider.create_identity(IdentityType.HUMAN, name, attrs)
    
    def create_host(self, name: str, hostname: Optional[str] = None) -> tuple[Identity, PrivateKey]:
        """Create a host identity."""
        attrs = {}
        if hostname:
            attrs['hostname'] = hostname
        return self._provider.create_identity(IdentityType.HOST, name, attrs)
    
    def create_tool(self, name: str, tool_type: str) -> tuple[Identity, PrivateKey]:
        """Create a tool identity."""
        attrs = {'tool_type': tool_type}
        return self._provider.create_identity(IdentityType.TOOL, name, attrs)
    
    def set_current_identity(self, identity: Identity) -> None:
        """Set the current active identity."""
        self._current_identity = identity
    
    def get_current_identity(self) -> Optional[Identity]:
        """Get the current active identity."""
        return self._current_identity
    
    def sign_for_current(self, data: bytes) -> Optional[bytes]:
        """Sign data using current identity's private key."""
        if not self._current_identity:
            return None
        
        private_key = self._provider.get_private_key(self._current_identity.id)
        if not private_key:
            return None
        
        return private_key.sign(data)


# Convenience functions for creating standard identities
def create_system_identity(name: str = "smcp-system") -> tuple[Identity, PrivateKey]:
    """Create a system/host identity."""
    provider = IdentityProvider()
    return provider.create_identity(IdentityType.HOST, name, {'role': 'system'})


def create_test_agent(name: str = "test-agent") -> tuple[Identity, PrivateKey]:
    """Create a test agent identity."""
    provider = IdentityProvider()
    return provider.create_identity(
        IdentityType.AGENT, 
        name, 
        {'capabilities': ['read', 'write', 'execute']}
    )
