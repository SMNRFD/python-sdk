"""
SMCP Identity System

Identity management and certificates supporting:
- Agent identities (autonomous software)
- Human identities (users)
- Host identities (server systems)
- Server identities (service endpoints)
- Tool identities (individual capabilities)
- Resource identities (protected resources)

Security Properties:
- Cryptographic binding to key pairs
- Certificate chain validation
- Revocation checking
- Strict expiration enforcement
"""

import uuid
from enum import Enum
from typing import Optional, List, Dict, Any, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import threading
import cbor2

from smcp.crypto import KeyPair, CryptoError


class IdentityType(Enum):
    """Types of identities in SMCP."""
    AGENT = "agent"
    HUMAN = "human"
    HOST = "host"
    SERVER = "server"
    TOOL = "tool"
    RESOURCE = "resource"


class IdentityError(Exception):
    """Base exception for identity errors."""
    pass


@dataclass
class Identity:
    """Identity certificate structure."""
    id: str
    identity_type: IdentityType
    name: str
    public_key: str  # hex encoded
    algorithm: str
    issuer_id: Optional[str]
    subject_alt_names: List[str]
    valid_from: datetime
    valid_until: datetime
    revoked: bool = False
    revocation_reason: Optional[str] = None
    revoked_at: Optional[datetime] = None
    metadata: Dict[str, str] = field(default_factory=dict)
    signature: Optional[str] = None  # hex encoded
    
    @classmethod
    def new_root(cls, name: str, identity_type: IdentityType, keypair: KeyPair,
                 validity_days: int = 365) -> 'Identity':
        """Create a new self-signed root identity."""
        identity_id = str(uuid.uuid4())
        now = datetime.utcnow()
        
        identity = cls(
            id=identity_id,
            identity_type=identity_type,
            name=name,
            public_key=keypair.public_bytes.hex(),
            algorithm="Ed25519",
            issuer_id=None,
            subject_alt_names=[],
            valid_from=now,
            valid_until=now + timedelta(days=validity_days),
        )
        
        # Self-sign
        identity.signature = identity._sign(keypair).hex()
        
        return identity
    
    @classmethod
    def new_signed(cls, name: str, identity_type: IdentityType, keypair: KeyPair,
                   issuer: 'Identity', issuer_keypair: KeyPair,
                   validity_days: int = 30,
                   subject_alt_names: Optional[List[str]] = None) -> 'Identity':
        """Create a new identity signed by an issuer."""
        if issuer.revoked:
            raise IdentityError(f"Issuer identity {issuer.id} is revoked")
        
        if issuer.valid_until <= datetime.utcnow():
            raise IdentityError(f"Issuer identity {issuer.id} has expired")
        
        identity_id = str(uuid.uuid4())
        now = datetime.utcnow()
        
        # Don't exceed issuer's validity
        requested_end = now + timedelta(days=validity_days)
        valid_until = min(requested_end, issuer.valid_until)
        
        identity = cls(
            id=identity_id,
            identity_type=identity_type,
            name=name,
            public_key=keypair.public_bytes.hex(),
            algorithm="Ed25519",
            issuer_id=issuer.id,
            subject_alt_names=subject_alt_names or [],
            valid_from=now,
            valid_until=valid_until,
        )
        
        # Sign with issuer's key
        identity.signature = identity._sign(issuer_keypair).hex()
        
        return identity
    
    def _canonical_bytes(self) -> bytes:
        """Get canonical bytes for signing."""
        data = cbor2.dumps({
            "id": self.id,
            "type": self.identity_type.value,
            "name": self.name,
            "public_key": self.public_key,
            "algorithm": self.algorithm,
            "issuer_id": self.issuer_id,
            "sans": self.subject_alt_names,
            "valid_from": int(self.valid_from.timestamp()),
            "valid_until": int(self.valid_until.timestamp()),
        })
        return data
    
    def _sign(self, keypair: KeyPair) -> bytes:
        """Sign the identity."""
        return keypair.sign(self._canonical_bytes())
    
    def verify_signature(self, issuer_public_key: bytes) -> bool:
        """Verify the identity signature."""
        if not self.signature:
            raise IdentityError("No signature present")
        
        from nacl.signing import VerifyKey, BadSignature
        
        try:
            verify_key = VerifyKey(issuer_public_key)
            signature = bytes.fromhex(self.signature)
            verify_key.verify(self._canonical_bytes(), signature)
            return True
        except BadSignature:
            raise IdentityError("Signature verification failed")
        except Exception as e:
            raise IdentityError(f"Signature verification error: {e}")
    
    def is_valid(self) -> bool:
        """Check if identity is currently valid."""
        now = datetime.utcnow()
        
        if self.revoked:
            raise IdentityError(f"Identity {self.id} is revoked")
        
        if now < self.valid_from:
            raise IdentityError(f"Identity {self.id} not yet valid")
        
        if now >= self.valid_until:
            raise IdentityError(f"Identity {self.id} has expired")
        
        return True
    
    def revoke(self, reason: str, keypair: KeyPair) -> None:
        """Revoke the identity."""
        self.revoked = True
        self.revocation_reason = reason
        self.revoked_at = datetime.utcnow()
        
        # Re-sign to include revocation status
        self.signature = self._sign(keypair).hex()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "identity_type": self.identity_type.value,
            "name": self.name,
            "public_key": self.public_key,
            "algorithm": self.algorithm,
            "issuer_id": self.issuer_id,
            "subject_alt_names": self.subject_alt_names,
            "valid_from": self.valid_from.isoformat(),
            "valid_until": self.valid_until.isoformat(),
            "revoked": self.revoked,
            "revocation_reason": self.revocation_reason,
            "metadata": self.metadata,
            "signature": self.signature,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Identity':
        """Create from dictionary."""
        return cls(
            id=data["id"],
            identity_type=IdentityType(data["identity_type"]),
            name=data["name"],
            public_key=data["public_key"],
            algorithm=data["algorithm"],
            issuer_id=data.get("issuer_id"),
            subject_alt_names=data.get("subject_alt_names", []),
            valid_from=datetime.fromisoformat(data["valid_from"]),
            valid_until=datetime.fromisoformat(data["valid_until"]),
            revoked=data.get("revoked", False),
            revocation_reason=data.get("revocation_reason"),
            metadata=data.get("metadata", {}),
            signature=data.get("signature"),
        )


class IdentityManager:
    """Manages identities, trust anchors, and revocation."""
    
    def __init__(self):
        self._identities: Dict[str, Identity] = {}
        self._revocation_list: Dict[str, datetime] = {}
        self._trust_anchors: Set[str] = set()
        self._lock = threading.RLock()
        self._keypairs: Dict[str, KeyPair] = {}  # In production, use HSM
    
    def add_trust_anchor(self, identity: Identity) -> None:
        """Register a trust anchor (root CA)."""
        if identity.issuer_id is not None:
            raise IdentityError("Only root identities can be trust anchors")
        
        identity.is_valid()
        
        with self._lock:
            self._identities[identity.id] = identity
            self._trust_anchors.add(identity.id)
    
    def register(self, identity: Identity) -> None:
        """Register an identity."""
        identity.is_valid()
        
        with self._lock:
            # Verify signature if not a root
            if identity.issuer_id:
                issuer = self._identities.get(identity.issuer_id)
                if not issuer:
                    raise IdentityError(f"Issuer {identity.issuer_id} not found")
                
                issuer_pk = bytes.fromhex(issuer.public_key)
                identity.verify_signature(issuer_pk)
            
            if identity.id in self._identities:
                raise IdentityError(f"Duplicate identity: {identity.id}")
            
            self._identities[identity.id] = identity
    
    def get(self, identity_id: str) -> Optional[Identity]:
        """Get an identity by ID."""
        with self._lock:
            return self._identities.get(identity_id)
    
    def validate(self, identity_id: str) -> Identity:
        """Validate an identity including chain verification."""
        with self._lock:
            identity = self._identities.get(identity_id)
            if not identity:
                raise IdentityError(f"Identity not found: {identity_id}")
            
            # Check revocation
            if identity_id in self._revocation_list:
                raise IdentityError(f"Identity {identity_id} is revoked")
            
            # Check validity
            identity.is_valid()
            
            # Verify chain
            self._verify_chain(identity)
            
            return identity
    
    def _verify_chain(self, identity: Identity) -> None:
        """Verify certificate chain to trust anchor."""
        visited: Set[str] = set()
        current = identity
        
        while True:
            if current.id in visited:
                raise IdentityError("Circular certificate chain detected")
            visited.add(current.id)
            
            # Check if trust anchor
            if current.id in self._trust_anchors:
                return
            
            # Get issuer
            if not current.issuer_id:
                raise IdentityError("Chain does not lead to trust anchor")
            
            issuer = self._identities.get(current.issuer_id)
            if not issuer:
                raise IdentityError(f"Issuer {current.issuer_id} not found")
            
            # Verify issuer's signature
            issuer_pk = bytes.fromhex(issuer.public_key)
            current.verify_signature(issuer_pk)
            
            current = issuer
    
    def revoke(self, identity_id: str, reason: str) -> None:
        """Revoke an identity."""
        with self._lock:
            identity = self._identities.get(identity_id)
            if not identity:
                raise IdentityError(f"Identity not found: {identity_id}")
            
            # In production, would need proper authorization
            identity.revoked = True
            identity.revocation_reason = reason
            identity.revoked_at = datetime.utcnow()
            
            self._revocation_list[identity_id] = datetime.utcnow()
    
    def list(self) -> List[Identity]:
        """List all registered identities."""
        with self._lock:
            return list(self._identities.values())
    
    def clear(self) -> None:
        """Clear all identities (for testing)."""
        with self._lock:
            self._identities.clear()
            self._revocation_list.clear()
            self._trust_anchors.clear()


__all__ = [
    "IdentityType",
    "IdentityError",
    "Identity",
    "IdentityManager",
]
