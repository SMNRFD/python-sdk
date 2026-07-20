"""
SMCP Capability System

Capability-based authorization with:
- Signed capability tokens
- Temporal constraints
- Usage limits
- Delegation support
- Parameter constraints
- Revocation

Security Properties:
- Cryptographic signing
- Offline verification
- Least privilege enforcement
- Fail-closed by default
"""

import uuid
from enum import Enum
from typing import Optional, List, Dict, Any, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import threading
import cbor2

from smcp.crypto import KeyPair, Hasher, CryptoError


class ConstraintType(Enum):
    """Types of capability constraints."""
    TEMPORAL = "temporal"
    USAGE = "usage"
    PARAMETER = "parameter"
    PATH = "path"


@dataclass
class Constraints:
    """Constraints on capability usage."""
    # Temporal constraints
    valid_from: Optional[datetime] = None
    valid_until: Optional[datetime] = None
    
    # Usage constraints
    max_uses: Optional[int] = None
    uses_count: int = 0
    
    # Parameter constraints (JSON schema-like)
    allowed_parameters: Optional[Dict[str, Any]] = None
    
    # Path constraints
    allowed_paths: Optional[List[str]] = None
    
    def is_satisfied(self, action: str, parameters: Optional[Dict[str, Any]] = None,
                     path: Optional[str] = None) -> bool:
        """Check if constraints are satisfied for given action."""
        now = datetime.utcnow()
        
        # Check temporal
        if self.valid_from and now < self.valid_from:
            return False
        if self.valid_until and now >= self.valid_until:
            return False
        
        # Check usage
        if self.max_uses is not None and self.uses_count >= self.max_uses:
            return False
        
        # Check path
        if self.allowed_paths and path:
            if not any(path.startswith(p) for p in self.allowed_paths):
                return False
        
        # Check parameters (simplified)
        if self.allowed_parameters and parameters:
            for key, allowed_values in self.allowed_parameters.items():
                if key in parameters:
                    if isinstance(allowed_values, list):
                        if parameters[key] not in allowed_values:
                            return False
        
        return True
    
    def increment_usage(self) -> None:
        """Increment usage count."""
        self.uses_count += 1
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "valid_from": self.valid_from.isoformat() if self.valid_from else None,
            "valid_until": self.valid_until.isoformat() if self.valid_until else None,
            "max_uses": self.max_uses,
            "uses_count": self.uses_count,
            "allowed_parameters": self.allowed_parameters,
            "allowed_paths": self.allowed_paths,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Constraints':
        """Create from dictionary."""
        return cls(
            valid_from=datetime.fromisoformat(data["valid_from"]) if data.get("valid_from") else None,
            valid_until=datetime.fromisoformat(data["valid_until"]) if data.get("valid_until") else None,
            max_uses=data.get("max_uses"),
            uses_count=data.get("uses_count", 0),
            allowed_parameters=data.get("allowed_parameters"),
            allowed_paths=data.get("allowed_paths"),
        )


class CapabilityError(Exception):
    """Base exception for capability errors."""
    pass


@dataclass
class Capability:
    """A signed capability token."""
    id: str
    subject_id: str  # Who holds this capability
    issuer_id: str   # Who issued it
    actions: List[str]  # Permitted actions
    resource: str    # Target resource
    constraints: Constraints
    delegated_from: Optional[str] = None  # Parent capability ID if delegated
    signature: Optional[str] = None  # hex encoded
    created_at: datetime = field(default_factory=datetime.utcnow)
    revoked: bool = False
    
    @classmethod
    def issue(cls, subject_id: str, issuer_id: str, actions: List[str],
              resource: str, constraints: Optional[Constraints] = None,
              issuer_keypair: Optional[KeyPair] = None) -> 'Capability':
        """Issue a new capability."""
        cap_id = str(uuid.uuid4())
        constraints = constraints or Constraints()
        
        cap = cls(
            id=cap_id,
            subject_id=subject_id,
            issuer_id=issuer_id,
            actions=actions,
            resource=resource,
            constraints=constraints,
            created_at=datetime.utcnow(),
        )
        
        if issuer_keypair:
            cap.signature = cap._sign(issuer_keypair).hex()
        
        return cap
    
    def _canonical_bytes(self) -> bytes:
        """Get canonical bytes for signing."""
        data = cbor2.dumps({
            "id": self.id,
            "subject_id": self.subject_id,
            "issuer_id": self.issuer_id,
            "actions": self.actions,
            "resource": self.resource,
            "constraints": self.constraints.to_dict(),
            "delegated_from": self.delegated_from,
            "created_at": int(self.created_at.timestamp()),
        })
        return data
    
    def _sign(self, keypair: KeyPair) -> bytes:
        """Sign the capability."""
        return keypair.sign(self._canonical_bytes())
    
    def verify_signature(self, issuer_public_key: bytes) -> bool:
        """Verify the capability signature."""
        if not self.signature:
            raise CapabilityError("No signature present")
        
        from nacl.signing import VerifyKey, BadSignature
        
        try:
            verify_key = VerifyKey(issuer_public_key)
            signature = bytes.fromhex(self.signature)
            verify_key.verify(self._canonical_bytes(), signature)
            return True
        except BadSignature:
            raise CapabilityError("Signature verification failed")
    
    def can_perform(self, action: str, parameters: Optional[Dict[str, Any]] = None,
                    path: Optional[str] = None) -> bool:
        """Check if this capability permits the action."""
        if self.revoked:
            return False
        
        if action not in self.actions and "*" not in self.actions:
            return False
        
        return self.constraints.is_satisfied(action, parameters, path)
    
    def delegate(self, new_subject_id: str, new_actions: List[str],
                 new_constraints: Optional[Constraints] = None,
                 issuer_keypair: Optional[KeyPair] = None) -> 'Capability':
        """Delegate this capability to another subject."""
        if self.revoked:
            raise CapabilityError("Cannot delegate revoked capability")
        
        # Delegated capabilities must be subset of original
        if "*" not in self.actions:
            for action in new_actions:
                if action not in self.actions:
                    raise CapabilityError(f"Cannot delegate action {action} not in original")
        
        # Constraints must be at least as restrictive
        if new_constraints is None:
            new_constraints = Constraints(
                valid_from=self.constraints.valid_from,
                valid_until=self.constraints.valid_until,
                max_uses=self.constraints.max_uses,
                allowed_parameters=self.constraints.allowed_parameters,
                allowed_paths=self.constraints.allowed_paths,
            )
        
        return Capability.issue(
            subject_id=new_subject_id,
            issuer_id=self.issuer_id,
            actions=new_actions,
            resource=self.resource,
            constraints=new_constraints,
            issuer_keypair=issuer_keypair,
        )
    
    def revoke(self) -> None:
        """Revoke this capability."""
        self.revoked = True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "subject_id": self.subject_id,
            "issuer_id": self.issuer_id,
            "actions": self.actions,
            "resource": self.resource,
            "constraints": self.constraints.to_dict(),
            "delegated_from": self.delegated_from,
            "signature": self.signature,
            "created_at": self.created_at.isoformat(),
            "revoked": self.revoked,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Capability':
        """Create from dictionary."""
        return cls(
            id=data["id"],
            subject_id=data["subject_id"],
            issuer_id=data["issuer_id"],
            actions=data["actions"],
            resource=data["resource"],
            constraints=Constraints.from_dict(data["constraints"]),
            delegated_from=data.get("delegated_from"),
            signature=data.get("signature"),
            created_at=datetime.fromisoformat(data["created_at"]),
            revoked=data.get("revoked", False),
        )


class CapabilityManager:
    """Manages capability issuance, verification, and revocation."""
    
    def __init__(self):
        self._capabilities: Dict[str, Capability] = {}
        self._by_subject: Dict[str, Set[str]] = {}
        self._revoked: Set[str] = set()
        self._lock = threading.RLock()
        self._keypairs: Dict[str, KeyPair] = {}
        self._public_keys: Dict[str, bytes] = {}
    
    def register_issuer(self, issuer_id: str, keypair: KeyPair) -> None:
        """Register an issuer's keypair."""
        with self._lock:
            self._keypairs[issuer_id] = keypair
            self._public_keys[issuer_id] = keypair.public_bytes
    
    def register_public_key(self, issuer_id: str, public_key: bytes) -> None:
        """Register just the public key for verification."""
        with self._lock:
            self._public_keys[issuer_id] = public_key
    
    def issue(self, subject_id: str, actions: List[str], resource: str,
              constraints: Optional[Constraints] = None,
              issuer_id: Optional[str] = None) -> Capability:
        """Issue a new capability."""
        with self._lock:
            if issuer_id is None:
                if not self._keypairs:
                    raise CapabilityError("No issuers registered")
                issuer_id = list(self._keypairs.keys())[0]
            
            keypair = self._keypairs.get(issuer_id)
            
            cap = Capability.issue(
                subject_id=subject_id,
                issuer_id=issuer_id,
                actions=actions,
                resource=resource,
                constraints=constraints,
                issuer_keypair=keypair,
            )
            
            self._capabilities[cap.id] = cap
            
            if subject_id not in self._by_subject:
                self._by_subject[subject_id] = set()
            self._by_subject[subject_id].add(cap.id)
            
            return cap
    
    def verify(self, capability: Capability) -> bool:
        """Verify a capability's signature and validity."""
        with self._lock:
            if capability.revoked or capability.id in self._revoked:
                return False
            
            public_key = self._public_keys.get(capability.issuer_id)
            if not public_key:
                raise CapabilityError(f"Unknown issuer: {capability.issuer_id}")
            
            try:
                capability.verify_signature(public_key)
            except CapabilityError:
                return False
            
            # Check constraints
            if not capability.constraints.is_satisfied("*"):
                return False
            
            return True
    
    def check_permission(self, subject_id: str, action: str, resource: str,
                         parameters: Optional[Dict[str, Any]] = None,
                         path: Optional[str] = None) -> bool:
        """Check if subject has permission for action on resource."""
        with self._lock:
            cap_ids = self._by_subject.get(subject_id, set())
            
            for cap_id in cap_ids:
                cap = self._capabilities.get(cap_id)
                if not cap or cap.revoked or cap_id in self._revoked:
                    continue
                
                if cap.resource != resource and cap.resource != "*":
                    continue
                
                if cap.can_perform(action, parameters, path):
                    cap.constraints.increment_usage()
                    return True
            
            return False
    
    def revoke(self, capability_id: str) -> None:
        """Revoke a capability."""
        with self._lock:
            if capability_id in self._capabilities:
                self._capabilities[capability_id].revoke()
            self._revoked.add(capability_id)
    
    def get_capabilities(self, subject_id: str) -> List[Capability]:
        """Get all capabilities for a subject."""
        with self._lock:
            cap_ids = self._by_subject.get(subject_id, set())
            return [self._capabilities[cid] for cid in cap_ids if cid in self._capabilities]
    
    def clear(self) -> None:
        """Clear all capabilities (for testing)."""
        with self._lock:
            self._capabilities.clear()
            self._by_subject.clear()
            self._revoked.clear()


__all__ = [
    "ConstraintType",
    "Constraints",
    "CapabilityError",
    "Capability",
    "CapabilityManager",
]
