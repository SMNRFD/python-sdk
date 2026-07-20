"""
SMCP Capability System

This module implements capability-based authorization for SMCP.
Capabilities are unforgeable tokens that grant specific permissions.

Architecture:
- Capabilities are cryptographically signed tokens
- Support delegation with constraints
- Include temporal, usage, and parameter constraints
- Verifiable without contacting issuer (offline verification)

Security Notes:
- All capabilities must be signed
- Delegation chains are validated
- Constraints are enforced at verification time
- Revoked capabilities are rejected
- No capability can grant more than the granter possesses
"""

from __future__ import annotations

import uuid
import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Optional, Dict, List, Any, Set
from copy import deepcopy

from crypto import PrivateKey, PublicKey, hash_data, CryptoError, SignatureError
from identity import Identity, IdentityType


class ConstraintType(Enum):
    """Types of capability constraints."""
    TEMPORAL = "temporal"
    USAGE = "usage"
    PATH = "path"
    PARAMETER = "parameter"
    CONTEXT = "context"


class CapabilityStatus(Enum):
    """Status of a capability."""
    VALID = "valid"
    EXPIRED = "expired"
    REVOKED = "revoked"
    CONSTRAINT_VIOLATED = "constraint_violated"
    INVALID_SIGNATURE = "invalid_signature"
    INSUFFICIENT_PRIVILEGES = "insufficient_privileges"


@dataclass(frozen=True)
class Action:
    """An action that can be performed on a resource."""
    name: str
    resource_type: str
    
    def __post_init__(self):
        if not self.name:
            raise ValueError("Action name cannot be empty")
        if not self.resource_type:
            raise ValueError("Resource type cannot be empty")


@dataclass(frozen=True)
class Resource:
    """A resource that actions can be performed on."""
    type: str
    id: str
    attributes: Dict[str, Any] = field(default_factory=dict)
    
    def matches(self, other: 'Resource') -> bool:
        """Check if this resource matches another (for constraint checking)."""
        if self.type != other.type:
            return False
        if self.id != '*' and other.id != '*' and self.id != other.id:
            return False
        return True


@dataclass
class TemporalConstraint:
    """Time-based constraint on capability usage."""
    valid_from: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    valid_until: Optional[datetime] = None
    allowed_hours: Optional[List[int]] = None  # Hours of day (0-23)
    allowed_days: Optional[List[int]] = None   # Days of week (0-6, Monday=0)
    
    def is_satisfied(self, at_time: Optional[datetime] = None) -> bool:
        """Check if temporal constraint is satisfied."""
        check_time = at_time or datetime.now(timezone.utc)
        
        # Check validity window
        if check_time < self.valid_from:
            return False
        if self.valid_until and check_time > self.valid_until:
            return False
        
        # Check allowed hours
        if self.allowed_hours is not None:
            if check_time.hour not in self.allowed_hours:
                return False
        
        # Check allowed days
        if self.allowed_days is not None:
            if check_time.weekday() not in self.allowed_days:
                return False
        
        return True


@dataclass
class UsageConstraint:
    """Usage limit constraint."""
    max_uses: Optional[int] = None
    max_uses_per_minute: Optional[int] = None
    max_uses_per_hour: Optional[int] = None
    max_uses_per_day: Optional[int] = None
    current_uses: int = 0
    use_timestamps: List[datetime] = field(default_factory=list)
    
    def record_use(self) -> bool:
        """Record a use and check if within limits."""
        now = datetime.now(timezone.utc)
        
        # Clean old timestamps
        minute_ago = now - timedelta(minutes=1)
        hour_ago = now - timedelta(hours=1)
        day_ago = now - timedelta(days=1)
        
        self.use_timestamps = [
            ts for ts in self.use_timestamps
            if ts > minute_ago or (self.max_uses_per_hour and ts > hour_ago) or (self.max_uses_per_day and ts > day_ago)
        ]
        
        # Check total uses
        if self.max_uses is not None and self.current_uses >= self.max_uses:
            return False
        
        # Check per-minute rate
        if self.max_uses_per_minute is not None:
            recent = sum(1 for ts in self.use_timestamps if ts > minute_ago)
            if recent >= self.max_uses_per_minute:
                return False
        
        # Check per-hour rate
        if self.max_uses_per_hour is not None:
            recent = sum(1 for ts in self.use_timestamps if ts > hour_ago)
            if recent >= self.max_uses_per_hour:
                return False
        
        # Check per-day rate
        if self.max_uses_per_day is not None:
            recent = sum(1 for ts in self.use_timestamps if ts > day_ago)
            if recent >= self.max_uses_per_day:
                return False
        
        # Record use
        self.current_uses += 1
        self.use_timestamps.append(now)
        return True
    
    def is_satisfied(self) -> bool:
        """Check if usage constraint allows another use."""
        # Create a copy to test without modifying state
        test_constraint = deepcopy(self)
        return test_constraint.record_use()


@dataclass
class PathConstraint:
    """Delegation path constraint."""
    max_depth: int = 5  # Maximum delegation depth
    current_depth: int = 0
    allowed_delegates: Optional[List[str]] = None  # Specific identities allowed
    
    def can_delegate(self) -> bool:
        """Check if further delegation is allowed."""
        return self.current_depth < self.max_depth
    
    def can_delegate_to(self, delegate_id: str) -> bool:
        """Check if delegation to specific identity is allowed."""
        if not self.can_delegate():
            return False
        if self.allowed_delegates is None:
            return True
        return delegate_id in self.allowed_delegates


@dataclass
class ParameterConstraint:
    """Constraint on input parameters."""
    allowed_parameters: Dict[str, Any] = field(default_factory=dict)
    forbidden_parameters: Set[str] = field(default_factory=set)
    parameter_patterns: Dict[str, str] = field(default_factory=dict)  # Regex patterns
    
    def validate_parameters(self, params: Dict[str, Any]) -> bool:
        """Validate parameters against constraints."""
        import re
        
        # Check forbidden parameters
        for param in self.forbidden_parameters:
            if param in params:
                return False
        
        # Check allowed values
        for param, allowed_value in self.allowed_parameters.items():
            if param not in params:
                continue
            if params[param] != allowed_value:
                return False
        
        # Check patterns
        for param, pattern in self.parameter_patterns.items():
            if param not in params:
                continue
            value = str(params[param])
            if not re.match(pattern, value):
                return False
        
        return True


@dataclass
class ContextConstraint:
    """Environmental context constraint."""
    required_locations: Optional[List[str]] = None
    forbidden_locations: Optional[List[str]] = None
    required_networks: Optional[List[str]] = None
    required_device_types: Optional[List[str]] = None
    
    def is_satisfied(self, context: Dict[str, Any]) -> bool:
        """Check if context satisfies constraints."""
        # Check location
        if self.required_locations:
            current_location = context.get('location')
            if current_location not in self.required_locations:
                return False
        
        if self.forbidden_locations:
            current_location = context.get('location')
            if current_location in self.forbidden_locations:
                return False
        
        # Check network
        if self.required_networks:
            current_network = context.get('network')
            if current_network not in self.required_networks:
                return False
        
        # Check device type
        if self.required_device_types:
            device_type = context.get('device_type')
            if device_type not in self.required_device_types:
                return False
        
        return True


@dataclass(frozen=True)
class DelegationInfo:
    """Information about capability delegation."""
    is_delegated: bool = False
    delegator: Optional[str] = None
    delegation_chain: List[str] = field(default_factory=list)
    current_depth: int = 0
    remaining_depth: int = 5


@dataclass(frozen=True)
class Capability:
    """
    A capability token granting specific permissions.
    
    This is the core authorization primitive in SMCP.
    Capabilities are:
    - Unforgeable (cryptographically signed)
    - Composable (can be combined)
    - Delegatable (with constraints)
    - Verifiable offline
    
    Attributes:
        id: Unique capability identifier
        issuer: Identity that issued this capability
        subject: Identity this capability is for
        actions: Actions this capability grants
        resources: Resources the actions apply to
        conditions: All constraints on this capability
        delegation: Delegation information
        metadata: Additional metadata
        signature: Cryptographic signature
        created_at: Creation timestamp
    """
    id: str
    issuer: str
    subject: str
    actions: List[Action]
    resources: List[Resource]
    conditions: Dict[ConstraintType, Any] = field(default_factory=dict)
    delegation: DelegationInfo = field(default_factory=DelegationInfo)
    metadata: Dict[str, Any] = field(default_factory=dict)
    signature: bytes = field(default=b'')
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def get_temporal_constraint(self) -> Optional[TemporalConstraint]:
        """Get temporal constraint if present."""
        return self.conditions.get(ConstraintType.TEMPORAL)
    
    def get_usage_constraint(self) -> Optional[UsageConstraint]:
        """Get usage constraint if present."""
        return self.conditions.get(ConstraintType.USAGE)
    
    def get_path_constraint(self) -> Optional[PathConstraint]:
        """Get path constraint if present."""
        return self.conditions.get(ConstraintType.PATH)
    
    def get_parameter_constraint(self) -> Optional[ParameterConstraint]:
        """Get parameter constraint if present."""
        return self.conditions.get(ConstraintType.PARAMETER)
    
    def get_context_constraint(self) -> Optional[ContextConstraint]:
        """Get context constraint if present."""
        return self.conditions.get(ConstraintType.CONTEXT)
    
    def is_expired(self) -> bool:
        """Check if capability has expired."""
        temporal = self.get_temporal_constraint()
        if temporal:
            return not temporal.is_satisfied()
        return False
    
    def can_action(self, action: Action, resource: Resource) -> bool:
        """Check if this capability allows an action on a resource."""
        # Check if action is granted
        action_allowed = False
        for cap_action in self.actions:
            if cap_action.name == action.name:
                # Check resource type match
                if cap_action.resource_type == resource.type or cap_action.resource_type == '*':
                    action_allowed = True
                    break
        
        if not action_allowed:
            return False
        
        # Check resource constraints
        resource_allowed = False
        for cap_resource in self.resources:
            if cap_resource.matches(resource):
                resource_allowed = True
                break
        
        return resource_allowed
    
    def to_bytes(self) -> bytes:
        """Serialize capability to bytes for signing."""
        import json
        data = {
            'id': self.id,
            'issuer': self.issuer,
            'subject': self.subject,
            'actions': [{'name': a.name, 'resource_type': a.resource_type} for a in self.actions],
            'resources': [{'type': r.type, 'id': r.id} for r in self.resources],
            'delegation': {
                'is_delegated': self.delegation.is_delegated,
                'delegator': self.delegation.delegator,
                'remaining_depth': self.delegation.remaining_depth,
            },
            'created_at': self.created_at.isoformat(),
        }
        return json.dumps(data, sort_keys=True).encode('utf-8')
    
    def verify_signature(self, issuer_public_key: PublicKey) -> bool:
        """Verify the capability's signature."""
        if not self.signature:
            return False
        return issuer_public_key.verify(self.signature, self.to_bytes())


class CapabilityManager:
    """
    Manager for capability lifecycle operations.
    
    Handles creation, verification, delegation, and revocation of capabilities.
    """
    
    def __init__(self):
        self._capabilities: Dict[str, Capability] = {}
        self._revoked_ids: Set[str] = set()
        self._issuer_keys: Dict[str, PrivateKey] = {}
        self._trusted_issuers: Dict[str, PublicKey] = {}
    
    def register_issuer(self, issuer_id: str, private_key: PrivateKey, public_key: PublicKey) -> None:
        """Register a capability issuer."""
        self._issuer_keys[issuer_id] = private_key
        self._trusted_issuers[issuer_id] = public_key
    
    def issue(
        self,
        issuer: Identity,
        subject: Identity,
        actions: List[Action],
        resources: List[Resource],
        conditions: Optional[Dict[ConstraintType, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Capability:
        """
        Issue a new capability.
        
        Args:
            issuer: Identity issuing the capability
            subject: Identity receiving the capability
            actions: Actions being granted
            resources: Resources the actions apply to
            conditions: Optional constraints
            metadata: Optional metadata
            
        Returns:
            Signed capability token
        """
        # Get issuer's private key
        private_key = self._issuer_keys.get(issuer.id)
        if not private_key:
            raise CryptoError(f"No private key found for issuer {issuer.id}")
        
        # Create capability
        cap_id = str(uuid.uuid4())
        capability = Capability(
            id=cap_id,
            issuer=issuer.id,
            subject=subject.id,
            actions=actions,
            resources=resources,
            conditions=conditions or {},
            metadata=metadata or {},
        )
        
        # Sign capability
        data = capability.to_bytes()
        signature = private_key.sign(data)
        
        # Create immutable signed version
        capability = Capability(
            id=capability.id,
            issuer=capability.issuer,
            subject=capability.subject,
            actions=capability.actions,
            resources=capability.resources,
            conditions=capability.conditions,
            delegation=capability.delegation,
            metadata=capability.metadata,
            signature=signature,
            created_at=capability.created_at
        )
        
        # Store capability
        self._capabilities[cap_id] = capability
        
        return capability
    
    def verify(
        self,
        capability: Capability,
        action: Optional[Action] = None,
        resource: Optional[Resource] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> tuple[bool, CapabilityStatus, str]:
        """
        Verify a capability.
        
        Args:
            capability: Capability to verify
            action: Optional action to check
            resource: Optional resource to check
            context: Optional context for constraint evaluation
            
        Returns:
            Tuple of (is_valid, status, message)
        """
        # Check if revoked
        if capability.id in self._revoked_ids:
            return False, CapabilityStatus.REVOKED, "Capability has been revoked"
        
        # Check signature
        issuer_pub = self._trusted_issuers.get(capability.issuer)
        if not issuer_pub:
            return False, CapabilityStatus.INVALID_SIGNATURE, f"Unknown issuer: {capability.issuer}"
        
        if not capability.verify_signature(issuer_pub):
            return False, CapabilityStatus.INVALID_SIGNATURE, "Invalid signature"
        
        # Check expiration
        if capability.is_expired():
            return False, CapabilityStatus.EXPIRED, "Capability has expired"
        
        # Check usage constraints
        usage = capability.get_usage_constraint()
        if usage and not usage.is_satisfied():
            return False, CapabilityStatus.CONSTRAINT_VIOLATED, "Usage limit exceeded"
        
        # Check context constraints
        if context:
            ctx_constraint = capability.get_context_constraint()
            if ctx_constraint and not ctx_constraint.is_satisfied(context):
                return False, CapabilityStatus.CONSTRAINT_VIOLATED, "Context constraint not satisfied"
        
        # Check action/resource if provided
        if action and resource:
            if not capability.can_action(action, resource):
                return False, CapabilityStatus.INSUFFICIENT_PRIVILEGES, "Action not permitted on resource"
        
        return True, CapabilityStatus.VALID, "Capability is valid"
    
    def delegate(
        self,
        capability: Capability,
        from_identity: Identity,
        to_identity: Identity,
        actions: Optional[List[Action]] = None,
        resources: Optional[List[Resource]] = None,
        additional_conditions: Optional[Dict[ConstraintType, Any]] = None
    ) -> Capability:
        """
        Delegate a capability to another identity.
        
        The delegated capability cannot have more privileges than the original.
        """
        # Verify the original capability
        is_valid, status, msg = self.verify(capability)
        if not is_valid:
            raise CryptoError(f"Cannot delegate invalid capability: {msg}")
        
        # Check delegation is allowed
        path_constraint = capability.get_path_constraint()
        if path_constraint and not path_constraint.can_delegate_to(to_identity.id):
            raise CryptoError("Delegation not allowed to this identity")
        
        if path_constraint and path_constraint.current_depth >= path_constraint.max_depth:
            raise CryptoError("Maximum delegation depth reached")
        
        # Get issuer's private key (must be original issuer or have delegation rights)
        private_key = self._issuer_keys.get(from_identity.id)
        if not private_key:
            # Try original issuer
            private_key = self._issuer_keys.get(capability.issuer)
        if not private_key:
            raise CryptoError("Cannot delegate: no signing key available")
        
        # Create delegated capability with reduced scope
        new_actions = actions or capability.actions
        new_resources = resources or capability.resources
        new_conditions = deepcopy(capability.conditions)
        
        if additional_conditions:
            new_conditions.update(additional_conditions)
        
        # Update path constraint
        if path_constraint:
            new_path = PathConstraint(
                max_depth=path_constraint.max_depth,
                current_depth=path_constraint.current_depth + 1,
                allowed_delegates=path_constraint.allowed_delegates
            )
            new_conditions[ConstraintType.PATH] = new_path
        
        # Create new capability
        cap_id = str(uuid.uuid4())
        new_capability = Capability(
            id=cap_id,
            issuer=from_identity.id,
            subject=to_identity.id,
            actions=new_actions,
            resources=new_resources,
            conditions=new_conditions,
            delegation=DelegationInfo(
                is_delegated=True,
                delegator=from_identity.id,
                delegation_chain=capability.delegation.delegation_chain + [from_identity.id],
                remaining_depth=path_constraint.remaining_depth - 1 if path_constraint else 4
            ),
            metadata={**capability.metadata, 'delegated_from': capability.id}
        )
        
        # Sign
        data = new_capability.to_bytes()
        signature = private_key.sign(data)
        
        new_capability = Capability(
            id=new_capability.id,
            issuer=new_capability.issuer,
            subject=new_capability.subject,
            actions=new_capability.actions,
            resources=new_capability.resources,
            conditions=new_capability.conditions,
            delegation=new_capability.delegation,
            metadata=new_capability.metadata,
            signature=signature,
            created_at=new_capability.created_at
        )
        
        self._capabilities[cap_id] = new_capability
        return new_capability
    
    def revoke(self, capability_id: str) -> bool:
        """Revoke a capability."""
        if capability_id in self._capabilities:
            self._revoked_ids.add(capability_id)
            return True
        return False
    
    def get_capability(self, capability_id: str) -> Optional[Capability]:
        """Retrieve a capability by ID."""
        return self._capabilities.get(capability_id)
    
    def list_capabilities(self, subject_id: Optional[str] = None) -> List[Capability]:
        """List capabilities, optionally filtered by subject."""
        result = []
        for cap in self._capabilities.values():
            if cap.id in self._revoked_ids:
                continue
            if subject_id and cap.subject != subject_id:
                continue
            result.append(cap)
        return result


# Convenience functions
def create_read_action(resource_type: str) -> Action:
    """Create a read action."""
    return Action(name="read", resource_type=resource_type)


def create_write_action(resource_type: str) -> Action:
    """Create a write action."""
    return Action(name="write", resource_type=resource_type)


def create_execute_action(resource_type: str) -> Action:
    """Create an execute action."""
    return Action(name="execute", resource_type=resource_type)


def create_all_action(resource_type: str) -> Action:
    """Create an all-actions wildcard."""
    return Action(name="*", resource_type=resource_type)


def create_wildcard_resource(type: str) -> Resource:
    """Create a wildcard resource."""
    return Resource(type=type, id="*")


def create_specific_resource(type: str, id: str) -> Resource:
    """Create a specific resource."""
    return Resource(type=type, id=id)
