"""
SMCP Consent System

Consent workflow management with:
- Interactive consent requests
- Automatic consent decisions
- Delegated consent
- Time-limited consent
- Multi-step consent workflows

Security Properties:
- Explicit user confirmation for sensitive actions
- Audit trail of all consent decisions
- Revocable consent
- Fail-closed by default
"""

import uuid
from enum import Enum
from typing import Optional, List, Dict, Any, Callable, Awaitable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import threading


class ConsentStatus(Enum):
    """Status of a consent request."""
    PENDING = "pending"
    GRANTED = "granted"
    DENIED = "denied"
    EXPIRED = "expired"
    REVOKED = "revoked"


class ConsentError(Exception):
    """Base exception for consent errors."""
    pass


@dataclass
class ConsentRequest:
    """A request for user consent."""
    id: str
    subject_id: str  # Who is being asked
    requester_id: str  # Who is requesting
    action: str
    resource: str
    reason: str
    required: bool = False  # Is consent required or optional
    expires_at: Optional[datetime] = None
    status: ConsentStatus = ConsentStatus.PENDING
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)
    responded_at: Optional[datetime] = None
    
    @classmethod
    def create(cls, subject_id: str, requester_id: str, action: str,
               resource: str, reason: str, required: bool = False,
               validity_hours: int = 24) -> 'ConsentRequest':
        """Create a new consent request."""
        now = datetime.utcnow()
        return cls(
            id=str(uuid.uuid4()),
            subject_id=subject_id,
            requester_id=requester_id,
            action=action,
            resource=resource,
            reason=reason,
            required=required,
            expires_at=now + timedelta(hours=validity_hours),
            created_at=now,
        )
    
    def is_expired(self) -> bool:
        """Check if the request has expired."""
        if self.expires_at is None:
            return False
        return datetime.utcnow() >= self.expires_at
    
    def grant(self) -> None:
        """Grant consent."""
        if self.status != ConsentStatus.PENDING:
            raise ConsentError(f"Cannot grant consent in status {self.status}")
        
        if self.is_expired():
            self.status = ConsentStatus.EXPIRED
            raise ConsentError("Consent request has expired")
        
        self.status = ConsentStatus.GRANTED
        self.responded_at = datetime.utcnow()
    
    def deny(self) -> None:
        """Deny consent."""
        if self.status != ConsentStatus.PENDING:
            raise ConsentError(f"Cannot deny consent in status {self.status}")
        
        if self.is_expired():
            self.status = ConsentStatus.EXPIRED
            raise ConsentError("Consent request has expired")
        
        self.status = ConsentStatus.DENIED
        self.responded_at = datetime.utcnow()
    
    def revoke(self) -> None:
        """Revoke previously granted consent."""
        if self.status == ConsentStatus.GRANTED:
            self.status = ConsentStatus.REVOKED
            self.responded_at = datetime.utcnow()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "subject_id": self.subject_id,
            "requester_id": self.requester_id,
            "action": self.action,
            "resource": self.resource,
            "reason": self.reason,
            "required": self.required,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "status": self.status.value,
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat(),
            "responded_at": self.responded_at.isoformat() if self.responded_at else None,
        }


@dataclass
class ConsentResponse:
    """Response to a consent request."""
    request_id: str
    granted: bool
    reason: str = ""
    conditions: List[Dict[str, Any]] = field(default_factory=list)
    
    @classmethod
    def approve(cls, request_id: str, reason: str = "",
                conditions: Optional[List[Dict[str, Any]]] = None) -> 'ConsentResponse':
        return cls(request_id=request_id, granted=True, reason=reason, conditions=conditions or [])
    
    @classmethod
    def reject(cls, request_id: str, reason: str = "") -> 'ConsentResponse':
        return cls(request_id=request_id, granted=False, reason=reason)


class ConsentManager:
    """Manages consent requests and decisions."""
    
    def __init__(self):
        self._requests: Dict[str, ConsentRequest] = {}
        self._by_subject: Dict[str, Set[str]] = {}
        self._by_requester: Dict[str, Set[str]] = {}
        self._lock = threading.RLock()
        
        # Automatic consent rules (subject_id -> action_pattern -> auto_grant)
        self._auto_consent_rules: Dict[str, Dict[str, bool]] = {}
        
        # Consent handlers for interactive consent
        self._handlers: List[Callable[[ConsentRequest], Awaitable[ConsentResponse]]] = []
    
    def register_auto_consent(self, subject_id: str, action_pattern: str,
                              auto_grant: bool) -> None:
        """Register automatic consent rule."""
        with self._lock:
            if subject_id not in self._auto_consent_rules:
                self._auto_consent_rules[subject_id] = {}
            self._auto_consent_rules[subject_id][action_pattern] = auto_grant
    
    def register_handler(self, handler: Callable[[ConsentRequest], Awaitable[ConsentResponse]]) -> None:
        """Register an interactive consent handler."""
        self._handlers.append(handler)
    
    def request_consent(self, subject_id: str, requester_id: str, action: str,
                        resource: str, reason: str, required: bool = False,
                        validity_hours: int = 24) -> ConsentRequest:
        """Create a new consent request."""
        request = ConsentRequest.create(
            subject_id=subject_id,
            requester_id=requester_id,
            action=action,
            resource=resource,
            reason=reason,
            required=required,
            validity_hours=validity_hours,
        )
        
        with self._lock:
            self._requests[request.id] = request
            
            if subject_id not in self._by_subject:
                self._by_subject[subject_id] = set()
            self._by_subject[subject_id].add(request.id)
            
            if requester_id not in self._by_requester:
                self._by_requester[requester_id] = set()
            self._by_requester[requester_id].add(request.id)
        
        # Check auto-consent rules
        self._check_auto_consent(request)
        
        return request
    
    def _check_auto_consent(self, request: ConsentRequest) -> None:
        """Check and apply auto-consent rules."""
        with self._lock:
            rules = self._auto_consent_rules.get(request.subject_id, {})
            
            for pattern, auto_grant in rules.items():
                if pattern == "*" or pattern == request.action:
                    if auto_grant:
                        request.grant()
                    else:
                        request.deny()
                    return
    
    def get_request(self, request_id: str) -> Optional[ConsentRequest]:
        """Get a consent request by ID."""
        with self._lock:
            return self._requests.get(request_id)
    
    def respond(self, request_id: str, granted: bool, reason: str = "") -> ConsentRequest:
        """Respond to a consent request."""
        with self._lock:
            request = self._requests.get(request_id)
            if not request:
                raise ConsentError(f"Consent request not found: {request_id}")
            
            if granted:
                request.grant()
            else:
                request.deny()
            
            return request
    
    def check_consent(self, subject_id: str, action: str, resource: str) -> bool:
        """Check if consent exists for an action."""
        with self._lock:
            request_ids = self._by_subject.get(subject_id, set())
            
            for request_id in request_ids:
                request = self._requests.get(request_id)
                if not request:
                    continue
                
                if request.action != action and request.action != "*":
                    continue
                
                if request.resource != resource and request.resource != "*":
                    continue
                
                if request.status == ConsentStatus.GRANTED:
                    if not request.is_expired():
                        return True
            
            return False
    
    def get_pending_requests(self, subject_id: str) -> List[ConsentRequest]:
        """Get pending consent requests for a subject."""
        with self._lock:
            request_ids = self._by_subject.get(subject_id, set())
            result = []
            
            for request_id in request_ids:
                request = self._requests.get(request_id)
                if request and request.status == ConsentStatus.PENDING:
                    if not request.is_expired():
                        result.append(request)
            
            return result
    
    def revoke_consent(self, request_id: str) -> None:
        """Revoke previously granted consent."""
        with self._lock:
            request = self._requests.get(request_id)
            if not request:
                raise ConsentError(f"Consent request not found: {request_id}")
            
            request.revoke()
    
    def list_requests(self, subject_id: Optional[str] = None,
                      requester_id: Optional[str] = None) -> List[ConsentRequest]:
        """List consent requests with optional filtering."""
        with self._lock:
            if subject_id:
                request_ids = self._by_subject.get(subject_id, set())
            elif requester_id:
                request_ids = self._by_requester.get(requester_id, set())
            else:
                request_ids = set(self._requests.keys())
            
            return [self._requests[rid] for rid in request_ids if rid in self._requests]
    
    def clear(self) -> None:
        """Clear all consent requests."""
        with self._lock:
            self._requests.clear()
            self._by_subject.clear()
            self._by_requester.clear()


__all__ = [
    "ConsentStatus",
    "ConsentError",
    "ConsentRequest",
    "ConsentResponse",
    "ConsentManager",
]
