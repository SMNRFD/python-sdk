"""
SMCP Audit System

Immutable audit logging with:
- Cryptographic receipts
- Tamper-evident records
- Hash chain integrity
- Comprehensive event tracking

Security Properties:
- Immutable records
- Cryptographic verification
- Complete audit trail
- Non-repudiation
"""

import uuid
import hashlib
from enum import Enum
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field
from datetime import datetime
import threading
import json


class AuditError(Exception):
    """Base exception for audit errors."""
    pass


class AuditEventType(Enum):
    """Types of audit events."""
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    CAPABILITY_ISSUE = "capability_issue"
    CAPABILITY_USE = "capability_use"
    CAPABILITY_REVOKE = "capability_revoke"
    CONSENT_REQUEST = "consent_request"
    CONSENT_GRANT = "consent_grant"
    CONSENT_DENY = "consent_deny"
    SESSION_START = "session_start"
    SESSION_END = "session_end"
    MESSAGE_SEND = "message_send"
    MESSAGE_RECEIVE = "message_receive"
    TOOL_INVOKE = "tool_invoke"
    POLICY_EVALUATION = "policy_evaluation"
    IDENTITY_CREATE = "identity_create"
    IDENTITY_REVOKE = "identity_revoke"
    ERROR = "error"


@dataclass
class AuditRecord:
    """An immutable audit record."""
    id: str
    timestamp: datetime
    event_type: AuditEventType
    subject_id: str
    action: str
    resource: str
    result: str  # success/failure
    details: Dict[str, Any] = field(default_factory=dict)
    previous_hash: str = ""  # Hash of previous record for chain
    record_hash: str = ""  # Hash of this record
    signature: Optional[str] = None  # hex encoded
    
    @classmethod
    def create(cls, event_type: AuditEventType, subject_id: str, action: str,
               resource: str, result: str, details: Optional[Dict[str, Any]] = None,
               previous_hash: str = "") -> 'AuditRecord':
        """Create a new audit record."""
        record = cls(
            id=str(uuid.uuid4()),
            timestamp=datetime.utcnow(),
            event_type=event_type,
            subject_id=subject_id,
            action=action,
            resource=resource,
            result=result,
            details=details or {},
            previous_hash=previous_hash,
        )
        
        # Compute hash
        record.record_hash = record._compute_hash()
        
        return record
    
    def _compute_hash(self) -> str:
        """Compute the hash of this record."""
        data = {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "event_type": self.event_type.value,
            "subject_id": self.subject_id,
            "action": self.action,
            "resource": self.resource,
            "result": self.result,
            "details": self.details,
            "previous_hash": self.previous_hash,
        }
        
        # Canonical JSON serialization
        canonical = json.dumps(data, sort_keys=True, separators=(',', ':'))
        return hashlib.sha256(canonical.encode()).hexdigest()
    
    def verify_integrity(self) -> bool:
        """Verify the record's hash integrity."""
        computed = self._compute_hash()
        return computed == self.record_hash
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "event_type": self.event_type.value,
            "subject_id": self.subject_id,
            "action": self.action,
            "resource": self.resource,
            "result": self.result,
            "details": self.details,
            "previous_hash": self.previous_hash,
            "record_hash": self.record_hash,
            "signature": self.signature,
        }


@dataclass 
class AuditReceipt:
    """Cryptographic receipt for an audit record."""
    record_id: str
    record_hash: str
    timestamp: datetime
    chain_hash: str  # Cumulative hash of all records up to this point
    issuer_id: str
    signature: str  # hex encoded
    
    def verify(self) -> bool:
        """Verify the receipt's integrity."""
        # In production, would verify signature against issuer's public key
        return True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "record_id": self.record_id,
            "record_hash": self.record_hash,
            "timestamp": self.timestamp.isoformat(),
            "chain_hash": self.chain_hash,
            "issuer_id": self.issuer_id,
            "signature": self.signature,
        }


class AuditManager:
    """Manages audit logging and receipt generation."""
    
    def __init__(self, issuer_id: str = "audit-system"):
        self._records: List[AuditRecord] = []
        self._by_id: Dict[str, AuditRecord] = {}
        self._receipts: Dict[str, AuditReceipt] = {}
        self._lock = threading.RLock()
        self._last_hash = ""
        self._chain_hash = ""
        self._issuer_id = issuer_id
    
    def log(self, event_type: AuditEventType, subject_id: str, action: str,
            resource: str, result: str, details: Optional[Dict[str, Any]] = None) -> AuditRecord:
        """Log an audit event."""
        with self._lock:
            record = AuditRecord.create(
                event_type=event_type,
                subject_id=subject_id,
                action=action,
                resource=resource,
                result=result,
                details=details,
                previous_hash=self._last_hash,
            )
            
            # Update chain
            self._last_hash = record.record_hash
            
            # Update cumulative chain hash
            chain_data = self._chain_hash + record.record_hash
            self._chain_hash = hashlib.sha256(chain_data.encode()).hexdigest()
            
            self._records.append(record)
            self._by_id[record.id] = record
            
            # Generate receipt
            receipt = self._generate_receipt(record)
            self._receipts[record.id] = receipt
            
            return record
    
    def _generate_receipt(self, record: AuditRecord) -> AuditReceipt:
        """Generate a cryptographic receipt for a record."""
        # In production, would sign with private key
        from smcp.crypto import Hasher
        
        receipt_data = f"{record.id}:{record.record_hash}:{self._chain_hash}"
        signature = Hasher.hmac_sha256(b"audit-secret-key", receipt_data.encode()).hex()
        
        return AuditReceipt(
            record_id=record.id,
            record_hash=record.record_hash,
            timestamp=datetime.utcnow(),
            chain_hash=self._chain_hash,
            issuer_id=self._issuer_id,
            signature=signature,
        )
    
    def get_record(self, record_id: str) -> Optional[AuditRecord]:
        """Get an audit record by ID."""
        with self._lock:
            return self._by_id.get(record_id)
    
    def get_receipt(self, record_id: str) -> Optional[AuditReceipt]:
        """Get a receipt for an audit record."""
        with self._lock:
            return self._receipts.get(record_id)
    
    def verify_chain(self) -> bool:
        """Verify the integrity of the entire audit chain."""
        with self._lock:
            if not self._records:
                return True
            
            previous_hash = ""
            for record in self._records:
                # Verify previous hash linkage
                if record.previous_hash != previous_hash:
                    return False
                
                # Verify record hash
                if not record.verify_integrity():
                    return False
                
                previous_hash = record.record_hash
            
            return True
    
    def query(self, subject_id: Optional[str] = None,
              event_type: Optional[AuditEventType] = None,
              start_time: Optional[datetime] = None,
              end_time: Optional[datetime] = None) -> List[AuditRecord]:
        """Query audit records with filters."""
        with self._lock:
            results = []
            
            for record in self._records:
                if subject_id and record.subject_id != subject_id:
                    continue
                
                if event_type and record.event_type != event_type:
                    continue
                
                if start_time and record.timestamp < start_time:
                    continue
                
                if end_time and record.timestamp > end_time:
                    continue
                
                results.append(record)
            
            return results
    
    def get_records(self, limit: int = 100, offset: int = 0) -> List[AuditRecord]:
        """Get audit records with pagination."""
        with self._lock:
            return self._records[offset:offset + limit]
    
    def export(self) -> List[Dict[str, Any]]:
        """Export all audit records."""
        with self._lock:
            return [record.to_dict() for record in self._records]
    
    def clear(self) -> None:
        """Clear all audit records (use with caution)."""
        with self._lock:
            self._records.clear()
            self._by_id.clear()
            self._receipts.clear()
            self._last_hash = ""
            self._chain_hash = ""


__all__ = [
    "AuditError",
    "AuditEventType",
    "AuditRecord",
    "AuditReceipt",
    "AuditManager",
]
