"""SMCP Session Management."""
import uuid
from enum import Enum
from typing import Optional, Dict, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import threading


class SessionState(Enum):
    CREATED = "created"
    ACTIVE = "active"
    CLOSING = "closing"
    CLOSED = "closed"


class SessionError(Exception):
    pass


@dataclass
class Session:
    id: str
    state: SessionState = SessionState.CREATED
    created_at: datetime = field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @classmethod
    def create(cls, duration_hours: int = 24) -> 'Session':
        now = datetime.utcnow()
        return cls(
            id=str(uuid.uuid4()),
            state=SessionState.CREATED,
            created_at=now,
            expires_at=now + timedelta(hours=duration_hours),
        )
    
    def activate(self) -> None:
        if self.state == SessionState.CREATED:
            self.state = SessionState.ACTIVE
    
    def close(self) -> None:
        self.state = SessionState.CLOSED
    
    def is_expired(self) -> bool:
        if self.expires_at and datetime.utcnow() >= self.expires_at:
            self.state = SessionState.CLOSED
            return True
        return False
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "state": self.state.value,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "metadata": self.metadata,
        }


class SessionManager:
    def __init__(self):
        self._sessions: Dict[str, Session] = {}
        self._lock = threading.RLock()
    
    def create_session(self, duration_hours: int = 24) -> Session:
        session = Session.create(duration_hours)
        with self._lock:
            self._sessions[session.id] = session
        return session
    
    def get_session(self, session_id: str) -> Optional[Session]:
        with self._lock:
            return self._sessions.get(session_id)
    
    def close_session(self, session_id: str) -> None:
        with self._lock:
            session = self._sessions.get(session_id)
            if session:
                session.close()
    
    def list_sessions(self) -> list:
        with self._lock:
            return list(self._sessions.values())
    
    def clear(self) -> None:
        with self._lock:
            self._sessions.clear()


__all__ = ["SessionState", "SessionError", "Session", "SessionManager"]
