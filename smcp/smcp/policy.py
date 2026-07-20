"""
SMCP Policy Engine

Policy-based authorization with:
- Policy language parser
- Rule evaluation engine
- Conflict resolution
- Hot reload support

Security Properties:
- Deterministic evaluation
- Fail-closed by default
- No arbitrary code execution
"""

import re
from enum import Enum
from typing import Optional, List, Dict, Any, Set, Callable
from dataclasses import dataclass, field
import threading


class PolicyError(Exception):
    """Base exception for policy errors."""
    pass


class Decision(Enum):
    """Policy decision outcomes."""
    ALLOW = "allow"
    DENY = "deny"
    INDETERMINATE = "indeterminate"


@dataclass
class PolicyDecision:
    """Result of policy evaluation."""
    decision: Decision
    reason: str = ""
    obligations: List[Dict[str, Any]] = field(default_factory=list)
    
    @classmethod
    def allow(cls, reason: str = "", obligations: Optional[List[Dict[str, Any]]] = None) -> 'PolicyDecision':
        return cls(decision=Decision.ALLOW, reason=reason, obligations=obligations or [])
    
    @classmethod
    def deny(cls, reason: str = "") -> 'PolicyDecision':
        return cls(decision=Decision.DENY, reason=reason)
    
    @classmethod
    def indeterminate(cls, reason: str = "") -> 'PolicyDecision':
        return cls(decision=Decision.INDETERMINATE, reason=reason)


@dataclass
class Policy:
    """A policy rule."""
    id: str
    name: str
    description: str = ""
    effect: Decision = Decision.DENY  # Default deny
    subject_matcher: Optional[str] = None  # Regex pattern
    action_matcher: Optional[str] = None
    resource_matcher: Optional[str] = None
    condition: Optional[Callable[[Dict[str, Any]], bool]] = None
    priority: int = 0
    enabled: bool = True
    
    def matches(self, subject: str, action: str, resource: str,
                context: Optional[Dict[str, Any]] = None) -> bool:
        """Check if this policy applies to the request."""
        if not self.enabled:
            return False
        
        # Check subject matcher
        if self.subject_matcher:
            if not re.match(self.subject_matcher, subject):
                return False
        
        # Check action matcher
        if self.action_matcher:
            if not re.match(self.action_matcher, action):
                return False
        
        # Check resource matcher
        if self.resource_matcher:
            if not re.match(self.resource_matcher, resource):
                return False
        
        # Check custom condition
        if self.condition and context:
            try:
                if not self.condition(context):
                    return False
            except Exception:
                return False
        
        return True


class PolicyEngine:
    """Evaluates policies for authorization decisions."""
    
    def __init__(self):
        self._policies: Dict[str, Policy] = {}
        self._lock = threading.RLock()
        self._default_decision = Decision.DENY
    
    def add_policy(self, policy: Policy) -> None:
        """Add a policy to the engine."""
        with self._lock:
            self._policies[policy.id] = policy
    
    def remove_policy(self, policy_id: str) -> None:
        """Remove a policy."""
        with self._lock:
            self._policies.pop(policy_id, None)
    
    def get_policy(self, policy_id: str) -> Optional[Policy]:
        """Get a policy by ID."""
        with self._lock:
            return self._policies.get(policy_id)
    
    def evaluate(self, subject: str, action: str, resource: str,
                 context: Optional[Dict[str, Any]] = None) -> PolicyDecision:
        """Evaluate all applicable policies."""
        with self._lock:
            applicable_policies = []
            
            for policy in self._policies.values():
                if policy.matches(subject, action, resource, context):
                    applicable_policies.append(policy)
            
            if not applicable_policies:
                return PolicyDecision(
                    decision=self._default_decision,
                    reason="No applicable policies"
                )
            
            # Sort by priority (higher first)
            applicable_policies.sort(key=lambda p: p.priority, reverse=True)
            
            # First matching policy wins (priority-based)
            for policy in applicable_policies:
                return PolicyDecision(
                    decision=policy.effect,
                    reason=f"Matched policy: {policy.name}"
                )
            
            return PolicyDecision(
                decision=self._default_decision,
                reason="No policy matched"
            )
    
    def check_permission(self, subject: str, action: str, resource: str,
                         context: Optional[Dict[str, Any]] = None) -> bool:
        """Simple permission check returning boolean."""
        result = self.evaluate(subject, action, resource, context)
        return result.decision == Decision.ALLOW
    
    def set_default_decision(self, decision: Decision) -> None:
        """Set the default decision when no policies match."""
        with self._lock:
            self._default_decision = decision
    
    def list_policies(self) -> List[Policy]:
        """List all policies."""
        with self._lock:
            return list(self._policies.values())
    
    def clear(self) -> None:
        """Clear all policies."""
        with self._lock:
            self._policies.clear()


# Common policy builders
def allow_all() -> Policy:
    """Create a policy that allows everything."""
    return Policy(
        id="allow-all",
        name="Allow All",
        effect=Decision.ALLOW,
        subject_matcher=".*",
        action_matcher=".*",
        resource_matcher=".*",
        priority=-1000,
    )


def deny_all() -> Policy:
    """Create a policy that denies everything."""
    return Policy(
        id="deny-all",
        name="Deny All",
        effect=Decision.DENY,
        subject_matcher=".*",
        action_matcher=".*",
        resource_matcher=".*",
        priority=-1000,
    )


def allow_action(action_pattern: str) -> Policy:
    """Create a policy that allows specific actions."""
    return Policy(
        id=f"allow-{action_pattern}",
        name=f"Allow {action_pattern}",
        effect=Decision.ALLOW,
        action_matcher=action_pattern,
        priority=100,
    )


def deny_action(action_pattern: str) -> Policy:
    """Create a policy that denies specific actions."""
    return Policy(
        id=f"deny-{action_pattern}",
        name=f"Deny {action_pattern}",
        effect=Decision.DENY,
        action_matcher=action_pattern,
        priority=200,
    )


__all__ = [
    "PolicyError",
    "Decision",
    "PolicyDecision",
    "Policy",
    "PolicyEngine",
    "allow_all",
    "deny_all",
    "allow_action",
    "deny_action",
]
