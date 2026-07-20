# Secure Model Communication Protocol (SMCP) Specification

## Version 1.0.0

## Abstract

SMCP is a secure, capability-based communication protocol designed for AI agent systems, enabling secure tool invocation, identity management, consent workflows, and audit trails.

## Table of Contents

1. Introduction
2. Security Model
3. Identity System
4. Capability System
5. Protocol Messages
6. Transport Layer
7. Serialization
8. Session Management
9. Policy Engine
10. Consent System
11. Audit System
12. Discovery
13. Tool Registry
14. Extension Framework

---

## 1. Introduction

### 1.1 Purpose

SMCP provides a secure communication framework for:
- AI agents invoking tools
- Human-agent interaction
- Inter-agent communication
- Resource access control
- Audit and compliance

### 1.2 Design Principles

- **Zero Trust**: No implicit trust; all interactions must be authenticated and authorized
- **Least Privilege**: Capabilities grant minimal necessary permissions
- **Defense in Depth**: Multiple security layers
- **Deterministic Behavior**: Reproducible outcomes
- **Fail Closed**: Errors default to denying access

### 1.3 Terminology

- **Agent**: An AI system participating in SMCP
- **Human**: A human user with an SMCP identity
- **Host**: A server or runtime environment
- **Tool**: A callable function or service
- **Capability**: A verifiable authorization token
- **Session**: A secured communication channel

---

## 2. Security Model

### 2.1 Cryptographic Primitives

SMCP uses only battle-tested cryptographic algorithms:

| Purpose | Algorithm |
|---------|-----------|
| Key Exchange | X25519 |
| Signatures | Ed25519 |
| Symmetric Encryption | AES-256-GCM, ChaCha20-Poly1305 |
| Key Derivation | HKDF-SHA256 |
| Hashing | SHA-256, SHA-3 |
| Serialization | CBOR, Canonical JSON |

### 2.2 Trust Model

- All identities are verified through cryptographic keys
- Certificate chains establish trust relationships
- Capabilities are cryptographically signed tokens
- All messages are authenticated and integrity-protected

### 2.3 Threat Model

SMCP protects against:
- Eavesdropping (confidentiality)
- Message tampering (integrity)
- Impersonation (authentication)
- Replay attacks (nonces, timestamps)
- Privilege escalation (capability validation)
- Unauthorized delegation (path constraints)

---

## 3. Identity System

### 3.1 Identity Types

1. **Agent Identity**: AI system identifier
2. **Human Identity**: User identifier
3. **Host Identity**: Server/runtime identifier
4. **Tool Identity**: Tool/service identifier
5. **Resource Identity**: Data/resource identifier

### 3.2 Identity Structure

```
Identity {
    type: IdentityType
    id: UUID
    public_key: Ed25519PublicKey
    certificates: [Certificate]
    attributes: Map<String, Value>
    issued_at: Timestamp
    expires_at: Timestamp
}
```

### 3.3 Key Management

- Keys are Ed25519 for signing
- X25519 for key exchange
- Key rotation supported through certificate chains
- Revocation through CRL/OCSP

---

## 4. Capability System

### 4.1 Capability Token Structure

```
Capability {
    id: UUID
    issuer: Identity
    subject: Identity
    actions: [Action]
    resources: [Resource]
    conditions: Conditions
    delegation: DelegationInfo
    validity: ValidityPeriod
    signature: Signature
}
```

### 4.2 Capability Operations

- **Issue**: Create new capability
- **Verify**: Validate capability authenticity and constraints
- **Delegate**: Create derived capability with reduced scope
- **Restrict**: Add additional constraints
- **Expire**: Time-based invalidation
- **Revoke**: Explicit invalidation

### 4.3 Constraints

- **Temporal**: Time windows, expiration
- **Usage**: Count limits, rate limits
- **Path**: Delegation depth limits
- **Parameter**: Input value constraints
- **Context**: Environmental requirements

---

## 5. Protocol Messages

### 5.1 Message Format

All messages follow this structure:

```
Message {
    version: ProtocolVersion
    message_type: MessageType
    message_id: UUID
    timestamp: Timestamp
    nonce: Nonce
    sender: Identity
    receiver: Identity
    payload: Payload
    signature: Signature
}
```

### 5.2 Message Types

#### Connection Establishment
- **HELLO**: Initial connection greeting
- **NEGOTIATE**: Protocol parameter negotiation
- **AUTH**: Authentication exchange

#### Session Management
- **SESSION_OPEN**: Open new session
- **SESSION_CLOSE**: Close session
- **PING**: Keep-alive request
- **PONG**: Keep-alive response
- **HEARTBEAT**: Periodic health check

#### Discovery
- **DISCOVER**: Find available services
- **LIST_TOOLS**: List available tools
- **GET_TOOL**: Get tool details

#### Invocation
- **INVOKE**: Invoke a tool
- **RESULT**: Invocation result
- **ERROR**: Error response

#### Authorization
- **CONSENT_REQUEST**: Request user consent
- **CONSENT_RESPONSE**: Consent decision
- **CAPABILITY_REQUEST**: Request capability
- **CAPABILITY_GRANT**: Grant capability
- **CAPABILITY_REVOKE**: Revoke capability

#### Audit
- **AUDIT_RECEIPT**: Audit record acknowledgment
- **POLICY_DECISION**: Policy evaluation result

---

## 6. Transport Layer

### 6.1 Supported Transports

- TLS 1.3 over TCP
- QUIC
- Unix Domain Sockets
- Named Pipes
- WebSocket
- HTTP/2
- HTTP/3
- stdio

### 6.2 Transport Abstraction

All transports implement:

```
Transport {
    connect() -> Connection
    send(Message) -> Result
    receive() -> Result<Message>
    close() -> Result
}
```

---

## 7. Serialization

### 7.1 Formats

- **Canonical CBOR**: Primary binary format
- **Canonical JSON**: Human-readable format

### 7.2 Canonicalization

Both formats ensure deterministic encoding for:
- Consistent hashing
- Signature verification
- Deduplication

---

## 8. Session Management

### 8.1 Session Lifecycle

1. Handshake
2. Authentication
3. Capability exchange
4. Message exchange
5. Heartbeat
6. Graceful close

### 8.2 Session State

```
Session {
    id: SessionID
    state: SessionState
    parties: [Identity]
    capabilities: [Capability]
    created_at: Timestamp
    last_activity: Timestamp
    heartbeat_interval: Duration
}
```

### 8.3 Replay Protection

- Nonces must be unique per session
- Timestamps validated with clock skew tolerance
- Sequence numbers for ordered delivery

---

## 9. Policy Engine

### 9.1 Policy Language

Declarative policy language supporting:
- Attribute-based access control (ABAC)
- Role-based access control (RBAC)
- Relationship-based access control (ReBAC)

### 9.2 Policy Evaluation

Policies evaluate to:
- **Permit**: Access granted
- **Deny**: Access denied
- **Indeterminate**: Insufficient information

### 9.3 Conflict Resolution

- Deny overrides Permit
- Specific rules override general rules
- Explicit rules override implicit rules

---

## 10. Consent System

### 10.1 Consent Types

- **Interactive**: Real-time user approval
- **Automatic**: Pre-approved based on policy
- **Delegated**: Approved by delegate
- **Time-Limited**: Valid for specific duration
- **One-Time**: Single use only
- **Multi-Step**: Requires multiple approvals

### 10.2 Consent Workflow

1. Consent request generated
2. Request presented to approver
3. Decision recorded
4. Capability issued if approved
5. Audit trail created

---

## 11. Audit System

### 11.1 Audit Record Structure

```
AuditRecord {
    id: UUID
    timestamp: Timestamp
    actor: Identity
    action: Action
    resource: Resource
    capability: CapabilityRef
    decision: Decision
    effects: [Effect]
    receipt_hash: Hash
    signature: Signature
}
```

### 11.2 Immutability

- Records are hash-chained
- Each record includes previous hash
- Tamper-evident through signatures
- External anchoring supported

---

## 12. Discovery

### 12.1 Discovery Mechanisms

- Static configuration
- DNS-based discovery
- mDNS/Bonjour
- Central registry
- Peer-to-peer gossip

### 12.2 Service Advertisement

Services advertise:
- Capabilities offered
- Required authentication
- Supported protocols
- Network endpoints

---

## 13. Tool Registry

### 13.1 Tool Manifest

```
ToolManifest {
    name: String
    version: SemVer
    description: String
    author: Identity
    inputs: [Parameter]
    outputs: [Parameter]
    capabilities_required: [Capability]
    capabilities_granted: [Capability]
    policy: Policy
}
```

### 13.2 Registry Operations

- Register tool
- Deregister tool
- Query tools
- Update tool metadata
- Validate tool manifests

---

## 14. Extension Framework

### 14.1 Plugin Types

- Authentication providers
- Identity providers
- Policy providers
- Risk providers
- Transport providers
- Compression providers
- Serialization providers
- Discovery providers
- Registry providers
- Audit providers

### 14.2 Plugin Security

- Sandboxed execution
- Declared permissions
- Versioned interfaces
- Signed plugins required
- Resource limits enforced

---

## Appendix A: Protocol Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2024 | Initial release |

## Appendix B: Error Codes

| Code | Name | Description |
|------|------|-------------|
| 1000 | NORMAL_CLOSURE | Normal completion |
| 1001 | GOING_AWAY | Endpoint leaving |
| 2000 | AUTHENTICATION_FAILED | Invalid credentials |
| 2001 | AUTHORIZATION_FAILED | Insufficient privileges |
| 2002 | CAPABILITY_EXPIRED | Capability no longer valid |
| 2003 | CAPABILITY_REVOKED | Capability explicitly revoked |
| 3000 | INVALID_MESSAGE | Malformed message |
| 3001 | INVALID_SIGNATURE | Signature verification failed |
| 3002 | REPLAY_DETECTED | Duplicate nonce detected |
| 4000 | TOOL_NOT_FOUND | Requested tool unavailable |
| 4001 | TOOL_EXECUTION_FAILED | Tool execution error |
| 5000 | INTERNAL_ERROR | Server internal error |

## Appendix C: Implementation Compliance

Implementations claiming SMCP compliance must:
- Support all mandatory message types
- Implement required cryptographic algorithms
- Pass compliance test suite
- Maintain audit trails
- Support capability-based authorization
