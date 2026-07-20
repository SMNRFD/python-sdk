# SMCP - Secure Model Communication Protocol

## Reference Implementation

Version: 1.0.0

## Overview

SMCP (Secure Model Communication Protocol) is a secure, capability-based communication protocol designed for AI agent systems. It enables secure tool invocation, identity management, consent workflows, and audit trails.

## Design Principles

- **Zero Trust**: No implicit trust; all interactions must be authenticated and authorized
- **Least Privilege**: Capabilities grant minimal necessary permissions
- **Defense in Depth**: Multiple security layers
- **Deterministic Behavior**: Reproducible outcomes
- **Fail Closed**: Errors default to denying access

## Core Components

### Crypto Layer (`crypto/`)
- Ed25519 signatures
- X25519 key exchange
- AES-256-GCM and ChaCha20-Poly1305 encryption
- HKDF-SHA256 key derivation
- SHA-256 and SHA-3 hashing

### Identity System (`identity/`)
- Multiple identity types (Agent, Human, Host, Tool, Resource)
- Certificate-based verification
- Key management and rotation
- Revocation support

### Capability System (`capability/`)
- Cryptographically signed capability tokens
- Delegation with constraints
- Temporal, usage, path, parameter, and context constraints
- Offline verification

### Protocol Layer (`protocol/`)
- All SMCP message types
- Message signing and verification
- Replay protection via nonces
- Clock skew handling

### Serialization (`transport/serialization.py`)
- Canonical CBOR encoding
- Canonical JSON encoding (RFC 8785)
- Deterministic serialization for signing

## Installation

```bash
pip install cryptography cbor2
```

## Quick Start

```python
import smcp

# Create cryptographic key pair
key = smcp.PrivateKey.generate()
public_key = key.public_key()

# Create an identity
from smcp import IdentityProvider, IdentityType
provider = IdentityProvider()
identity, priv_key = provider.create_identity(IdentityType.AGENT, "my-agent")

# Issue a capability
from smcp import CapabilityManager, create_read_action, create_wildcard_resource
cm = CapabilityManager()
cm.register_issuer(identity.id, priv_key, identity.public_key)

action = create_read_action("file")
resource = create_wildcard_resource("file")
capability = cm.issue(identity, identity, [action], [resource])

# Verify the capability
is_valid, status, msg = cm.verify(capability)
print(f"Capability valid: {is_valid} ({status.value})")

# Create and sign a protocol message
from smcp import MessageFactory, MessageType
factory = MessageFactory(identity.id, priv_key)
hello_msg = factory.create_hello("receiver-id")

# Serialize the message
from smcp import canonical_cbor_encode, canonical_cbor_decode
encoded = canonical_cbor_encode(hello_msg.to_dict())
decoded = canonical_cbor_decode(encoded)
```

## Message Types

### Connection Establishment
- `HELLO` - Initial connection greeting
- `NEGOTIATE` - Protocol parameter negotiation
- `AUTH` - Authentication exchange

### Session Management
- `SESSION_OPEN` - Open new session
- `SESSION_CLOSE` - Close session
- `PING` / `PONG` - Keep-alive
- `HEARTBEAT` - Periodic health check

### Discovery
- `DISCOVER` - Find available services
- `LIST_TOOLS` - List available tools
- `GET_TOOL` - Get tool details

### Invocation
- `INVOKE` - Invoke a tool
- `RESULT` - Invocation result
- `ERROR` - Error response

### Authorization
- `CONSENT_REQUEST` / `CONSENT_RESPONSE` - Consent workflow
- `CAPABILITY_REQUEST` / `CAPABILITY_GRANT` / `CAPABILITY_REVOKE` - Capability management

### Audit
- `AUDIT_RECEIPT` - Audit record
- `POLICY_DECISION` - Policy evaluation result

## Security Considerations

1. **Never use custom cryptography** - Only battle-tested algorithms are used
2. **All messages must be signed** - Unsigned messages are rejected
3. **Nonces prevent replay attacks** - Each message has a unique nonce
4. **Timestamps are validated** - Messages outside clock skew tolerance are rejected
5. **Capabilities are unforgeable** - Cryptographic signatures ensure authenticity
6. **Private keys never leave their owner** - Keys are not transmitted

## Documentation

See `specs/smcp-spec.md` for the complete protocol specification.

## License

[License information]

## Contributing

[Contribution guidelines]
