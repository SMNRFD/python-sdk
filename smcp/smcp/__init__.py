"""SMCP - Secure Model Communication Protocol Reference Implementation."""

__version__ = "1.0.0"
__author__ = "SMCP Project"

from crypto import (
    PrivateKey, PublicKey, ExchangeKeyPair, KeyStore,
    hash_data, derive_key, generate_nonce, generate_session_id,
    encrypt_aes_gcm, decrypt_aes_gcm,
    encrypt_chacha20, decrypt_chacha20,
    compute_hmac, constant_time_compare,
    SignedMessage, CryptoError
)

from identity import (
    Identity, IdentityType, IdentityStatus, IdentityProvider, IdentityManager,
    Certificate,
    create_system_identity, create_test_agent
)

from capability import (
    Capability, CapabilityManager, CapabilityStatus,
    Action, Resource,
    ConstraintType,
    TemporalConstraint, UsageConstraint, PathConstraint,
    ParameterConstraint, ContextConstraint, DelegationInfo,
    create_read_action, create_write_action, create_execute_action,
    create_wildcard_resource, create_specific_resource
)

from protocol import (
    MessageType, ProtocolVersion, ProtocolMessage,
    MessageValidator, MessageFactory,
    create_hello_payload, create_negotiate_payload,
    create_auth_payload, create_session_open_payload,
    create_session_close_payload, create_discover_payload,
    create_invoke_payload, create_result_payload, create_error_payload,
    create_consent_request_payload, create_consent_response_payload,
    create_capability_grant_payload, create_audit_receipt_payload,
    create_policy_decision_payload
)

from transport.serialization import (
    Serializer, Format, SerializationError,
    canonical_json_encode, canonical_json_decode,
    canonical_cbor_encode, canonical_cbor_decode,
    serialize_message, deserialize_message,
    compute_message_hash
)

__all__ = [
    # Version
    '__version__',
    # Crypto
    'PrivateKey', 'PublicKey', 'ExchangeKeyPair', 'KeyStore',
    'hash_data', 'derive_key', 'generate_nonce', 'generate_session_id',
    'encrypt_aes_gcm', 'decrypt_aes_gcm',
    'encrypt_chacha20', 'decrypt_chacha20',
    'compute_hmac', 'constant_time_compare',
    'SignedMessage', 'CryptoError',
    # Identity
    'Identity', 'IdentityType', 'IdentityStatus', 
    'IdentityProvider', 'IdentityManager', 'Certificate',
    'create_system_identity', 'create_test_agent',
    # Capability
    'Capability', 'CapabilityManager', 'CapabilityStatus',
    'Action', 'Resource', 'ConstraintType',
    'TemporalConstraint', 'UsageConstraint', 'PathConstraint',
    'ParameterConstraint', 'ContextConstraint', 'DelegationInfo',
    'create_read_action', 'create_write_action', 'create_execute_action',
    'create_wildcard_resource', 'create_specific_resource',
    # Protocol
    'MessageType', 'ProtocolVersion', 'ProtocolMessage',
    'MessageValidator', 'MessageFactory',
    'create_hello_payload', 'create_negotiate_payload',
    'create_auth_payload', 'create_session_open_payload',
    'create_session_close_payload', 'create_discover_payload',
    'create_invoke_payload', 'create_result_payload', 'create_error_payload',
    'create_consent_request_payload', 'create_consent_response_payload',
    'create_capability_grant_payload', 'create_audit_receipt_payload',
    'create_policy_decision_payload',
    # Serialization
    'Serializer', 'Format', 'SerializationError',
    'canonical_json_encode', 'canonical_json_decode',
    'canonical_cbor_encode', 'canonical_cbor_decode',
    'serialize_message', 'deserialize_message',
    'compute_message_hash',
]
