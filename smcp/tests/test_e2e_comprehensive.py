#!/usr/bin/env python3
"""
SMCP End-to-End Comprehensive Test Suite

This test suite validates the complete SMCP implementation including:
- Cryptographic operations
- Identity management
- Capability system
- Protocol messages
- Serialization
- Integration between all subsystems

All tests are deterministic and reproducible.
"""

import sys
import os
from datetime import datetime, timezone, timedelta
from pathlib import Path

# Add smcp to path
sys.path.insert(0, str(Path(__file__).parent))

from crypto import (
    PrivateKey, PublicKey, ExchangeKeyPair, KeyStore,
    generate_nonce, hash_data, derive_key,
    encrypt_aes_gcm, decrypt_aes_gcm,
    encrypt_chacha20, decrypt_chacha20,
    compute_hmac, constant_time_compare,
    SignedMessage, CryptoError, HashAlgorithm, EncryptionAlgorithm
)

from identity import (
    IdentityType, IdentityStatus, Identity, Certificate,
    IdentityProvider, IdentityManager,
    create_system_identity, create_test_agent
)

from capability import (
    Action, Resource, Capability,
    TemporalConstraint, UsageConstraint, PathConstraint,
    ParameterConstraint, ContextConstraint,
    ConstraintType, CapabilityStatus,
    CapabilityManager, DelegationInfo
)

from protocol import (
    MessageType, ProtocolVersion, ProtocolMessage,
    MessageValidator, MessageFactory,
    create_hello_payload, create_invoke_payload,
    create_result_payload, create_error_payload,
    create_consent_request_payload, create_audit_receipt_payload
)

from transport.serialization import (
    canonical_cbor_encode, canonical_cbor_decode,
    canonical_json_encode, canonical_json_decode
)


class TestResults:
    """Track test results."""
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.errors = []
    
    def record(self, name: str, passed: bool, error: str = None):
        if passed:
            self.passed += 1
            print(f"  ✓ {name}")
        else:
            self.failed += 1
            self.errors.append((name, error))
            print(f"  ✗ {name}: {error}")
    
    def summary(self):
        total = self.passed + self.failed
        print(f"\n{'='*60}")
        print(f"Test Results: {self.passed}/{total} passed")
        if self.failed > 0:
            print(f"\nFailed tests:")
            for name, error in self.errors:
                print(f"  - {name}: {error}")
        return self.failed == 0


def test_crypto_layer(results: TestResults):
    """Test cryptographic operations."""
    print("\n[1] Testing Cryptographic Layer...")
    
    # Test Ed25519 key generation
    try:
        private_key = PrivateKey.generate()
        public_key = private_key.public_key()
        results.record("Ed25519 key generation", True)
    except Exception as e:
        results.record("Ed25519 key generation", False, str(e))
        return
    
    # Test signing and verification
    try:
        data = b"test message for signing"
        signature = private_key.sign(data)
        verified = public_key.verify(signature, data)
        results.record("Ed25519 sign/verify", verified)
    except Exception as e:
        results.record("Ed25519 sign/verify", False, str(e))
    
    # Test signature tampering detection
    try:
        tampered_data = b"tampered message"
        tampered_verified = public_key.verify(signature, tampered_data)
        results.record("Signature tampering detection", not tampered_verified)
    except Exception as e:
        results.record("Signature tampering detection", False, str(e))
    
    # Test X25519 key exchange
    try:
        alice_keys = ExchangeKeyPair.generate()
        bob_keys = ExchangeKeyPair.generate()
        
        alice_secret = alice_keys.derive_shared_secret(bob_keys.public_key)
        bob_secret = bob_keys.derive_shared_secret(alice_keys.public_key)
        
        keys_match = alice_secret == bob_secret and len(alice_secret) == 32
        results.record("X25519 key exchange", keys_match)
    except Exception as e:
        results.record("X25519 key exchange", False, str(e))
    
    # Test HKDF key derivation
    try:
        shared_secret = b"x" * 32
        salt = generate_nonce(16)
        info = b"smcp-test-key"
        
        derived_key = derive_key(shared_secret, salt, info, 32)
        results.record("HKDF key derivation", len(derived_key) == 32)
    except Exception as e:
        results.record("HKDF key derivation", False, str(e))
    
    # Test AES-GCM encryption
    try:
        key = generate_nonce(32)
        plaintext = b"secret message for AES-GCM encryption test"
        ciphertext, nonce = encrypt_aes_gcm(key, plaintext)
        decrypted = decrypt_aes_gcm(key, nonce, ciphertext)
        
        encryption_works = decrypted == plaintext
        results.record("AES-GCM encrypt/decrypt", encryption_works)
    except Exception as e:
        results.record("AES-GCM encrypt/decrypt", False, str(e))
    
    # Test AES-GCM authentication
    try:
        key = generate_nonce(32)
        plaintext = b"authenticated message"
        ciphertext, nonce = encrypt_aes_gcm(key, plaintext)
        
        # Tamper with ciphertext
        tampered = bytearray(ciphertext)
        tampered[0] ^= 0xFF
        
        try:
            decrypt_aes_gcm(key, nonce, bytes(tampered))
            results.record("AES-GCM authentication", False, "Tampering not detected")
        except CryptoError:
            results.record("AES-GCM authentication", True)
    except Exception as e:
        results.record("AES-GCM authentication", False, str(e))
    
    # Test ChaCha20-Poly1305
    try:
        key = generate_nonce(32)
        plaintext = b"secret message for ChaCha20 encryption test"
        ciphertext, nonce = encrypt_chacha20(key, plaintext)
        decrypted = decrypt_chacha20(key, nonce, ciphertext)
        
        encryption_works = decrypted == plaintext
        results.record("ChaCha20-Poly1305 encrypt/decrypt", encryption_works)
    except Exception as e:
        results.record("ChaCha20-Poly1305 encrypt/decrypt", False, str(e))
    
    # Test hashing
    try:
        data = b"test data for hashing"
        sha256_hash = hash_data(data, HashAlgorithm.SHA256)
        sha3_hash = hash_data(data, HashAlgorithm.SHA3_256)
        
        hashes_valid = len(sha256_hash) == 32 and len(sha3_hash) == 32 and sha256_hash != sha3_hash
        results.record("SHA-256 and SHA3-256 hashing", hashes_valid)
    except Exception as e:
        results.record("SHA-256 and SHA3-256 hashing", False, str(e))
    
    # Test HMAC
    try:
        key = generate_nonce(32)
        data = b"HMAC test data"
        mac = compute_hmac(key, data)
        
        # Verify HMAC
        mac2 = compute_hmac(key, data)
        hmac_valid = constant_time_compare(mac, mac2)
        results.record("HMAC computation", hmac_valid)
    except Exception as e:
        results.record("HMAC computation", False, str(e))
    
    # Test nonce generation
    try:
        nonce1 = generate_nonce(32)
        nonce2 = generate_nonce(32)
        nonces_unique = nonce1 != nonce2 and len(nonce1) == 32
        results.record("Nonce generation uniqueness", nonces_unique)
    except Exception as e:
        results.record("Nonce generation uniqueness", False, str(e))
    
    # Test KeyStore
    try:
        keystore = KeyStore()
        key_id = "test-key-1"
        test_key = PrivateKey.generate()
        
        keystore.add_signing_key(key_id, test_key)
        retrieved = keystore.get_signing_key(key_id)
        
        keystore_works = retrieved is not None and retrieved.public_key().to_bytes() == test_key.public_key().to_bytes()
        results.record("KeyStore operations", keystore_works)
    except Exception as e:
        results.record("KeyStore operations", False, str(e))
    
    # Test SignedMessage
    try:
        payload = b"signed message payload"
        signed = SignedMessage.create(payload, private_key)
        verified = signed.verify()
        results.record("SignedMessage creation/verification", verified)
    except Exception as e:
        results.record("SignedMessage creation/verification", False, str(e))


def test_identity_system(results: TestResults):
    """Test identity management."""
    print("\n[2] Testing Identity System...")
    
    # Test identity creation
    try:
        provider = IdentityProvider()
        identity, private_key = provider.create_identity(
            IdentityType.AGENT, 
            "test-agent",
            {"role": "tester"}
        )
        
        identity_valid = (
            identity.id is not None and
            identity.type == IdentityType.AGENT and
            identity.name == "test-agent" and
            identity.is_active()
        )
        results.record("Identity creation", identity_valid)
    except Exception as e:
        results.record("Identity creation", False, str(e))
        return
    
    # Test identity retrieval
    try:
        retrieved = provider.get_identity(identity.id)
        retrieval_works = retrieved is not None and retrieved.id == identity.id
        results.record("Identity retrieval", retrieval_works)
    except Exception as e:
        results.record("Identity retrieval", False, str(e))
    
    # Test identity revocation
    try:
        provider.revoke_identity(identity.id)
        revoked = provider.is_revoked(identity.id)
        updated_identity = provider.get_identity(identity.id)
        
        revocation_works = revoked and updated_identity.status == IdentityStatus.REVOKED
        results.record("Identity revocation", revocation_works)
    except Exception as e:
        results.record("Identity revocation", False, str(e))
    
    # Test identity verification
    try:
        provider2 = IdentityProvider()
        valid_identity, _ = provider2.create_identity(IdentityType.HUMAN, "valid-user")
        
        verification_result = provider2.verify_identity(valid_identity)
        results.record("Identity verification", verification_result)
    except Exception as e:
        results.record("Identity verification", False, str(e))
    
    # Test identity expiration
    try:
        provider3 = IdentityProvider()
        expired_identity, _ = provider3.create_identity(
            IdentityType.TOOL,
            "temp-tool",
            expires_in=timedelta(seconds=-1)  # Already expired
        )
        
        is_expired = expired_identity.is_expired()
        results.record("Identity expiration detection", is_expired)
    except Exception as e:
        results.record("Identity expiration detection", False, str(e))
    
    # Test IdentityManager convenience methods
    try:
        manager = IdentityManager()
        
        agent, _ = manager.create_agent("manager-agent", ["read", "write"])
        human, _ = manager.create_human("manager-human", "test@example.com")
        host, _ = manager.create_host("manager-host", "localhost")
        tool, _ = manager.create_tool("manager-tool", "calculator")
        
        manager_works = (
            agent.type == IdentityType.AGENT and
            human.type == IdentityType.HUMAN and
            host.type == IdentityType.HOST and
            tool.type == IdentityType.TOOL
        )
        results.record("IdentityManager convenience methods", manager_works)
    except Exception as e:
        results.record("IdentityManager convenience methods", False, str(e))
    
    # Test identity serialization
    try:
        identity_dict = identity.to_dict()
        restored = Identity.from_dict(identity_dict)
        
        serialization_works = restored.id == identity.id and restored.name == identity.name
        results.record("Identity serialization/deserialization", serialization_works)
    except Exception as e:
        results.record("Identity serialization/deserialization", False, str(e))


def test_capability_system(results: TestResults):
    """Test capability-based authorization."""
    print("\n[3] Testing Capability System...")
    
    # Setup identities
    try:
        idp = IdentityProvider()
        issuer, issuer_key = idp.create_identity(IdentityType.SERVER, "capability-issuer")
        subject, subject_key = idp.create_identity(IdentityType.AGENT, "capability-subject")
        
        cap_manager = CapabilityManager()
        cap_manager.register_issuer(issuer.id, issuer_key, issuer.public_key)
        results.record("Capability manager setup", True)
    except Exception as e:
        results.record("Capability manager setup", False, str(e))
        return
    
    # Test basic capability issuance
    try:
        actions = [Action("read", "document"), Action("write", "document")]
        resources = [Resource("document", "doc-123")]
        
        capability = cap_manager.issue(
            issuer, subject, actions, resources,
            metadata={"purpose": "testing"}
        )
        
        issued = (
            capability.id is not None and
            capability.issuer == issuer.id and
            capability.subject == subject.id and
            len(capability.actions) == 2
        )
        results.record("Capability issuance", issued)
    except Exception as e:
        results.record("Capability issuance", False, str(e))
        return
    
    # Test capability verification
    try:
        action = Action("read", "document")
        resource = Resource("document", "doc-123")
        
        is_valid, status, msg = cap_manager.verify(capability, action, resource)
        verification_passed = status == CapabilityStatus.VALID
        results.record("Capability verification", verification_passed)
    except Exception as e:
        results.record("Capability verification", False, str(e))
    
    # Test capability action checking
    try:
        can_read = capability.can_action(Action("read", "document"), Resource("document", "doc-123"))
        cannot_delete = not capability.can_action(Action("delete", "document"), Resource("document", "doc-123"))
        
        action_check_works = can_read and cannot_delete
        results.record("Capability action checking", action_check_works)
    except Exception as e:
        results.record("Capability action checking", False, str(e))
    
    # Test temporal constraints
    try:
        future_constraint = TemporalConstraint(
            valid_from=datetime.now(timezone.utc) + timedelta(hours=1),
            valid_until=datetime.now(timezone.utc) + timedelta(hours=2)
        )
        
        past_constraint = TemporalConstraint(
            valid_from=datetime.now(timezone.utc) - timedelta(hours=2),
            valid_until=datetime.now(timezone.utc) - timedelta(hours=1)
        )
        
        future_valid = not future_constraint.is_satisfied()
        past_invalid = not past_constraint.is_satisfied()
        
        temporal_works = future_valid and past_invalid
        results.record("Temporal constraints", temporal_works)
    except Exception as e:
        results.record("Temporal constraints", False, str(e))
    
    # Test usage constraints
    try:
        usage = UsageConstraint(max_uses=3)
        
        first_use = usage.record_use()
        second_use = usage.record_use()
        third_use = usage.record_use()
        fourth_use = usage.record_use()  # Should fail
        
        usage_works = first_use and second_use and third_use and not fourth_use
        results.record("Usage constraints", usage_works)
    except Exception as e:
        results.record("Usage constraints", False, str(e))
    
    # Test delegation
    try:
        delegate, delegate_key = idp.create_identity(IdentityType.AGENT, "delegate")
        
        delegated_cap = cap_manager.delegate(
            capability, issuer, delegate,
            additional_conditions={
                ConstraintType.PATH: PathConstraint(max_depth=2, current_depth=1)
            }
        )
        
        delegation_works = (
            delegated_cap is not None and
            delegated_cap.delegation.is_delegated and
            delegated_cap.delegation.delegator == issuer.id
        )
        results.record("Capability delegation", delegation_works)
    except Exception as e:
        results.record("Capability delegation", False, str(e))
    
    # Test parameter constraints
    try:
        param_constraint = ParameterConstraint(
            allowed_parameters={"max_size": 1000},
            forbidden_parameters={"dangerous_flag"}
        )
        
        valid_params = {"max_size": 1000, "other": "value"}
        invalid_params = {"dangerous_flag": True}
        
        params_valid = param_constraint.validate_parameters(valid_params)
        params_rejected = not param_constraint.validate_parameters(invalid_params)
        
        param_works = params_valid and params_rejected
        results.record("Parameter constraints", param_works)
    except Exception as e:
        results.record("Parameter constraints", False, str(e))
    
    # Test capability revocation
    try:
        cap_manager.revoke(capability.id)
        is_valid, status, msg = cap_manager.verify(capability, action, resource)
        
        revocation_works = status == CapabilityStatus.REVOKED
        results.record("Capability revocation", revocation_works)
    except Exception as e:
        results.record("Capability revocation", False, str(e))


def test_protocol_messages(results: TestResults):
    """Test protocol message handling."""
    print("\n[4] Testing Protocol Messages...")
    
    # Setup identities for protocol testing
    try:
        idp = IdentityProvider()
        sender, sender_key = idp.create_identity(IdentityType.AGENT, "protocol-sender")
        receiver, receiver_key = idp.create_identity(IdentityType.SERVER, "protocol-receiver")
        
        factory = MessageFactory(sender.id, sender_key)
        results.record("Protocol setup", True)
    except Exception as e:
        results.record("Protocol setup", False, str(e))
        return
    
    # Test HELLO message
    try:
        hello_msg = factory.create_hello(receiver.id)
        
        hello_valid = (
            hello_msg.message_type == MessageType.HELLO and
            hello_msg.sender == sender.id and
            hello_msg.receiver == receiver.id and
            hello_msg.signature != b''
        )
        results.record("HELLO message creation", hello_valid)
    except Exception as e:
        results.record("HELLO message creation", False, str(e))
    
    # Test message signature verification
    try:
        hello_msg = factory.create_hello(receiver.id)
        verified = hello_msg.verify(sender.public_key)
        results.record("Message signature verification", verified)
    except Exception as e:
        results.record("Message signature verification", False, str(e))
    
    # Test PING/PONG
    try:
        ping_msg = factory.create_ping(receiver.id)
        pong_msg = factory.create_pong(sender.id)
        
        ping_pong_valid = (
            ping_msg.message_type == MessageType.PING and
            pong_msg.message_type == MessageType.PONG
        )
        results.record("PING/PONG messages", ping_pong_valid)
    except Exception as e:
        results.record("PING/PONG messages", False, str(e))
    
    # Test session messages
    try:
        open_msg = factory.create_session_open(receiver.id, "session-123", "standard", 3600)
        close_msg = factory.create_session_close(receiver.id, "normal_closure", 1000)
        
        session_valid = (
            open_msg.message_type == MessageType.SESSION_OPEN and
            close_msg.message_type == MessageType.SESSION_CLOSE and
            open_msg.payload["session_id"] == "session-123"
        )
        results.record("Session messages", session_valid)
    except Exception as e:
        results.record("Session messages", False, str(e))
    
    # Test INVOKE message
    try:
        invoke_msg = factory.create_invoke(
            receiver.id,
            "calculator-tool",
            "add",
            {"a": 5, "b": 3}
        )
        
        invoke_valid = (
            invoke_msg.message_type == MessageType.INVOKE and
            invoke_msg.payload["tool_id"] == "calculator-tool" and
            invoke_msg.payload["action"] == "add"
        )
        results.record("INVOKE message", invoke_valid)
    except Exception as e:
        results.record("INVOKE message", False, str(e))
    
    # Test message validation
    try:
        validator = MessageValidator()
        trusted_senders = [sender.id]
        
        hello_msg = factory.create_hello(receiver.id)
        valid, error = validator.validate(hello_msg, receiver.id, trusted_senders)
        
        validation_works = valid and error == ""
        results.record("Message validation", validation_works)
    except Exception as e:
        results.record("Message validation", False, str(e))
    
    # Test replay protection
    try:
        validator = MessageValidator()
        trusted_senders = [sender.id]
        
        msg = factory.create_ping(receiver.id)
        valid1, _ = validator.validate(msg, receiver.id, trusted_senders)
        valid2, error2 = validator.validate(msg, receiver.id, trusted_senders)
        
        replay_protection = valid1 and not valid2 and "Duplicate nonce" in error2
        results.record("Replay protection", replay_protection)
    except Exception as e:
        results.record("Replay protection", False, str(e))
    
    # Test clock skew validation
    try:
        from protocol import ProtocolMessage
        
        # Create message with old timestamp
        old_msg = ProtocolMessage(
            version="1.0.0",
            message_type=MessageType.PING,
            message_id="old-msg",
            timestamp=datetime.now(timezone.utc) - timedelta(hours=1),
            nonce=generate_nonce(32),
            sender=sender.id,
            receiver=receiver.id,
            payload={}
        )
        old_msg.sign(sender_key)
        
        validator = MessageValidator()
        valid, error = validator.validate(old_msg, receiver.id, [sender.id])
        
        clock_skew_works = not valid and "clock skew" in error.lower()
        results.record("Clock skew validation", clock_skew_works)
    except Exception as e:
        results.record("Clock skew validation", False, str(e))
    
    # Test consent request/response
    try:
        consent_req = factory.create_message(
            MessageType.CONSENT_REQUEST,
            receiver.id,
            create_consent_request_payload(
                "data_access",
                "read_user_data",
                "user-profile",
                "Need access for processing",
                300
            )
        )
        
        consent_response = factory.create_message(
            MessageType.CONSENT_RESPONSE,
            sender.id,
            {"granted": True, "conditions": {"time_limit": 300}}
        )
        
        consent_valid = (
            consent_req.message_type == MessageType.CONSENT_REQUEST and
            consent_response.message_type == MessageType.CONSENT_RESPONSE
        )
        results.record("Consent messages", consent_valid)
    except Exception as e:
        results.record("Consent messages", False, str(e))
    
    # Test audit receipt
    try:
        audit_msg = factory.create_message(
            MessageType.AUDIT_RECEIPT,
            receiver.id,
            create_audit_receipt_payload(
                "audit-123",
                "tool_invocation",
                sender.id,
                datetime.now(timezone.utc).isoformat(),
                "prev-hash-abc",
                "current-hash-xyz"
            )
        )
        
        audit_valid = audit_msg.message_type == MessageType.AUDIT_RECEIPT
        results.record("Audit receipt message", audit_valid)
    except Exception as e:
        results.record("Audit receipt message", False, str(e))


def test_serialization(results: TestResults):
    """Test serialization formats."""
    print("\n[5] Testing Serialization...")
    
    # Test CBOR encoding/decoding
    try:
        original = {
            "string": "test",
            "number": 42,
            "array": [1, 2, 3],
            "nested": {"key": "value"},
            "boolean": True,
            "null": None
        }
        
        encoded = canonical_cbor_encode(original)
        decoded = canonical_cbor_decode(encoded)
        
        cbor_works = decoded == original
        results.record("CBOR encode/decode", cbor_works)
    except Exception as e:
        results.record("CBOR encode/decode", False, str(e))
    
    # Test JSON encoding/decoding
    try:
        original = {
            "string": "test",
            "number": 42,
            "array": [1, 2, 3],
            "nested": {"key": "value"},
            "boolean": True
        }
        
        encoded = canonical_json_encode(original)
        decoded = canonical_json_decode(encoded)
        
        json_works = decoded == original
        results.record("JSON encode/decode", json_works)
    except Exception as e:
        results.record("JSON encode/decode", False, str(e))
    
    # Test canonical property (same input = same output)
    try:
        data = {"b": 2, "a": 1}  # Keys in different order
        
        encoded1 = canonical_json_encode(data)
        encoded2 = canonical_json_encode(data)
        
        canonical_property = encoded1 == encoded2
        results.record("Canonical encoding determinism", canonical_property)
    except Exception as e:
        results.record("Canonical encoding determinism", False, str(e))
    
    # Test protocol message serialization
    try:
        idp = IdentityProvider()
        sender, sender_key = idp.create_identity(IdentityType.AGENT, "serial-sender")
        receiver, _ = idp.create_identity(IdentityType.SERVER, "serial-receiver")
        
        factory = MessageFactory(sender.id, sender_key)
        msg = factory.create_ping(receiver.id)
        
        msg_dict = msg.to_dict()
        restored = ProtocolMessage.from_dict(msg_dict)
        
        msg_serialization = (
            restored.message_id == msg.message_id and
            restored.message_type == msg.message_type
        )
        results.record("Protocol message serialization", msg_serialization)
    except Exception as e:
        results.record("Protocol message serialization", False, str(e))


def test_integration(results: TestResults):
    """Test integration between subsystems."""
    print("\n[6] Testing Subsystem Integration...")
    
    # Full workflow: Identity -> Capability -> Protocol
    try:
        # Create identities
        idp = IdentityProvider()
        server, server_key = idp.create_identity(IdentityType.SERVER, "integration-server")
        client, client_key = idp.create_identity(IdentityType.AGENT, "integration-client")
        
        # Issue capability
        cap_manager = CapabilityManager()
        cap_manager.register_issuer(server.id, server_key, server.public_key)
        
        actions = [Action("invoke", "tool")]
        resources = [Resource("tool", "*")]
        
        capability = cap_manager.issue(server, client, actions, resources)
        
        # Create protocol message with capability
        factory = MessageFactory(client.id, client_key)
        invoke_msg = factory.create_invoke(
            server.id,
            "calculator",
            "compute",
            {"expression": "2+2"}
        )
        
        # Verify message
        verified = invoke_msg.verify(client.public_key)
        
        # Verify capability
        is_valid, status, msg = cap_manager.verify(
            capability,
            Action("invoke", "tool"),
            Resource("tool", "calculator")
        )
        
        integration_works = (
            verified and
            status == CapabilityStatus.VALID
        )
        results.record("Full workflow integration", integration_works)
    except Exception as e:
        results.record("Full workflow integration", False, str(e))
    
    # Test key exchange + encrypted communication simulation
    try:
        # Key exchange
        client_exchange = ExchangeKeyPair.generate()
        server_exchange = ExchangeKeyPair.generate()
        
        shared_secret_client = client_exchange.derive_shared_secret(server_exchange.public_key)
        shared_secret_server = server_exchange.derive_shared_secret(client_exchange.public_key)
        
        # Derive encryption key
        salt = generate_nonce(16)
        info = b"smcp-session-key"
        
        client_key = derive_key(shared_secret_client, salt, info, 32)
        server_key = derive_key(shared_secret_server, salt, info, 32)
        
        # Encrypt message
        message = b"encrypted protocol message"
        ciphertext, nonce = encrypt_aes_gcm(client_key, message)
        
        # Decrypt message
        decrypted = decrypt_aes_gcm(server_key, nonce, ciphertext)
        
        crypto_integration = decrypted == message and client_key == server_key
        results.record("Key exchange + encryption integration", crypto_integration)
    except Exception as e:
        results.record("Key exchange + encryption integration", False, str(e))
    
    # Test capability with temporal constraint in protocol flow
    try:
        idp = IdentityProvider()
        issuer, issuer_key = idp.create_identity(IdentityType.SERVER, "temp-issuer")
        subject, _ = idp.create_identity(IdentityType.AGENT, "temp-subject")
        
        cap_manager = CapabilityManager()
        cap_manager.register_issuer(issuer.id, issuer_key, issuer.public_key)
        
        # Create capability with temporal constraint
        temporal = TemporalConstraint(
            valid_from=datetime.now(timezone.utc) - timedelta(minutes=5),
            valid_until=datetime.now(timezone.utc) + timedelta(minutes=5)
        )
        
        capability = cap_manager.issue(
            issuer, subject,
            [Action("read", "resource")],
            [Resource("resource", "*")],
            conditions={ConstraintType.TEMPORAL: temporal}
        )
        
        # Verify with valid temporal constraint
        is_valid, status, msg = cap_manager.verify(
            capability,
            Action("read", "resource"),
            Resource("resource", "test")
        )
        
        temporal_integration = status == CapabilityStatus.VALID
        results.record("Temporal constraint integration", temporal_integration)
    except Exception as e:
        results.record("Temporal constraint integration", False, str(e))


def main():
    """Run all tests."""
    print("="*60)
    print("SMCP End-to-End Comprehensive Test Suite")
    print("="*60)
    
    results = TestResults()
    
    # Run all test suites
    test_crypto_layer(results)
    test_identity_system(results)
    test_capability_system(results)
    test_protocol_messages(results)
    test_serialization(results)
    test_integration(results)
    
    # Print summary
    success = results.summary()
    
    if success:
        print("\n✓ All tests passed!")
        return 0
    else:
        print("\n✗ Some tests failed!")
        return 1


if __name__ == "__main__":
    sys.exit(main())
