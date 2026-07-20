#!/usr/bin/env python3
"""SMCP Security Test Suite - Tests security properties and attack resistance."""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from datetime import datetime, timezone, timedelta
from crypto import PrivateKey, generate_nonce, encrypt_aes_gcm, decrypt_aes_gcm, CryptoError
from identity import IdentityProvider, IdentityType
from capability import CapabilityManager, Action, Resource
from protocol import MessageValidator, MessageFactory, MessageType, ProtocolMessage

def test_signature_forgery_resistance():
    """Test that signatures cannot be forged."""
    print("\n[Security] Testing signature forgery resistance...")
    
    idp = IdentityProvider()
    alice, alice_key = idp.create_identity(IdentityType.AGENT, "alice")
    bob, bob_key = idp.create_identity(IdentityType.AGENT, "bob")
    
    factory = MessageFactory(alice.id, alice_key)
    msg = factory.create_hello(bob.id)
    
    # Try to verify with wrong key
    verified_with_bob = msg.verify(bob.public_key())
    
    # Tamper with message
    msg.payload["tampered"] = True
    
    verified_after_tamper = msg.verify(alice.public_key())
    
    passed = not verified_with_bob and not verified_after_tamper
    print(f"  {'PASS' if passed else 'FAIL'} Signature forgery resistance")
    return passed

def test_replay_attack_prevention():
    """Test replay attack prevention."""
    print("\n[Security] Testing replay attack prevention...")
    
    idp = IdentityProvider()
    sender, sender_key = idp.create_identity(IdentityType.AGENT, "sender")
    receiver, _ = idp.create_identity(IdentityType.SERVER, "receiver")
    
    factory = MessageFactory(sender.id, sender_key)
    validator = MessageValidator()
    
    msg = factory.create_ping(receiver.id)
    
    valid1, _ = validator.validate(msg, receiver.id, [sender.id])
    valid2, error2 = validator.validate(msg, receiver.id, [sender.id])
    valid3, error3 = validator.validate(msg, receiver.id, [sender.id])
    
    passed = valid1 and not valid2 and not valid3
    print(f"  {'PASS' if passed else 'FAIL'} Replay attack prevention")
    return passed

def test_clock_skew_protection():
    """Test clock skew protection."""
    print("\n[Security] Testing clock skew protection...")
    
    idp = IdentityProvider()
    sender, sender_key = idp.create_identity(IdentityType.AGENT, "sender")
    receiver, _ = idp.create_identity(IdentityType.SERVER, "receiver")
    
    future_msg = ProtocolMessage(
        version="1.0.0",
        message_type=MessageType.PING,
        message_id="future-msg",
        timestamp=datetime.now(timezone.utc) + timedelta(hours=2),
        nonce=generate_nonce(32),
        sender=sender.id,
        receiver=receiver.id,
        payload={}
    )
    future_msg.sign(sender_key)
    
    past_msg = ProtocolMessage(
        version="1.0.0",
        message_type=MessageType.PING,
        message_id="past-msg",
        timestamp=datetime.now(timezone.utc) - timedelta(hours=2),
        nonce=generate_nonce(32),
        sender=sender.id,
        receiver=receiver.id,
        payload={}
    )
    past_msg.sign(sender_key)
    
    validator = MessageValidator()
    future_valid, _ = validator.validate(future_msg, receiver.id, [sender.id])
    past_valid, _ = validator.validate(past_msg, receiver.id, [sender.id])
    
    passed = not future_valid and not past_valid
    print(f"  {'PASS' if passed else 'FAIL'} Clock skew protection")
    return passed

def test_capability_escalation_prevention():
    """Test that capabilities cannot be escalated."""
    print("\n[Security] Testing capability escalation prevention...")
    
    idp = IdentityProvider()
    issuer, issuer_key = idp.create_identity(IdentityType.SERVER, "issuer")
    subject, _ = idp.create_identity(IdentityType.AGENT, "subject")
    
    cap_manager = CapabilityManager()
    cap_manager.register_issuer(issuer.id, issuer_key, issuer.public_key())
    
    capability = cap_manager.issue(
        issuer, subject,
        [Action("read", "document")],
        [Resource("document", "doc-1")]
    )
    
    is_valid, status, _ = cap_manager.verify(
        capability,
        Action("write", "document"),
        Resource("document", "doc-1")
    )
    
    is_valid2, status2, _ = cap_manager.verify(
        capability,
        Action("read", "document"),
        Resource("document", "doc-999")
    )
    
    passed = not is_valid and not is_valid2
    print(f"  {'PASS' if passed else 'FAIL'} Capability escalation prevention")
    return passed

def test_encryption_integrity():
    """Test encryption integrity (tamper detection)."""
    print("\n[Security] Testing encryption integrity...")
    
    key = generate_nonce(32)
    plaintext = b"confidential data"
    
    ciphertext, nonce = encrypt_aes_gcm(key, plaintext)
    
    tampered = bytearray(ciphertext)
    tampered[5] ^= 0xFF
    
    try:
        decrypt_aes_gcm(key, nonce, bytes(tampered))
        passed = False
    except CryptoError:
        passed = True
    
    print(f"  {'PASS' if passed else 'FAIL'} Encryption integrity")
    return passed

def test_key_uniqueness():
    """Test that generated keys are unique."""
    print("\n[Security] Testing key uniqueness...")
    
    keys = set()
    for _ in range(100):
        key = PrivateKey.generate()
        key_bytes = key.to_bytes()
        keys.add(key_bytes)
    
    passed = len(keys) == 100
    print(f"  {'PASS' if passed else 'FAIL'} Key uniqueness (100 keys)")
    return passed

def test_nonce_uniqueness():
    """Test that nonces are unique."""
    print("\n[Security] Testing nonce uniqueness...")
    
    nonces = set()
    for _ in range(1000):
        nonce = generate_nonce(32)
        nonces.add(nonce)
    
    passed = len(nonces) == 1000
    print(f"  {'PASS' if passed else 'FAIL'} Nonce uniqueness (1000 nonces)")
    return passed

def main():
    print("="*60)
    print("SMCP Security Test Suite")
    print("="*60)
    
    results = [
        test_signature_forgery_resistance(),
        test_replay_attack_prevention(),
        test_clock_skew_protection(),
        test_capability_escalation_prevention(),
        test_encryption_integrity(),
        test_key_uniqueness(),
        test_nonce_uniqueness(),
    ]
    
    passed = sum(results)
    total = len(results)
    
    print(f"\n{'='*60}")
    print(f"Security Tests: {passed}/{total} passed")
    
    if passed == total:
        print("\nAll security tests PASSED!")
        return 0
    else:
        print("\nSome security tests FAILED!")
        return 1

if __name__ == "__main__":
    sys.exit(main())
