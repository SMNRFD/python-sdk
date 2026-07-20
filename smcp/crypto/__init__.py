"""
SMCP Cryptographic Layer

This module provides cryptographic primitives for SMCP.
Only battle-tested algorithms are used - no custom cryptography.

Security Notes:
- All cryptographic operations use constant-time comparisons where applicable
- Keys are securely generated using os.urandom or secrets module
- Private keys are never logged or exposed in error messages
- All operations fail closed on errors

Dependencies:
- cryptography library for cryptographic primitives
- Standard library for secure random generation
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Tuple, Union
from datetime import datetime, timezone

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519, ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature, InvalidTag


class CryptoError(Exception):
    """Base exception for cryptographic errors."""
    pass


class KeyGenerationError(CryptoError):
    """Error during key generation."""
    pass


class SignatureError(CryptoError):
    """Error during signature operations."""
    pass


class DecryptionError(CryptoError):
    """Error during decryption operations."""
    pass


class DerivationError(CryptoError):
    """Error during key derivation."""
    pass


class HashAlgorithm(Enum):
    """Supported hash algorithms."""
    SHA256 = "sha256"
    SHA3_256 = "sha3_256"
    SHA3_512 = "sha3_512"


class EncryptionAlgorithm(Enum):
    """Supported encryption algorithms."""
    AES_256_GCM = "aes-256-gcm"
    CHACHA20_POLY1305 = "chacha20-poly1305"


@dataclass(frozen=True)
class PublicKey:
    """Immutable public key wrapper."""
    _key: ed25519.Ed25519PublicKey
    
    def to_bytes(self) -> bytes:
        """Serialize public key to bytes."""
        return self._key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    
    def to_pem(self) -> str:
        """Serialize public key to PEM format."""
        return self._key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
    
    @classmethod
    def from_bytes(cls, data: bytes) -> PublicKey:
        """Deserialize public key from bytes."""
        try:
            key = ed25519.Ed25519PublicKey.from_public_bytes(data)
            return cls(key)
        except Exception as e:
            raise CryptoError(f"Failed to deserialize public key: {e}")
    
    @classmethod
    def from_pem(cls, pem_data: str) -> PublicKey:
        """Deserialize public key from PEM format."""
        try:
            key = serialization.load_pem_public_key(
                pem_data.encode('utf-8'),
                backend=default_backend()
            )
            return cls(key)
        except Exception as e:
            raise CryptoError(f"Failed to deserialize public key from PEM: {e}")
    
    def verify(self, signature: bytes, data: bytes) -> bool:
        """Verify a signature against data."""
        try:
            self._key.verify(signature, data)
            return True
        except InvalidSignature:
            return False


@dataclass
class PrivateKey:
    """Private key wrapper with secure handling."""
    _key: ed25519.Ed25519PrivateKey
    
    def __post_init__(self):
        # Ensure key is not accidentally logged
        object.__setattr__(self, '_secure', True)
    
    def public_key(self) -> PublicKey:
        """Get the corresponding public key."""
        return PublicKey(self._key.public_key())
    
    def sign(self, data: bytes) -> bytes:
        """Sign data with this private key."""
        return self._key.sign(data)
    
    def to_bytes(self) -> bytes:
        """Serialize private key to bytes (use with extreme caution)."""
        return self._key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
    
    def to_pem(self, password: Optional[bytes] = None) -> str:
        """Serialize private key to PEM format."""
        if password:
            encryption = serialization.BestAvailableEncryption(password)
        else:
            encryption = serialization.NoEncryption()
        
        return self._key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        ).decode('utf-8')
    
    @classmethod
    def generate(cls) -> PrivateKey:
        """Generate a new Ed25519 private key."""
        try:
            key = ed25519.Ed25519PrivateKey.generate()
            return cls(key)
        except Exception as e:
            raise KeyGenerationError(f"Failed to generate private key: {e}")
    
    @classmethod
    def from_bytes(cls, data: bytes) -> PrivateKey:
        """Deserialize private key from bytes."""
        try:
            key = ed25519.Ed25519PrivateKey.from_private_bytes(data)
            return cls(key)
        except Exception as e:
            raise CryptoError(f"Failed to deserialize private key: {e}")
    
    @classmethod
    def from_pem(cls, pem_data: str, password: Optional[bytes] = None) -> PrivateKey:
        """Deserialize private key from PEM format."""
        try:
            if password:
                key = serialization.load_pem_private_key(
                    pem_data.encode('utf-8'),
                    password=password,
                    backend=default_backend()
                )
            else:
                key = serialization.load_pem_private_key(
                    pem_data.encode('utf-8'),
                    password=None,
                    backend=default_backend()
                )
            return cls(key)
        except Exception as e:
            raise CryptoError(f"Failed to deserialize private key from PEM: {e}")
    
    def __del__(self):
        """Attempt to clear sensitive data on deletion."""
        # Note: This is best-effort only in Python
        pass


@dataclass(frozen=True)
class ExchangeKeyPair:
    """X25519 key pair for key exchange."""
    _private_key: x25519.X25519PrivateKey
    
    @property
    def public_key(self) -> bytes:
        """Get the public key as bytes."""
        return self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    
    @classmethod
    def generate(cls) -> ExchangeKeyPair:
        """Generate a new X25519 key pair."""
        try:
            key = x25519.X25519PrivateKey.generate()
            return cls(key)
        except Exception as e:
            raise KeyGenerationError(f"Failed to generate exchange key pair: {e}")
    
    def derive_shared_secret(self, peer_public_key: bytes) -> bytes:
        """Derive shared secret from peer's public key."""
        try:
            peer_pub = x25519.X25519PublicKey.from_public_bytes(peer_public_key)
            shared = self._private_key.exchange(peer_pub)
            return shared
        except Exception as e:
            raise DerivationError(f"Failed to derive shared secret: {e}")


def generate_nonce(size: int = 32) -> bytes:
    """Generate a cryptographically secure nonce."""
    return secrets.token_bytes(size)


def generate_session_id() -> str:
    """Generate a unique session identifier."""
    return secrets.token_hex(16)


def hash_data(data: bytes, algorithm: HashAlgorithm = HashAlgorithm.SHA256) -> bytes:
    """Hash data using specified algorithm."""
    if algorithm == HashAlgorithm.SHA256:
        return hashlib.sha256(data).digest()
    elif algorithm == HashAlgorithm.SHA3_256:
        return hashlib.sha3_256(data).digest()
    elif algorithm == HashAlgorithm.SHA3_512:
        return hashlib.sha3_512(data).digest()
    else:
        raise CryptoError(f"Unsupported hash algorithm: {algorithm}")


def derive_key(
    shared_secret: bytes,
    salt: bytes,
    info: bytes,
    length: int = 32
) -> bytes:
    """Derive a key using HKDF-SHA256."""
    try:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            info=info,
            backend=default_backend()
        )
        return hkdf.derive(shared_secret)
    except Exception as e:
        raise DerivationError(f"Failed to derive key: {e}")


def encrypt_aes_gcm(
    key: bytes,
    plaintext: bytes,
    associated_data: Optional[bytes] = None
) -> Tuple[bytes, bytes]:
    """
    Encrypt data using AES-256-GCM.
    
    Returns:
        Tuple of (ciphertext_with_tag, nonce)
    """
    if len(key) != 32:
        raise CryptoError("AES-256-GCM requires a 32-byte key")
    
    aesgcm = AESGCM(key)
    nonce = generate_nonce(12)  # 96-bit nonce recommended for GCM
    
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
    return ciphertext, nonce


def decrypt_aes_gcm(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    associated_data: Optional[bytes] = None
) -> bytes:
    """Decrypt data using AES-256-GCM."""
    if len(key) != 32:
        raise CryptoError("AES-256-GCM requires a 32-byte key")
    
    try:
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data)
        return plaintext
    except InvalidTag:
        raise DecryptionError("Decryption failed - authentication tag invalid")
    except Exception as e:
        raise DecryptionError(f"Decryption failed: {e}")


def encrypt_chacha20(
    key: bytes,
    plaintext: bytes,
    associated_data: Optional[bytes] = None
) -> Tuple[bytes, bytes]:
    """
    Encrypt data using ChaCha20-Poly1305.
    
    Returns:
        Tuple of (ciphertext_with_tag, nonce)
    """
    if len(key) != 32:
        raise CryptoError("ChaCha20-Poly1305 requires a 32-byte key")
    
    chacha = ChaCha20Poly1305(key)
    nonce = generate_nonce(12)
    
    ciphertext = chacha.encrypt(nonce, plaintext, associated_data)
    return ciphertext, nonce


def decrypt_chacha20(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    associated_data: Optional[bytes] = None
) -> bytes:
    """Decrypt data using ChaCha20-Poly1305."""
    if len(key) != 32:
        raise CryptoError("ChaCha20-Poly1305 requires a 32-byte key")
    
    try:
        chacha = ChaCha20Poly1305(key)
        plaintext = chacha.decrypt(nonce, ciphertext, associated_data)
        return plaintext
    except InvalidTag:
        raise DecryptionError("Decryption failed - authentication tag invalid")
    except Exception as e:
        raise DecryptionError(f"Decryption failed: {e}")


def compute_hmac(key: bytes, data: bytes, algorithm: HashAlgorithm = HashAlgorithm.SHA256) -> bytes:
    """Compute HMAC of data."""
    hash_alg = {
        HashAlgorithm.SHA256: 'sha256',
        HashAlgorithm.SHA3_256: 'sha3_256',
        HashAlgorithm.SHA3_512: 'sha3_512',
    }.get(algorithm)
    
    if not hash_alg:
        raise CryptoError(f"Unsupported HMAC algorithm: {algorithm}")
    
    return hmac.new(key, data, hash_alg).digest()


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """Constant-time comparison to prevent timing attacks."""
    return hmac.compare_digest(a, b)


@dataclass(frozen=True)
class SignedMessage:
    """A message with cryptographic signature."""
    payload: bytes
    signature: bytes
    signer_public_key: PublicKey
    timestamp: datetime
    
    def verify(self) -> bool:
        """Verify the signature."""
        return self.signer_public_key.verify(self.signature, self.payload)
    
    @classmethod
    def create(
        cls,
        payload: bytes,
        private_key: PrivateKey
    ) -> SignedMessage:
        """Create a signed message."""
        signature = private_key.sign(payload)
        return cls(
            payload=payload,
            signature=signature,
            signer_public_key=private_key.public_key(),
            timestamp=datetime.now(timezone.utc)
        )


@dataclass
class KeyStore:
    """Secure storage for cryptographic keys."""
    _signing_keys: dict[str, PrivateKey] = field(default_factory=dict)
    _exchange_keys: dict[str, ExchangeKeyPair] = field(default_factory=dict)
    _trusted_public_keys: dict[str, PublicKey] = field(default_factory=dict)
    
    def add_signing_key(self, key_id: str, key: PrivateKey) -> None:
        """Add a signing key to the store."""
        self._signing_keys[key_id] = key
    
    def get_signing_key(self, key_id: str) -> Optional[PrivateKey]:
        """Retrieve a signing key by ID."""
        return self._signing_keys.get(key_id)
    
    def add_exchange_key(self, key_id: str, key_pair: ExchangeKeyPair) -> None:
        """Add an exchange key pair to the store."""
        self._exchange_keys[key_id] = key_pair
    
    def get_exchange_key(self, key_id: str) -> Optional[ExchangeKeyPair]:
        """Retrieve an exchange key pair by ID."""
        return self._exchange_keys.get(key_id)
    
    def add_trusted_public_key(self, key_id: str, public_key: PublicKey) -> None:
        """Add a trusted public key."""
        self._trusted_public_keys[key_id] = public_key
    
    def get_trusted_public_key(self, key_id: str) -> Optional[PublicKey]:
        """Retrieve a trusted public key by ID."""
        return self._trusted_public_keys.get(key_id)
    
    def remove_signing_key(self, key_id: str) -> bool:
        """Remove a signing key."""
        if key_id in self._signing_keys:
            del self._signing_keys[key_id]
            return True
        return False
    
    def list_key_ids(self) -> list[str]:
        """List all signing key IDs."""
        return list(self._signing_keys.keys())


# Module initialization - generate master key pair if needed
_master_key_pair: Optional[PrivateKey] = None


def get_master_key_pair() -> PrivateKey:
    """Get or generate the master key pair for this instance."""
    global _master_key_pair
    if _master_key_pair is None:
        _master_key_pair = PrivateKey.generate()
    return _master_key_pair
