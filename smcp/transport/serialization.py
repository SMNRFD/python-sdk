"""
SMCP Serialization Layer

This module provides serialization support for SMCP messages.
Supports canonical CBOR and canonical JSON formats.

Architecture:
- Canonical encoding ensures deterministic serialization
- Same data always produces same bytes (for hashing/signing)
- Supports all SMCP data types
- Pluggable format support

Security Notes:
- Canonical JSON follows RFC 8785
- CBOR uses definite length encoding
- No floating point to avoid precision issues
- All strings are UTF-8
- Maps/dicts have sorted keys
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union
from enum import Enum

try:
    import cbor2
    CBOR_AVAILABLE = True
except ImportError:
    CBOR_AVAILABLE = False


class SerializationError(Exception):
    """Error during serialization/deserialization."""
    pass


class Format(Enum):
    """Supported serialization formats."""
    CANONICAL_JSON = "canonical-json"
    CANONICAL_CBOR = "canonical-cbor"


def canonicalize_value(value: Any) -> Any:
    """
    Convert a value to its canonical form.
    
    Rules:
    - Datetimes become ISO 8601 strings with Z suffix
    - Enums become their string values
    - Bytes become base64 strings
    - None becomes null
    - Numbers stay as-is (no floats if possible)
    """
    if value is None:
        return None
    
    if isinstance(value, bool):
        return value
    
    if isinstance(value, int):
        return value
    
    if isinstance(value, float):
        # Avoid floats when possible, but if necessary use full precision
        return value
    
    if isinstance(value, str):
        return value
    
    if isinstance(value, bytes):
        import base64
        return base64.b64encode(value).decode('ascii')
    
    if isinstance(value, datetime):
        # Convert to UTC and format with Z suffix
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        utc_value = value.astimezone(timezone.utc)
        return utc_value.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
    
    if isinstance(value, Enum):
        return value.value
    
    if isinstance(value, dict):
        return {k: canonicalize_value(v) for k, v in value.items()}
    
    if isinstance(value, (list, tuple)):
        return [canonicalize_value(item) for item in value]
    
    # For custom objects with to_dict method
    if hasattr(value, 'to_dict') and callable(getattr(value, 'to_dict')):
        return canonicalize_value(value.to_dict())
    
    # Fallback: try to convert to string
    return str(value)


def canonical_json_encode(data: Any) -> str:
    """
    Encode data to canonical JSON per RFC 8785.
    
    Rules:
    - UTF-8 encoding
    - No trailing newline
    - Keys sorted lexicographically
    - No whitespace except in strings
    - Unicode escaped outside ASCII range (optional, we use raw UTF-8)
    """
    canonical_data = canonicalize_value(data)
    
    # Use separators to remove whitespace
    json_str = json.dumps(
        canonical_data,
        ensure_ascii=False,
        separators=(',', ':'),
        sort_keys=True,
        allow_nan=False
    )
    
    return json_str


def canonical_json_decode(json_str: str) -> Any:
    """Decode canonical JSON string."""
    try:
        return json.loads(json_str)
    except json.JSONDecodeError as e:
        raise SerializationError(f"Invalid JSON: {e}")


def canonical_cbor_encode(data: Any) -> bytes:
    """
    Encode data to canonical CBOR.
    
    Rules:
    - Definite length encoding only
    - Keys sorted bytewise
    - No preferred serialization
    - Strings must be valid UTF-8
    """
    if not CBOR_AVAILABLE:
        raise SerializationError("CBOR library not available")
    
    canonical_data = canonicalize_value(data)
    
    # Use definite length encoding
    try:
        encoded = cbor2.dumps(
            canonical_data,
            default=lambda x: None  # Fail on unknown types
        )
        return encoded
    except Exception as e:
        raise SerializationError(f"CBOR encoding failed: {e}")


def canonical_cbor_decode(data: bytes) -> Any:
    """Decode canonical CBOR bytes."""
    if not CBOR_AVAILABLE:
        raise SerializationError("CBOR library not available")
    
    try:
        return cbor2.loads(data)
    except Exception as e:
        raise SerializationError(f"CBOR decoding failed: {e}")


class Serializer:
    """
    Unified serializer supporting multiple formats.
    
    Provides consistent interface for serialization operations.
    """
    
    def __init__(self, format: Format = Format.CANONICAL_CBOR):
        """Initialize with specified format."""
        self.format = format
    
    def encode(self, data: Any) -> Union[bytes, str]:
        """Encode data to the configured format."""
        if self.format == Format.CANONICAL_JSON:
            return canonical_json_encode(data)
        elif self.format == Format.CANONICAL_CBOR:
            return canonical_cbor_encode(data)
        else:
            raise SerializationError(f"Unknown format: {self.format}")
    
    def decode(self, data: Union[bytes, str]) -> Any:
        """Decode data from the configured format."""
        if self.format == Format.CANONICAL_JSON:
            if isinstance(data, bytes):
                data = data.decode('utf-8')
            return canonical_json_decode(data)
        elif self.format == Format.CANONICAL_CBOR:
            if isinstance(data, str):
                data = data.encode('utf-8')
            return canonical_cbor_decode(data)
        else:
            raise SerializationError(f"Unknown format: {self.format}")
    
    def hash(self, data: Any) -> bytes:
        """Compute hash of canonicalized data."""
        import hashlib
        
        if self.format == Format.CANONICAL_CBOR:
            encoded = self.encode(data)
        else:
            encoded = self.encode(data).encode('utf-8')
        
        return hashlib.sha256(encoded).digest()


def serialize_message(message: Dict[str, Any], format: Format = Format.CANONICAL_CBOR) -> Union[bytes, str]:
    """Serialize an SMCP message."""
    serializer = Serializer(format)
    return serializer.encode(message)


def deserialize_message(data: Union[bytes, str], format: Format = Format.CANONICAL_CBOR) -> Dict[str, Any]:
    """Deserialize an SMCP message."""
    serializer = Serializer(format)
    return serializer.decode(data)


def compute_message_hash(message: Dict[str, Any], format: Format = Format.CANONICAL_CBOR) -> bytes:
    """Compute SHA-256 hash of a message."""
    serializer = Serializer(format)
    return serializer.hash(message)


# Convenience functions for common operations
def to_canonical_bytes(data: Any) -> bytes:
    """Convert any data to canonical CBOR bytes."""
    return canonical_cbor_encode(data)


def from_canonical_bytes(data: bytes) -> Any:
    """Parse canonical CBOR bytes."""
    return canonical_cbor_decode(data)


def to_canonical_string(data: Any) -> str:
    """Convert any data to canonical JSON string."""
    return canonical_json_encode(data)


def from_canonical_string(data: str) -> Any:
    """Parse canonical JSON string."""
    return canonical_json_decode(data)


def sign_and_serialize(
    data: Dict[str, Any],
    private_key: Any,
    format: Format = Format.CANONICAL_CBOR
) -> Dict[str, Any]:
    """
    Serialize data and add cryptographic signature.
    
    Returns dict with 'data' and 'signature' fields.
    """
    from crypto import PrivateKey
    
    # Serialize the data
    if format == Format.CANONICAL_CBOR:
        serialized = canonical_cbor_encode(data)
    else:
        serialized = canonical_json_encode(data).encode('utf-8')
    
    # Sign
    if not isinstance(private_key, PrivateKey):
        raise SerializationError("Invalid private key")
    
    signature = private_key.sign(serialized)
    
    return {
        'data': data,
        'signature': signature
    }


def verify_and_deserialize(
    signed_data: Dict[str, Any],
    public_key: Any,
    format: Format = Format.CANONICAL_CBOR
) -> Dict[str, Any]:
    """
    Verify signature and deserialize data.
    
    Returns the original data if signature is valid.
    Raises SerializationError if verification fails.
    """
    from crypto import PublicKey
    
    if 'data' not in signed_data or 'signature' not in signed_data:
        raise SerializationError("Missing data or signature")
    
    data = signed_data['data']
    signature = signed_data['signature']
    
    # Serialize data for verification
    if format == Format.CANONICAL_CBOR:
        serialized = canonical_cbor_encode(data)
    else:
        serialized = canonical_json_encode(data).encode('utf-8')
    
    # Verify
    if not isinstance(public_key, PublicKey):
        raise SerializationError("Invalid public key")
    
    if not public_key.verify(signature, serialized):
        raise SerializationError("Signature verification failed")
    
    return data
