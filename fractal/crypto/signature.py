"""Signature utilities for Fractal Bitcoin."""

import hashlib
from typing import Union, Tuple, Optional

from ..crypto.keys import PrivateKey, PublicKey
from ..exceptions import CryptoError
from ..types.common import Signature
from ..utils.encoding import encode_varint

__all__ = [
    "sign_message",
    "verify_message",
    "sign_transaction",
    "parse_der_signature",
    "encode_der_signature",
]

# Bitcoin message magic
MESSAGE_MAGIC = b"\x18Bitcoin Signed Message:\n"


def sign_message(
    private_key: PrivateKey,
    message: Union[str, bytes],
    deterministic: bool = True
) -> bytes:
    """
    Sign a message with Bitcoin message signing convention.
    
    Args:
        private_key: Private key to sign with
        message: Message to sign
        deterministic: Use deterministic signing
        
    Returns:
        Signature bytes (65 bytes for recoverable)
    """
    if isinstance(message, str):
        message = message.encode("utf-8")
        
    # Create message hash with Bitcoin magic
    message_hash = _hash_message(message)
    
    # Create recoverable signature
    return private_key.sign_recoverable(message_hash)


def verify_message(
    address_or_pubkey: Union[str, PublicKey],
    signature: bytes,
    message: Union[str, bytes]
) -> bool:
    """
    Verify a signed message.
    
    Args:
        address_or_pubkey: Bitcoin address or public key
        signature: Message signature
        message: Original message
        
    Returns:
        True if signature is valid
    """
    if isinstance(message, str):
        message = message.encode("utf-8")
        
    # Create message hash
    message_hash = _hash_message(message)
    
    # Get public key
    if isinstance(address_or_pubkey, str):
        # Would need to recover public key from signature
        # This requires full signature recovery implementation
        raise NotImplementedError("Address verification not implemented")
    else:
        pubkey = address_or_pubkey
        
    # Verify signature
    # Note: This would need adjustment for recoverable signatures
    return pubkey.verify(signature, message_hash)


def sign_transaction(
    private_key: PrivateKey,
    sighash: bytes,
    sighash_type: int = 0x01
) -> bytes:
    """
    Sign transaction sighash.
    
    Args:
        private_key: Private key to sign with
        sighash: Transaction sighash (32 bytes)
        sighash_type: Signature hash type
        
    Returns:
        DER-encoded signature with sighash type appended
    """
    if len(sighash) != 32:
        raise ValueError("Sighash must be 32 bytes")
        
    # Sign the hash
    signature = private_key.sign(sighash)
    
    # Append sighash type
    return signature + bytes([sighash_type])


def parse_der_signature(signature: bytes) -> Tuple[int, int, Optional[int]]:
    """
    Parse DER-encoded signature.
    
    Args:
        signature: DER-encoded signature (possibly with sighash type)
        
    Returns:
        Tuple of (r, s, sighash_type)
        
    Raises:
        CryptoError: If signature format is invalid
    """
    try:
        # Check for sighash type byte
        if len(signature) > 70:  # Max DER sig is ~72 bytes
            sighash_type = signature[-1]
            signature = signature[:-1]
        else:
            sighash_type = None
            
        # Parse DER structure
        if signature[0] != 0x30:
            raise ValueError("Invalid DER signature: missing sequence tag")
            
        length = signature[1]
        if length + 2 != len(signature):
            raise ValueError("Invalid DER signature: incorrect length")
            
        # Parse r value
        if signature[2] != 0x02:
            raise ValueError("Invalid DER signature: missing r integer tag")
            
        r_length = signature[3]
        r_bytes = signature[4:4 + r_length]
        r = int.from_bytes(r_bytes, "big")
        
        # Parse s value
        s_offset = 4 + r_length
        if signature[s_offset] != 0x02:
            raise ValueError("Invalid DER signature: missing s integer tag")
            
        s_length = signature[s_offset + 1]
        s_bytes = signature[s_offset + 2:s_offset + 2 + s_length]
        s = int.from_bytes(s_bytes, "big")
        
        return r, s, sighash_type
        
    except (IndexError, ValueError) as e:
        raise CryptoError(f"Invalid DER signature: {e}") from e


def encode_der_signature(r: int, s: int, sighash_type: Optional[int] = None) -> bytes:
    """
    Encode signature as DER.
    
    Args:
        r: Signature r value  
        s: Signature s value
        sighash_type: Optional sighash type to append
        
    Returns:
        DER-encoded signature
    """
    # Encode r
    r_bytes = r.to_bytes((r.bit_length() + 7) // 8, "big")
    if r_bytes[0] & 0x80:
        r_bytes = b"\x00" + r_bytes
    r_encoded = b"\x02" + bytes([len(r_bytes)]) + r_bytes
    
    # Encode s
    s_bytes = s.to_bytes((s.bit_length() + 7) // 8, "big")
    if s_bytes[0] & 0x80:
        s_bytes = b"\x00" + s_bytes
    s_encoded = b"\x02" + bytes([len(s_bytes)]) + s_bytes
    
    # Combine into sequence
    sequence = r_encoded + s_encoded
    result = b"\x30" + bytes([len(sequence)]) + sequence
    
    # Append sighash type if provided
    if sighash_type is not None:
        result += bytes([sighash_type])
        
    return result


def _hash_message(message: bytes) -> bytes:
    """
    Hash message with Bitcoin message signing convention.
    
    Args:
        message: Message bytes
        
    Returns:
        32-byte message hash
    """
    # Create full message with magic and length
    length_bytes = encode_varint(len(message))
    full_message = MESSAGE_MAGIC + length_bytes + message
    
    # Double SHA256
    return hashlib.sha256(hashlib.sha256(full_message).digest()).digest()