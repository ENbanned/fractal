"""Encoding and decoding utilities for Fractal Bitcoin."""

import hashlib
import struct
from typing import Tuple, List, Union, Optional

from ..constants import ADDRESS_PREFIXES, BECH32_HRP, Network
from ..exceptions import ValidationError
from ..types.common import HexStr, Address

__all__ = [
    "hex_to_bytes",
    "bytes_to_hex",
    "int_to_bytes",
    "bytes_to_int",
    "encode_varint",
    "decode_varint",
    "double_sha256",
    "hash160",
    "hash256",
    "encode_base58",
    "decode_base58",
    "encode_base58_check",
    "decode_base58_check",
    "encode_bech32",
    "decode_bech32",
    "decode_address",
    "encode_address",
    "serialize_script",
    "deserialize_script",
    "tagged_hash",
    "lift_x"
]

# Constants
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def hex_to_bytes(hex_str: Union[HexStr, str]) -> bytes:
    """
    Convert hex string to bytes.
    
    Args:
        hex_str: Hex string with or without 0x prefix
        
    Returns:
        Decoded bytes
        
    Raises:
        ValidationError: If hex string is invalid
    """
    try:
        # Remove 0x prefix if present
        if isinstance(hex_str, str) and hex_str.startswith("0x"):
            hex_str = hex_str[2:]
        return bytes.fromhex(hex_str)
    except ValueError as e:
        raise ValidationError(f"Invalid hex string: {hex_str}") from e


def bytes_to_hex(data: bytes, prefix: bool = False) -> HexStr:
    """
    Convert bytes to hex string.
    
    Args:
        data: Bytes to encode
        prefix: Add 0x prefix
        
    Returns:
        Hex string
    """
    hex_str = data.hex()
    if prefix:
        hex_str = f"0x{hex_str}"
    return HexStr(hex_str)


def int_to_bytes(
    value: int,
    length: int,
    byteorder: str = "big",
    signed: bool = False
) -> bytes:
    """
    Convert integer to bytes with specified length.
    
    Args:
        value: Integer value
        length: Number of bytes
        byteorder: 'big' or 'little' endian
        signed: Whether integer is signed
        
    Returns:
        Encoded bytes
    """
    return value.to_bytes(length, byteorder=byteorder, signed=signed)


def bytes_to_int(
    data: bytes,
    byteorder: str = "big",
    signed: bool = False
) -> int:
    """
    Convert bytes to integer.
    
    Args:
        data: Bytes to decode
        byteorder: 'big' or 'little' endian
        signed: Whether integer is signed
        
    Returns:
        Decoded integer
    """
    return int.from_bytes(data, byteorder=byteorder, signed=signed)


def encode_varint(n: int) -> bytes:
    """
    Encode integer as Bitcoin variable length integer.
    
    Args:
        n: Integer to encode
        
    Returns:
        Encoded varint bytes
    """
    if n < 0xfd:
        return bytes([n])
    elif n <= 0xffff:
        return b"\xfd" + struct.pack("<H", n)
    elif n <= 0xffffffff:
        return b"\xfe" + struct.pack("<I", n)
    else:
        return b"\xff" + struct.pack("<Q", n)


def decode_varint(data: bytes, offset: int = 0) -> Tuple[int, int]:
    """
    Decode Bitcoin variable length integer.
    
    Args:
        data: Bytes containing varint
        offset: Starting position
        
    Returns:
        Tuple of (value, new_offset)
    """
    if data[offset] < 0xfd:
        return data[offset], offset + 1
    elif data[offset] == 0xfd:
        return struct.unpack_from("<H", data, offset + 1)[0], offset + 3
    elif data[offset] == 0xfe:
        return struct.unpack_from("<I", data, offset + 1)[0], offset + 5
    else:
        return struct.unpack_from("<Q", data, offset + 1)[0], offset + 9


def double_sha256(data: bytes) -> bytes:
    """Perform double SHA256 hash."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def hash160(data: bytes) -> bytes:
    """Perform RIPEMD160(SHA256(data))."""
    sha256_hash = hashlib.sha256(data).digest()
    return hashlib.new("ripemd160", sha256_hash).digest()


def hash256(data: bytes) -> bytes:
    """Alias for double SHA256."""
    return double_sha256(data)


def encode_base58(data: bytes) -> str:
    """
    Encode bytes as Base58 string.
    
    Args:
        data: Bytes to encode
        
    Returns:
        Base58 encoded string
    """
    # Convert to integer
    n = bytes_to_int(data, byteorder="big")
    
    # Encode
    encoded = ""
    while n:
        n, remainder = divmod(n, 58)
        encoded = BASE58_ALPHABET[remainder] + encoded
        
    # Add leading zeros
    for byte in data:
        if byte == 0:
            encoded = "1" + encoded
        else:
            break
            
    return encoded


def decode_base58(string: str) -> bytes:
    """
    Decode Base58 string to bytes.
    
    Args:
        string: Base58 string
        
    Returns:
        Decoded bytes
        
    Raises:
        ValidationError: If string contains invalid characters
    """
    # Decode to integer
    n = 0
    for char in string:
        try:
            n = n * 58 + BASE58_ALPHABET.index(char)
        except ValueError:
            raise ValidationError(f"Invalid Base58 character: {char}")
            
    # Convert to bytes
    hex_str = hex(n)[2:]
    if len(hex_str) % 2:
        hex_str = "0" + hex_str
        
    # Add leading zeros
    leading_zeros = len(string) - len(string.lstrip("1"))
    return b"\x00" * leading_zeros + bytes.fromhex(hex_str)


def encode_base58_check(data: bytes) -> str:
    """
    Encode bytes as Base58Check (with checksum).
    
    Args:
        data: Bytes to encode
        
    Returns:
        Base58Check encoded string
    """
    checksum = double_sha256(data)[:4]
    return encode_base58(data + checksum)


def decode_base58_check(string: str) -> bytes:
    """
    Decode Base58Check string.
    
    Args:
        string: Base58Check string
        
    Returns:
        Decoded data (without checksum)
        
    Raises:
        ValidationError: If checksum is invalid
    """
    data = decode_base58(string)
    if len(data) < 4:
        raise ValidationError("Invalid Base58Check string: too short")
        
    payload, checksum = data[:-4], data[-4:]
    expected_checksum = double_sha256(payload)[:4]
    
    if checksum != expected_checksum:
        raise ValidationError("Invalid Base58Check checksum")
        
    return payload


def _bech32_polymod(values: List[int]) -> int:
    """Compute Bech32 checksum polymod."""
    generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp: str) -> List[int]:
    """Expand human-readable part for Bech32."""
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def encode_bech32(hrp: str, witver: int, witprog: bytes) -> str:
    """
    Encode as Bech32 address.
    
    Args:
        hrp: Human-readable part
        witver: Witness version
        witprog: Witness program
        
    Returns:
        Bech32 encoded address
    """
    # Convert witness program to 5-bit groups
    values = [witver]
    bits = 0
    value = 0
    
    for byte in witprog:
        value = (value << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            values.append((value >> bits) & 31)
            
    if bits:
        values.append((value << (5 - bits)) & 31)
        
    # Calculate checksum
    polymod = _bech32_polymod(_bech32_hrp_expand(hrp) + values + [0, 0, 0, 0, 0, 0]) ^ 1
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    
    # Build result
    return hrp + "1" + "".join(BECH32_CHARSET[v] for v in values + checksum)


def decode_bech32(address: str) -> Tuple[str, int, bytes]:
    """
    Decode Bech32 address.
    
    Args:
        address: Bech32 address
        
    Returns:
        Tuple of (hrp, witness_version, witness_program)
        
    Raises:
        ValidationError: If address is invalid
    """
    # Find separator
    pos = address.rfind("1")
    if pos < 1:
        raise ValidationError("Invalid Bech32 address: no separator")
        
    hrp = address[:pos]
    data = address[pos + 1:]
    
    # Decode data
    values = []
    for char in data:
        try:
            values.append(BECH32_CHARSET.index(char))
        except ValueError:
            raise ValidationError(f"Invalid Bech32 character: {char}")
            
    # Verify checksum
    if _bech32_polymod(_bech32_hrp_expand(hrp) + values) != 1:
        raise ValidationError("Invalid Bech32 checksum")
        
    # Extract witness version and program
    witver = values[0]
    witprog_5bit = values[1:-6]  # Remove checksum
    
    # Convert from 5-bit to 8-bit
    bits = 0
    value = 0
    witprog = bytearray()
    
    for v in witprog_5bit:
        value = (value << 5) | v
        bits += 5
        while bits >= 8:
            bits -= 8
            witprog.append((value >> bits) & 255)
            
    return hrp, witver, bytes(witprog)


def _bech32m_polymod(values: List[int]) -> int:
    """Compute Bech32m checksum polymod with modified constant."""
    generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def encode_bech32m(hrp: str, witver: int, witprog: bytes) -> str:
    """
    Encode as Bech32m address (for Taproot and future SegWit versions).
    
    Args:
        hrp: Human-readable part
        witver: Witness version
        witprog: Witness program
        
    Returns:
        Bech32m encoded address
    """
    # Convert witness program to 5-bit groups
    values = [witver]
    bits = 0
    value = 0
    
    for byte in witprog:
        value = (value << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            values.append((value >> bits) & 31)
            
    if bits:
        values.append((value << (5 - bits)) & 31)
        
    # Calculate checksum with Bech32m constant (0x2bc830a3 instead of 1)
    polymod = _bech32m_polymod(_bech32_hrp_expand(hrp) + values + [0, 0, 0, 0, 0, 0]) ^ 0x2bc830a3
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    
    # Build result
    return hrp + "1" + "".join(BECH32_CHARSET[v] for v in values + checksum)


def decode_bech32m(address: str) -> Tuple[str, int, bytes]:
    """
    Decode Bech32m address.
    
    Args:
        address: Bech32m address
        
    Returns:
        Tuple of (hrp, witness_version, witness_program)
        
    Raises:
        ValidationError: If address is invalid
    """
    # Find separator
    pos = address.rfind("1")
    if pos < 1:
        raise ValidationError("Invalid Bech32m address: no separator")
        
    hrp = address[:pos]
    data = address[pos + 1:]
    
    # Decode data
    values = []
    for char in data:
        try:
            values.append(BECH32_CHARSET.index(char))
        except ValueError:
            raise ValidationError(f"Invalid Bech32m character: {char}")
            
    # Verify checksum with Bech32m constant
    if _bech32m_polymod(_bech32_hrp_expand(hrp) + values) != 0x2bc830a3:
        raise ValidationError("Invalid Bech32m checksum")
        
    # Extract witness version and program
    witver = values[0]
    witprog_5bit = values[1:-6]  # Remove checksum
    
    # Convert from 5-bit to 8-bit
    bits = 0
    value = 0
    witprog = bytearray()
    
    for v in witprog_5bit:
        value = (value << 5) | v
        bits += 5
        while bits >= 8:
            bits -= 8
            witprog.append((value >> bits) & 255)
            
    return hrp, witver, bytes(witprog)



def decode_address(address: str, network: Network = Network.MAINNET) -> Tuple[str, bytes]:
    """
    Decode Bitcoin address to type and hash.
    
    Args:
        address: Bitcoin address
        network: Network for validation
        
    Returns:
        Tuple of (address_type, hash_bytes)
        
    Raises:
        ValidationError: If address is invalid
    """
    # Try Bech32/Bech32m
    if address.lower().startswith(("bc1", "tb1")):
        try:
            expected_hrp = BECH32_HRP[network]
            
            # Try Bech32 first (for SegWit v0)
            try:
                hrp, witver, witprog = decode_bech32(address.lower())
            except ValidationError:
                # Try Bech32m (for Taproot and future versions)
                hrp, witver, witprog = decode_bech32m(address.lower())
            
            if hrp != expected_hrp:
                raise ValidationError(f"Wrong network: expected {expected_hrp}, got {hrp}")
                
            if witver == 0:
                if len(witprog) == 20:
                    return "p2wpkh", witprog
                elif len(witprog) == 32:
                    return "p2wsh", witprog
            elif witver == 1 and len(witprog) == 32:
                return "p2tr", witprog
                
            raise ValidationError(f"Unknown witness version: {witver}")
            
        except Exception as e:
            raise ValidationError(f"Invalid Bech32/Bech32m address: {e}") from e
            
    # Try Base58Check (existing code unchanged)
    try:
        decoded = decode_base58_check(address)
        if len(decoded) != 21:
            raise ValidationError("Invalid address length")
            
        version = decoded[0:1]
        hash_bytes = decoded[1:]
        
        if version == ADDRESS_PREFIXES["p2pkh"][network]:
            return "p2pkh", hash_bytes
        elif version == ADDRESS_PREFIXES["p2sh"][network]:
            return "p2sh", hash_bytes
        else:
            raise ValidationError(f"Unknown address version: {version.hex()}")
            
    except Exception as e:
        raise ValidationError(f"Invalid Base58 address: {e}") from e


def encode_address(
    address_type: str,
    hash_bytes: bytes,
    network: Network = Network.MAINNET
) -> Address:
    """
    Encode hash as Bitcoin address.
    
    Args:
        address_type: Type of address (p2pkh, p2sh, p2wpkh, p2wsh, p2tr)
        hash_bytes: Hash to encode
        network: Target network
        
    Returns:
        Encoded address
        
    Raises:
        ValidationError: If parameters are invalid
    """
    if address_type == "p2pkh":
        if len(hash_bytes) != 20:
            raise ValidationError("P2PKH requires 20-byte hash")
        prefix = ADDRESS_PREFIXES["p2pkh"][network]
        return Address(encode_base58_check(prefix + hash_bytes))
        
    elif address_type == "p2sh":
        if len(hash_bytes) != 20:
            raise ValidationError("P2SH requires 20-byte hash")
        prefix = ADDRESS_PREFIXES["p2sh"][network]
        return Address(encode_base58_check(prefix + hash_bytes))
        
    elif address_type == "p2wpkh":
        if len(hash_bytes) != 20:
            raise ValidationError("P2WPKH requires 20-byte hash")
        hrp = BECH32_HRP[network]
        return Address(encode_bech32(hrp, 0, hash_bytes))  # SegWit v0 использует Bech32
        
    elif address_type == "p2wsh":
        if len(hash_bytes) != 32:
            raise ValidationError("P2WSH requires 32-byte hash")
        hrp = BECH32_HRP[network]
        return Address(encode_bech32(hrp, 0, hash_bytes))  # SegWit v0 использует Bech32
        
    elif address_type == "p2tr":
        if len(hash_bytes) != 32:
            raise ValidationError("P2TR requires 32-byte hash")
        hrp = BECH32_HRP[network]
        # ✅ ИСПРАВЛЕНО: Taproot использует Bech32m!
        return Address(encode_bech32m(hrp, 1, hash_bytes))
        
    else:
        raise ValidationError(f"Unknown address type: {address_type}")


def serialize_script(script_ops: List[Union[int, bytes]]) -> bytes:
    """
    Serialize script operations to bytes.
    
    Args:
        script_ops: List of opcodes (int) and data (bytes)
        
    Returns:
        Serialized script
    """
    result = bytearray()
    
    for op in script_ops:
        if isinstance(op, int):
            result.append(op)
        elif isinstance(op, bytes):
            # Push data
            if len(op) <= 75:
                result.append(len(op))
            elif len(op) <= 255:
                result.extend([0x4c, len(op)])  # OP_PUSHDATA1
            elif len(op) <= 65535:
                result.append(0x4d)  # OP_PUSHDATA2
                result.extend(struct.pack("<H", len(op)))
            else:
                result.append(0x4e)  # OP_PUSHDATA4
                result.extend(struct.pack("<I", len(op)))
            result.extend(op)
            
    return bytes(result)


def deserialize_script(script: bytes) -> List[Union[int, bytes]]:
    """
    Deserialize script bytes to operations.
    
    Args:
        script: Script bytes
        
    Returns:
        List of opcodes and data
    """
    ops = []
    i = 0
    
    while i < len(script):
        op = script[i]
        i += 1
        
        # Push data opcodes
        if 1 <= op <= 75:
            ops.append(script[i:i + op])
            i += op
        elif op == 0x4c:  # OP_PUSHDATA1
            size = script[i]
            i += 1
            ops.append(script[i:i + size])
            i += size
        elif op == 0x4d:  # OP_PUSHDATA2
            size = struct.unpack_from("<H", script, i)[0]
            i += 2
            ops.append(script[i:i + size])
            i += size
        elif op == 0x4e:  # OP_PUSHDATA4
            size = struct.unpack_from("<I", script, i)[0]
            i += 4
            ops.append(script[i:i + size])
            i += size
        else:
            # Regular opcode
            ops.append(op)
            
    return ops


def tagged_hash(tag: str, data: bytes) -> bytes:
    """
    Compute tagged hash as specified in BIP 340.
    
    Args:
        tag: Tag for the hash
        data: Data to hash
        
    Returns:
        Tagged hash
    """
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + data).digest()


def lift_x(x: bytes) -> Optional[bytes]:
    """
    Lift x-coordinate to full point (BIP 340).
    
    Args:
        x: 32-byte x-coordinate
        
    Returns:
        33-byte compressed public key or None if invalid
    """
    if len(x) != 32:
        return None
        
    # Check if x is valid field element
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    x_int = int.from_bytes(x, "big")
    
    if x_int >= p:
        return None
        
    # Compute y^2 = x^3 + 7 (mod p)
    y_squared = (pow(x_int, 3, p) + 7) % p
    
    # Check if y_squared is a quadratic residue
    y = pow(y_squared, (p + 1) // 4, p)
    if pow(y, 2, p) != y_squared:
        return None
        
    # Use even y (BIP 340 convention)
    if y % 2 != 0:
        y = p - y
        
    # Return as compressed point
    return b"\x02" + x  # Even y, so use 0x02 prefix