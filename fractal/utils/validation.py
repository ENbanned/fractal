"""Validation utilities for Fractal Bitcoin."""

import re
from typing import Union, Optional
from decimal import Decimal

from ..constants import (
    MAX_SUPPLY,
    SATOSHIS_PER_BITCOIN,
    DUST_LIMIT,
    MAX_SCRIPT_SIZE,
    Network,
)
from ..exceptions import ValidationError
from ..types.common import Satoshi, BTC, Amount
from ..utils.encoding import decode_address

__all__ = [
    "is_valid_address",
    "validate_address",
    "is_valid_txid",
    "validate_txid",
    "is_valid_block_hash",
    "validate_block_hash",
    "is_valid_amount",
    "validate_amount",
    "to_satoshi",
    "to_btc",
    "is_valid_private_key",
    "validate_private_key",
    "is_valid_public_key",
    "validate_public_key",
    "is_valid_script",
    "validate_script",
    "is_dust_amount",
]

# Regex patterns
TXID_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")
BLOCK_HASH_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")
HEX_PATTERN = re.compile(r"^[0-9a-fA-F]*$")


def is_valid_address(address: str, network: Optional[Network] = None) -> bool:
    """
    Check if Bitcoin address format is valid.
    
    Args:
        address: Address to validate
        network: Optional network to validate against
        
    Returns:
        True if valid, False otherwise
    """
    try:
        if network is not None:
            decode_address(address, network)
        else:
            # Try both networks
            try:
                decode_address(address, Network.MAINNET)
            except ValidationError:
                decode_address(address, Network.TESTNET)
        return True
    except ValidationError:
        return False


def validate_address(address: str, network: Optional[Network] = None) -> str:
    """
    Validate Bitcoin address and return normalized form.
    
    Args:
        address: Address to validate
        network: Optional network to validate against
        
    Returns:
        Normalized address
        
    Raises:
        ValidationError: If address is invalid
    """
    if not address:
        raise ValidationError("Address cannot be empty")
        
    # Normalize Bech32 to lowercase
    if address.lower().startswith(("bc1", "tb1")):
        address = address.lower()
        
    if not is_valid_address(address, network):
        raise ValidationError(f"Invalid Bitcoin address: {address}")
        
    return address


def is_valid_txid(txid: str) -> bool:
    """
    Check if transaction ID format is valid.
    
    Args:
        txid: Transaction ID to validate
        
    Returns:
        True if valid, False otherwise
    """
    return bool(TXID_PATTERN.match(txid))


def validate_txid(txid: str) -> str:
    """
    Validate transaction ID and return normalized form.
    
    Args:
        txid: Transaction ID to validate
        
    Returns:
        Normalized txid (lowercase)
        
    Raises:
        ValidationError: If txid is invalid
    """
    if not txid:
        raise ValidationError("Transaction ID cannot be empty")
        
    txid = txid.lower()
    
    if not is_valid_txid(txid):
        raise ValidationError(f"Invalid transaction ID: {txid}")
        
    return txid


def is_valid_block_hash(block_hash: str) -> bool:
    """
    Check if block hash format is valid.
    
    Args:
        block_hash: Block hash to validate
        
    Returns:
        True if valid, False otherwise
    """
    return bool(BLOCK_HASH_PATTERN.match(block_hash))


def validate_block_hash(block_hash: str) -> str:
    """
    Validate block hash and return normalized form.
    
    Args:
        block_hash: Block hash to validate
        
    Returns:
        Normalized block hash (lowercase)
        
    Raises:
        ValidationError: If block hash is invalid
    """
    if not block_hash:
        raise ValidationError("Block hash cannot be empty")
        
    block_hash = block_hash.lower()
    
    if not is_valid_block_hash(block_hash):
        raise ValidationError(f"Invalid block hash: {block_hash}")
        
    return block_hash


def is_valid_amount(amount: Amount) -> bool:
    """
    Check if amount is valid.
    
    Args:
        amount: Amount to validate
        
    Returns:
        True if valid, False otherwise
    """
    try:
        satoshi = to_satoshi(amount)
        return 0 <= satoshi <= MAX_SUPPLY
    except (ValueError, TypeError, ArithmeticError):
        return False


def validate_amount(amount: Amount) -> Satoshi:
    """
    Validate amount and convert to Satoshi.
    
    Args:
        amount: Amount to validate
        
    Returns:
        Amount in satoshis
        
    Raises:
        ValidationError: If amount is invalid
    """
    try:
        satoshi = to_satoshi(amount)
    except (ValueError, TypeError, ArithmeticError) as e:
        raise ValidationError(f"Invalid amount: {amount}") from e
        
    if satoshi < 0:
        raise ValidationError(f"Amount cannot be negative: {amount}")
        
    if satoshi > MAX_SUPPLY:
        raise ValidationError(f"Amount exceeds maximum supply: {amount}")
        
    return satoshi


def to_satoshi(amount: Amount) -> Satoshi:
    """
    Convert amount to satoshis.
    
    Args:
        amount: Amount in various formats
        
    Returns:
        Amount in satoshis
        
    Raises:
        ValueError: If conversion fails
    """
    if isinstance(amount, int):
        return Satoshi(amount)
        
    if isinstance(amount, (float, Decimal)):
        # Convert BTC to satoshis
        decimal_amount = Decimal(str(amount))
        satoshis = int(decimal_amount * SATOSHIS_PER_BITCOIN)
        return Satoshi(satoshis)
        
    if isinstance(amount, str):
        # Try to parse as float/decimal
        try:
            return to_satoshi(Decimal(amount))
        except:
            raise ValueError(f"Cannot convert string to amount: {amount}")
            
    raise TypeError(f"Unsupported amount type: {type(amount)}")


def to_btc(satoshis: Union[Satoshi, int]) -> BTC:
    """
    Convert satoshis to BTC.
    
    Args:
        satoshis: Amount in satoshis
        
    Returns:
        Amount in BTC
    """
    return BTC(Decimal(satoshis) / Decimal(SATOSHIS_PER_BITCOIN))


def is_dust_amount(amount: Union[Satoshi, int]) -> bool:
    """
    Check if amount is below dust limit.
    
    Args:
        amount: Amount in satoshis
        
    Returns:
        True if amount is dust, False otherwise
    """
    return amount < DUST_LIMIT


def is_valid_private_key(key: Union[str, bytes]) -> bool:
    """
    Check if private key format is valid.
    
    Args:
        key: Private key as hex string or bytes
        
    Returns:
        True if valid, False otherwise
    """
    try:
        if isinstance(key, str):
            if key.startswith("0x"):
                key = key[2:]
            if not HEX_PATTERN.match(key):
                return False
            key = bytes.fromhex(key)
            
        # Check length (32 bytes)
        if len(key) != 32:
            return False
            
        # Check if within valid range (1 to n-1)
        # secp256k1 order
        n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        key_int = int.from_bytes(key, "big")
        
        return 0 < key_int < n
        
    except (ValueError, TypeError):
        return False


def validate_private_key(key: Union[str, bytes]) -> bytes:
    """
    Validate private key and return as bytes.
    
    Args:
        key: Private key as hex string or bytes
        
    Returns:
        Private key as 32 bytes
        
    Raises:
        ValidationError: If private key is invalid
    """
    if isinstance(key, str):
        if key.startswith("0x"):
            key = key[2:]
        if not HEX_PATTERN.match(key):
            raise ValidationError("Private key must be hexadecimal")
        try:
            key = bytes.fromhex(key)
        except ValueError as e:
            raise ValidationError(f"Invalid hex private key: {e}") from e
            
    if len(key) != 32:
        raise ValidationError(f"Private key must be 32 bytes, got {len(key)}")
        
    # Check range
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    key_int = int.from_bytes(key, "big")
    
    if key_int == 0:
        raise ValidationError("Private key cannot be zero")
    if key_int >= n:
        raise ValidationError("Private key exceeds curve order")
        
    return key


def is_valid_public_key(key: Union[str, bytes]) -> bool:
    """
    Check if public key format is valid.
    
    Args:
        key: Public key as hex string or bytes
        
    Returns:
        True if valid, False otherwise
    """
    try:
        if isinstance(key, str):
            if key.startswith("0x"):
                key = key[2:]
            if not HEX_PATTERN.match(key):
                return False
            key = bytes.fromhex(key)
            
        # Check length (33 for compressed, 65 for uncompressed)
        if len(key) == 33:
            # Compressed: must start with 0x02 or 0x03
            return key[0] in (0x02, 0x03)
        elif len(key) == 65:
            # Uncompressed: must start with 0x04
            return key[0] == 0x04
        else:
            return False
            
    except (ValueError, TypeError):
        return False


def validate_public_key(key: Union[str, bytes]) -> bytes:
    """
    Validate public key and return as bytes.
    
    Args:
        key: Public key as hex string or bytes
        
    Returns:
        Public key bytes (33 or 65 bytes)
        
    Raises:
        ValidationError: If public key is invalid
    """
    if isinstance(key, str):
        if key.startswith("0x"):
            key = key[2:]
        if not HEX_PATTERN.match(key):
            raise ValidationError("Public key must be hexadecimal")
        try:
            key = bytes.fromhex(key)
        except ValueError as e:
            raise ValidationError(f"Invalid hex public key: {e}") from e
            
    if len(key) == 33:
        if key[0] not in (0x02, 0x03):
            raise ValidationError("Compressed public key must start with 0x02 or 0x03")
    elif len(key) == 65:
        if key[0] != 0x04:
            raise ValidationError("Uncompressed public key must start with 0x04")
    else:
        raise ValidationError(f"Public key must be 33 or 65 bytes, got {len(key)}")
        
    return key


def is_valid_script(script: Union[str, bytes]) -> bool:
    """
    Check if script format is valid.
    
    Args:
        script: Script as hex string or bytes
        
    Returns:
        True if valid, False otherwise
    """
    try:
        if isinstance(script, str):
            if script.startswith("0x"):
                script = script[2:]
            if not HEX_PATTERN.match(script):
                return False
            script = bytes.fromhex(script)
            
        # Check size limit
        return 0 <= len(script) <= MAX_SCRIPT_SIZE
        
    except (ValueError, TypeError):
        return False


def validate_script(script: Union[str, bytes]) -> bytes:
    """
    Validate script and return as bytes.
    
    Args:
        script: Script as hex string or bytes
        
    Returns:
        Script bytes
        
    Raises:
        ValidationError: If script is invalid
    """
    if isinstance(script, str):
        if script.startswith("0x"):
            script = script[2:]
        if not HEX_PATTERN.match(script):
            raise ValidationError("Script must be hexadecimal")
        try:
            script = bytes.fromhex(script)
        except ValueError as e:
            raise ValidationError(f"Invalid hex script: {e}") from e
            
    if len(script) > MAX_SCRIPT_SIZE:
        raise ValidationError(f"Script exceeds maximum size of {MAX_SCRIPT_SIZE} bytes")
        
    return script