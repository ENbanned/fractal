"""Common type definitions for Fractal Bitcoin."""

from typing import NewType, TypeAlias, Union
from decimal import Decimal

__all__ = [
    "HexStr",
    "Satoshi", 
    "BTC",
    "BlockHeight",
    "Timestamp",
    "TxId",
    "BlockHash",
    "Address",
    "ScriptPubKey",
    "PrivateKeyBytes",
    "PublicKeyBytes",
    "Signature",
]

# Basic types
HexStr = NewType("HexStr", str)
"""Hexadecimal string representation."""

Satoshi = NewType("Satoshi", int)
"""Satoshi amount (smallest unit)."""

BTC = NewType("BTC", Decimal)
"""Bitcoin amount in BTC."""

BlockHeight = NewType("BlockHeight", int)
"""Block height number."""

Timestamp = NewType("Timestamp", int)
"""Unix timestamp."""

# Identifiers
TxId = NewType("TxId", str)
"""Transaction ID (hash)."""

BlockHash = NewType("BlockHash", str)
"""Block hash."""

Address = NewType("Address", str)
"""Bitcoin address string."""

ScriptPubKey = NewType("ScriptPubKey", str)
"""Script public key hex."""

# Crypto types
PrivateKeyBytes = NewType("PrivateKeyBytes", bytes)
"""32-byte private key."""

PublicKeyBytes = NewType("PublicKeyBytes", bytes)
"""33 or 65 byte public key."""

Signature = NewType("Signature", bytes)
"""DER-encoded signature."""

# Type aliases
Amount = Union[Satoshi, BTC, int, float, Decimal]
"""Flexible amount type that can be converted."""

BlockIdentifier = Union[BlockHeight, BlockHash, str, int]
"""Block can be identified by height or hash."""

TransactionIdentifier = Union[TxId, str]
"""Transaction identifier."""