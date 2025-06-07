"""Block-related type definitions for Fractal Bitcoin."""

from dataclasses import dataclass
from typing import Optional, List, Dict, Any
from decimal import Decimal

from ..types.common import (
    BlockHash,
    BlockHeight,
    HexStr,
    Timestamp,
    Satoshi,
    BTC,
)
from ..types.transaction import Transaction

__all__ = [
    "BlockHeader",
    "Block",
    "BlockStats",
    "CompactBlock",
    "BlockFilter",
    "ChainTip",
    "BlockTemplate",
]


@dataclass(frozen=True)
class BlockHeader:
    """Block header information."""
    
    version: int
    previous_block_hash: BlockHash
    merkle_root: HexStr
    timestamp: Timestamp
    bits: int  # Compact difficulty representation
    nonce: int
    
    @property
    def hash(self) -> BlockHash:
        """Calculate block hash from header."""
        # This would need actual hashing implementation
        raise NotImplementedError("Header hashing not implemented")
        
    @property
    def difficulty(self) -> float:
        """Calculate difficulty from bits."""
        # Decode compact bits format
        exponent = self.bits >> 24
        mantissa = self.bits & 0xFFFFFF
        
        if mantissa > 0x7FFFFF:
            return 0.0
            
        target = mantissa * (256 ** (exponent - 3))
        max_target = 0x00000000FFFF0000000000000000000000000000000000000000000000000000
        
        return max_target / target if target > 0 else 0.0


@dataclass
class Block:
    """Complete block information."""
    
    # Block identifiers
    hash: BlockHash
    height: BlockHeight
    
    # Header fields
    version: int
    timestamp: Timestamp
    bits: int
    nonce: int
    merkle_root: HexStr
    
    # Block metadata
    size: int
    weight: int
    tx_count: int
    difficulty: float
    
    # Chain references
    previousblockhash: Optional[BlockHash]
    nextblockhash: Optional[BlockHash] = None
    
    # Additional info
    mediantime: Optional[Timestamp] = None
    chainwork: Optional[HexStr] = None
    confirmations: int = 0
    
    # Transaction data (optional)
    transactions: Optional[List[Transaction]] = None
    
    # Extra mining info
    extras: Optional[Dict[str, Any]] = None
    
    @property
    def header(self) -> BlockHeader:
        """Get block header."""
        return BlockHeader(
            version=self.version,
            previous_block_hash=self.previousblockhash or BlockHash("0" * 64),
            merkle_root=self.merkle_root,
            timestamp=self.timestamp,
            bits=self.bits,
            nonce=self.nonce,
        )
        
    @property
    def is_genesis(self) -> bool:
        """Check if this is the genesis block."""
        return self.height == 0
        
    @property
    def subsidy(self) -> Satoshi:
        """Calculate block subsidy (before fees)."""
        # Fractal Bitcoin subsidy calculation
        halvings = self.height // 2_100_000  # Halving every 2.1M blocks
        if halvings >= 64:
            return Satoshi(0)
            
        subsidy = 25 * 100_000_000  # 25 FB initial
        return Satoshi(subsidy >> halvings)
        
    @property
    def total_fees(self) -> Optional[Satoshi]:
        """Get total transaction fees if available."""
        if self.extras and "totalFees" in self.extras:
            return Satoshi(self.extras["totalFees"])
        return None
        
    @property
    def reward(self) -> Optional[Satoshi]:
        """Get total block reward if available."""
        if self.extras and "reward" in self.extras:
            return Satoshi(self.extras["reward"])
        return None
        
    @property
    def avg_fee_rate(self) -> Optional[float]:
        """Get average fee rate if available."""
        if self.extras and "avgFeeRate" in self.extras:
            return float(self.extras["avgFeeRate"])
        return None


@dataclass(frozen=True)
class BlockStats:
    """Block statistics."""
    
    height: BlockHeight
    blockhash: BlockHash
    
    # Fee statistics
    avg_fee: int
    avg_fee_rate: int
    max_fee: int
    max_fee_rate: int
    min_fee: int
    min_fee_rate: int
    total_fee: int
    
    # Size statistics  
    avg_tx_size: int
    total_size: int
    total_weight: int
    
    # Transaction statistics
    txs: int
    utxo_increase: int
    utxo_size_inc: int
    
    # Additional stats
    median_fee: Optional[int] = None
    median_time: Optional[Timestamp] = None
    
    @property
    def avg_fee_btc(self) -> BTC:
        """Get average fee in BTC."""
        return BTC(Decimal(self.avg_fee) / Decimal(100_000_000))


@dataclass
class CompactBlock:
    """Compact block representation for efficient transmission."""
    
    header: BlockHeader
    nonce: int
    short_tx_ids: List[int]
    prefilled_txs: List[tuple[int, Transaction]]
    
    @property
    def tx_count(self) -> int:
        """Get total transaction count."""
        return len(self.short_tx_ids) + len(self.prefilled_txs)


@dataclass(frozen=True)
class BlockFilter:
    """BIP157 compact block filter."""
    
    filter_type: int
    block_hash: BlockHash
    filter_data: bytes
    
    @property
    def filter_header(self) -> HexStr:
        """Calculate filter header hash."""
        # Would need actual implementation
        raise NotImplementedError("Filter header calculation not implemented")


@dataclass(frozen=True)
class ChainTip:
    """Chain tip information."""
    
    height: BlockHeight
    hash: BlockHash
    branchlen: int
    status: str  # "active", "valid-fork", "valid-headers", "headers-only", "invalid"
    
    @property
    def is_active(self) -> bool:
        """Check if this is the active chain tip."""
        return self.status == "active"


@dataclass
class BlockTemplate:
    """Mining block template."""
    
    # Template info
    version: int
    previousblockhash: BlockHash
    target: HexStr
    bits: int
    height: BlockHeight
    
    # Transaction selection
    transactions: List[Dict[str, Any]]
    coinbasevalue: Satoshi
    
    # Mining parameters
    mintime: Timestamp
    curtime: Timestamp
    
    # Additional fields
    capabilities: List[str] = None
    rules: List[str] = None
    vbavailable: Dict[str, int] = None
    vbrequired: int = 0
    
    @property
    def merkle_root(self) -> HexStr:
        """Calculate merkle root from transactions."""
        # Would need merkle tree implementation
        raise NotImplementedError("Merkle root calculation not implemented")
        
    @property
    def difficulty_target(self) -> int:
        """Get difficulty target as integer."""
        return int(self.target, 16)