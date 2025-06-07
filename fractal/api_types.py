"""API response type definitions for Fractal Bitcoin."""

from dataclasses import dataclass
from typing import Any, Optional, TypedDict

__all__ = [
    "DifficultyAdjustment",
    "PriceInfo",
    "AddressStats",
    "TransactionStatus",
    "BlockExtra",
    "MempoolInfo",
    "FeeEstimates",
    "MiningPoolInfo",
    "LightningNodeInfo",
    "AccelerationInfo",
]


class DifficultyAdjustment(TypedDict):
    """Difficulty adjustment information."""
    progressPercent: float
    difficultyChange: float
    estimatedRetargetDate: int
    remainingBlocks: int
    remainingTime: int
    previousRetarget: float
    nextRetargetHeight: int
    timeAvg: int
    adjustedTimeAvg: int
    timeOffset: int


class PriceInfo(TypedDict):
    """Bitcoin price information."""
    time: int
    USD: int
    EUR: int
    GBP: int
    CAD: int
    CHF: int
    AUD: int
    JPY: int


class ChainStats(TypedDict):
    """Chain statistics for address."""
    funded_txo_count: int
    funded_txo_sum: int
    spent_txo_count: int
    spent_txo_sum: int
    tx_count: int


class AddressStats(TypedDict):
    """Address statistics."""
    address: str
    chain_stats: ChainStats
    mempool_stats: ChainStats


class TransactionStatus(TypedDict):
    """Transaction confirmation status."""
    confirmed: bool
    block_height: Optional[int]
    block_hash: Optional[str]
    block_time: Optional[int]


@dataclass
class PoolInfo:
    """Mining pool information."""
    id: int
    name: str
    slug: str


@dataclass
class BlockExtra:
    """Extra block information."""
    reward: int
    coinbaseRaw: str
    coinbaseTx: dict[str, Any]
    medianFee: int
    feeRange: list[int]
    totalFees: int
    avgFee: int
    avgFeeRate: int
    pool: Optional[PoolInfo]
    matchRate: Optional[float]


class MempoolInfo(TypedDict):
    """Mempool statistics."""
    count: int
    vsize: int
    total_fee: int
    fee_histogram: list[list[int]]


class FeeEstimates(TypedDict):
    """Fee rate estimates."""
    fastestFee: int
    halfHourFee: int
    hourFee: int
    economyFee: int
    minimumFee: int


@dataclass
class MiningPoolInfo:
    """Mining pool details."""
    poolId: int
    name: str
    link: str
    blockCount: int
    rank: int
    emptyBlocks: int
    slug: str


@dataclass
class LightningNodeInfo:
    """Lightning node information."""
    public_key: str
    alias: str
    capacity: Optional[int]
    channels: Optional[int]
    first_seen: Optional[int]
    updated_at: Optional[int]
    color: Optional[str]
    city: Optional[dict[str, str]]
    country: Optional[dict[str, str]]


@dataclass
class AccelerationInfo:
    """Transaction acceleration information."""
    txid: str
    added: int
    feeDelta: int
    effectiveVsize: int
    effectiveFee: int
    pools: list[int]
    status: Optional[str]
    blockHash: Optional[str]
    blockHeight: Optional[int]