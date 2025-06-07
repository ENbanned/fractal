"""Address-related type definitions for Fractal Bitcoin."""

from dataclasses import dataclass
from enum import Enum
from typing import Optional, List, Dict, Any

from ..types.common import (
    Address as AddressStr,
    HexStr,
    Satoshi,
    TxId,
    ScriptPubKey,
    BlockHeight,
    Timestamp,
)
from ..types.transaction import OutPoint, ScriptType

__all__ = [
    "AddressType",
    "Address",
    "AddressInfo",
    "UTXO",
    "ExtendedUTXO",
    "AddressTransaction",
    "ScriptInfo",
]


class AddressType(str, Enum):
    """Bitcoin address types."""
    
    P2PKH = "p2pkh"  # Legacy (1...)
    P2SH = "p2sh"    # Multi-sig (3...)
    P2WPKH = "p2wpkh"  # SegWit (bc1q...)
    P2WSH = "p2wsh"    # SegWit script (bc1q...)
    P2TR = "p2tr"      # Taproot (bc1p...)
    UNKNOWN = "unknown"
    
    @classmethod
    def from_address(cls, address: str) -> "AddressType":
        """Determine address type from string."""
        if address.startswith("1"):
            return cls.P2PKH
        elif address.startswith("3"):
            return cls.P2SH
        elif address.startswith("bc1q") or address.startswith("tb1q"):
            if len(address) == 42:
                return cls.P2WPKH
            else:
                return cls.P2WSH
        elif address.startswith("bc1p") or address.startswith("tb1p"):
            return cls.P2TR
        else:
            return cls.UNKNOWN


@dataclass(frozen=True)
class ScriptInfo:
    """Script public key information."""
    
    hex: ScriptPubKey
    asm: str
    type: ScriptType
    req_sigs: Optional[int] = None
    addresses: Optional[List[AddressStr]] = None
    
    @property
    def is_standard(self) -> bool:
        """Check if script is standard."""
        return self.type != ScriptType.UNKNOWN


@dataclass(frozen=True) 
class Address:
    """Enhanced address representation."""
    
    address: AddressStr
    script_pubkey: ScriptPubKey
    type: AddressType
    
    # Optional metadata
    label: Optional[str] = None
    is_mine: bool = False
    is_watch_only: bool = False
    
    def __str__(self) -> str:
        """String representation."""
        return self.address
        
    @property
    def is_segwit(self) -> bool:
        """Check if address is SegWit."""
        return self.type in (AddressType.P2WPKH, AddressType.P2WSH, AddressType.P2TR)
        
    @property
    def is_taproot(self) -> bool:
        """Check if address is Taproot."""
        return self.type == AddressType.P2TR


@dataclass
class AddressInfo:
    """Complete address information from API."""
    
    address: AddressStr
    
    # Balance information
    chain_stats: Dict[str, int]
    mempool_stats: Dict[str, int]
    
    # Optional extended info
    script_pubkey: Optional[ScriptPubKey] = None
    type: Optional[AddressType] = None
    
    @property
    def balance(self) -> Satoshi:
        """Get total balance (confirmed + unconfirmed)."""
        confirmed = self.confirmed_balance
        unconfirmed = self.unconfirmed_balance
        return Satoshi(confirmed + unconfirmed)
        
    @property
    def confirmed_balance(self) -> Satoshi:
        """Get confirmed balance."""
        funded = self.chain_stats.get("funded_txo_sum", 0)
        spent = self.chain_stats.get("spent_txo_sum", 0)
        return Satoshi(funded - spent)
        
    @property
    def unconfirmed_balance(self) -> Satoshi:
        """Get unconfirmed balance."""
        funded = self.mempool_stats.get("funded_txo_sum", 0)
        spent = self.mempool_stats.get("spent_txo_sum", 0)
        return Satoshi(funded - spent)
        
    @property
    def tx_count(self) -> int:
        """Get total transaction count."""
        chain_txs = self.chain_stats.get("tx_count", 0)
        mempool_txs = self.mempool_stats.get("tx_count", 0)
        return chain_txs + mempool_txs
        
    @property
    def funded_txo_count(self) -> int:
        """Get total funded TXO count."""
        chain = self.chain_stats.get("funded_txo_count", 0)
        mempool = self.mempool_stats.get("funded_txo_count", 0)
        return chain + mempool
        
    @property
    def spent_txo_count(self) -> int:
        """Get total spent TXO count."""
        chain = self.chain_stats.get("spent_txo_count", 0)
        mempool = self.mempool_stats.get("spent_txo_count", 0)
        return chain + mempool


@dataclass(frozen=True)
class UTXO:
    """Unspent transaction output."""
    
    # Output reference
    outpoint: OutPoint
    value: Satoshi
    
    # Confirmation status
    status: Dict[str, Any]
    
    # Optional fields
    script_pubkey: Optional[ScriptPubKey] = None
    address: Optional[AddressStr] = None
    
    @property
    def txid(self) -> TxId:
        """Get transaction ID."""
        return self.outpoint.txid
        
    @property
    def vout(self) -> int:
        """Get output index."""
        return self.outpoint.vout
        
    @property
    def is_confirmed(self) -> bool:
        """Check if UTXO is confirmed."""
        return self.status.get("confirmed", False)
        
    @property
    def confirmations(self) -> int:
        """Get number of confirmations."""
        if not self.is_confirmed:
            return 0
        # Would need current height to calculate
        return self.status.get("confirmations", 0)
        
    @property
    def block_height(self) -> Optional[BlockHeight]:
        """Get block height if confirmed."""
        if self.is_confirmed:
            return BlockHeight(self.status.get("block_height"))
        return None
        
    def __str__(self) -> str:
        """String representation."""
        return f"{self.outpoint}:{self.value}"


@dataclass(frozen=True)
class ExtendedUTXO(UTXO):
    """Extended UTXO with additional spending information."""
    
    # Spending conditions
    redeem_script: Optional[HexStr] = None
    witness_script: Optional[HexStr] = None
    
    # Descriptors
    descriptor: Optional[str] = None
    
    # BIP32 derivation
    derivation_path: Optional[str] = None
    
    # Metadata
    label: Optional[str] = None
    frozen: bool = False  # Coin control
    
    @property
    def is_witness(self) -> bool:
        """Check if UTXO requires witness."""
        return self.witness_script is not None
        
    @property
    def effective_value(self) -> Satoshi:
        """Get effective value after estimated fee to spend."""
        # Rough estimation: 148 bytes for P2PKH input
        estimated_fee = 148 * 1  # 1 sat/byte minimum
        return Satoshi(max(0, self.value - estimated_fee))


@dataclass
class AddressTransaction:
    """Transaction associated with an address."""
    
    txid: TxId
    address: AddressStr
    category: str  # "send" or "receive"
    amount: Satoshi
    vout: Optional[int] = None
    confirmations: int = 0
    blockhash: Optional[str] = None
    blockheight: Optional[BlockHeight] = None
    blocktime: Optional[Timestamp] = None
    
    @property
    def is_confirmed(self) -> bool:
        """Check if transaction is confirmed."""
        return self.confirmations > 0
        
    @property
    def is_receive(self) -> bool:
        """Check if this is a receive transaction."""
        return self.category == "receive"
        
    @property
    def is_send(self) -> bool:
        """Check if this is a send transaction."""
        return self.category == "send"