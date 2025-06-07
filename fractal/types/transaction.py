"""Transaction-related type definitions for Fractal Bitcoin."""

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional, Union, List
from decimal import Decimal

from ..types.common import (
    HexStr,
    Satoshi,
    BTC,
    Timestamp,
    TxId,
    BlockHash,
    BlockHeight,
    ScriptPubKey,
    Address,
    Signature,
)

__all__ = [
    "TransactionInput",
    "TransactionOutput",
    "Transaction",
    "RawTransaction",
    "TransactionBuilder",
    "SigHashType",
    "ScriptType",
    "OutPoint",
    "WitnessData",
]


class SigHashType(IntEnum):
    """Signature hash types."""
    ALL = 0x01
    NONE = 0x02
    SINGLE = 0x03
    ANYONECANPAY = 0x80
    ALL_ANYONECANPAY = 0x81
    NONE_ANYONECANPAY = 0x82
    SINGLE_ANYONECANPAY = 0x83


class ScriptType(str):
    """Script types."""
    P2PKH = "p2pkh"
    P2SH = "p2sh"
    P2WPKH = "p2wpkh"
    P2WSH = "p2wsh"
    P2TR = "p2tr"
    NULLDATA = "nulldata"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class OutPoint:
    """Transaction output reference."""
    txid: TxId
    vout: int
    
    @property
    def bytes(self) -> bytes:
        """Get outpoint as bytes (txid + vout)."""
        txid_bytes = bytes.fromhex(self.txid)[::-1]  # Little-endian
        vout_bytes = self.vout.to_bytes(4, "little")
        return txid_bytes + vout_bytes
        
    def __str__(self) -> str:
        """String representation as txid:vout."""
        return f"{self.txid}:{self.vout}"


@dataclass(frozen=True)
class WitnessData:
    """Segregated witness data."""
    stack: List[HexStr]
    
    @property
    def is_empty(self) -> bool:
        """Check if witness is empty."""
        return len(self.stack) == 0
        
    @property
    def bytes(self) -> bytes:
        """Serialize witness data."""
        result = bytearray()
        result.append(len(self.stack))
        for item in self.stack:
            data = bytes.fromhex(item)
            if len(data) < 0xfd:
                result.append(len(data))
            else:
                result.append(0xfd)
                result.extend(len(data).to_bytes(2, "little"))
            result.extend(data)
        return bytes(result)


@dataclass(frozen=True)
class TransactionInput:
    """Transaction input."""
    
    # Required fields
    outpoint: OutPoint
    sequence: int = 0xFFFFFFFE  # RBF enabled by default
    
    # Script fields
    script_sig: HexStr = HexStr("")
    script_sig_asm: Optional[str] = None
    
    # Witness data (SegWit)
    witness: Optional[WitnessData] = None
    
    # Additional info
    is_coinbase: bool = False
    prevout: Optional[dict] = None  # Previous output details
    
    @property
    def txid(self) -> TxId:
        """Get previous transaction ID."""
        return self.outpoint.txid
        
    @property 
    def vout(self) -> int:
        """Get previous output index."""
        return self.outpoint.vout
        
    @property
    def is_rbf(self) -> bool:
        """Check if RBF is signaled."""
        return self.sequence < 0xFFFFFFFE
        
    @property
    def is_final(self) -> bool:
        """Check if input is final."""
        return self.sequence == 0xFFFFFFFF


@dataclass(frozen=True)
class TransactionOutput:
    """Transaction output."""
    
    # Required fields
    value: Satoshi
    script_pubkey: ScriptPubKey
    
    # Decoded script info
    script_pubkey_asm: Optional[str] = None
    script_pubkey_type: Optional[ScriptType] = None
    script_pubkey_address: Optional[Address] = None
    
    @property
    def is_spendable(self) -> bool:
        """Check if output is spendable (not OP_RETURN)."""
        return self.script_pubkey_type != ScriptType.NULLDATA
        
    @property
    def btc_value(self) -> BTC:
        """Get value in BTC."""
        return BTC(Decimal(self.value) / Decimal(100_000_000))


@dataclass
class Transaction:
    """Complete transaction information."""
    
    # Transaction data
    txid: TxId
    version: int
    locktime: int
    size: int
    vsize: int  # Virtual size for fee calculation
    weight: int  # BIP141 weight
    fee: Satoshi
    
    # Inputs and outputs
    vin: List[TransactionInput]
    vout: List[TransactionOutput]
    
    # Confirmation status
    status: dict = field(default_factory=dict)
    
    # Optional fields
    hex: Optional[HexStr] = None
    blockhash: Optional[BlockHash] = None
    blockheight: Optional[BlockHeight] = None
    blocktime: Optional[Timestamp] = None
    confirmations: int = 0
    
    @property
    def is_confirmed(self) -> bool:
        """Check if transaction is confirmed."""
        return self.status.get("confirmed", False)
        
    @property
    def is_coinbase(self) -> bool:
        """Check if transaction is coinbase."""
        return len(self.vin) == 1 and self.vin[0].is_coinbase
        
    @property
    def total_input_value(self) -> Optional[Satoshi]:
        """Calculate total input value if prevouts are available."""
        if not all(inp.prevout for inp in self.vin):
            return None
        return Satoshi(sum(inp.prevout["value"] for inp in self.vin))
        
    @property
    def total_output_value(self) -> Satoshi:
        """Calculate total output value."""
        return Satoshi(sum(out.value for out in self.vout))
        
    @property
    def fee_rate(self) -> float:
        """Calculate fee rate in sats/vByte."""
        if self.vsize == 0:
            return 0.0
        return self.fee / self.vsize
        
    @property
    def is_rbf(self) -> bool:
        """Check if transaction signals RBF."""
        return any(inp.is_rbf for inp in self.vin)
        
    def get_output(self, index: int) -> Optional[TransactionOutput]:
        """Get output by index."""
        if 0 <= index < len(self.vout):
            return self.vout[index]
        return None


@dataclass
class RawTransaction:
    """Raw transaction for building and signing."""
    
    version: int = 2
    locktime: int = 0
    inputs: List[TransactionInput] = field(default_factory=list)
    outputs: List[TransactionOutput] = field(default_factory=list)
    
    def add_input(
        self,
        txid: Union[TxId, str],
        vout: int,
        sequence: int = 0xFFFFFFFE,
        script_sig: Union[HexStr, str] = "",
        witness: Optional[List[str]] = None,
    ) -> "RawTransaction":
        """Add input to transaction."""
        outpoint = OutPoint(TxId(txid), vout)
        witness_data = WitnessData(witness) if witness else None
        
        self.inputs.append(
            TransactionInput(
                outpoint=outpoint,
                sequence=sequence,
                script_sig=HexStr(script_sig),
                witness=witness_data,
            )
        )
        return self
        
    def add_output(
        self,
        value: Union[Satoshi, int],
        script_pubkey: Union[ScriptPubKey, str],
        address: Optional[Union[Address, str]] = None,
    ) -> "RawTransaction":
        """Add output to transaction."""
        self.outputs.append(
            TransactionOutput(
                value=Satoshi(value),
                script_pubkey=ScriptPubKey(script_pubkey),
                script_pubkey_address=Address(address) if address else None,
            )
        )
        return self
        
    def add_data_output(self, data: bytes) -> "RawTransaction":
        """Add OP_RETURN output with data."""
        if len(data) > 80:
            raise ValueError("OP_RETURN data must be <= 80 bytes")
            
        # Build OP_RETURN script
        script = bytearray([0x6a])  # OP_RETURN
        if len(data) <= 75:
            script.append(len(data))
        else:
            script.extend([0x4c, len(data)])  # OP_PUSHDATA1
        script.extend(data)
        
        return self.add_output(
            value=0,
            script_pubkey=script.hex(),
        )
        
    @property
    def is_segwit(self) -> bool:
        """Check if transaction uses SegWit."""
        return any(inp.witness and not inp.witness.is_empty for inp in self.inputs)
        
    def estimate_size(self) -> int:
        """Estimate transaction size in bytes."""
        return self._calculate_base_size() + self._calculate_witness_size()
        
    def _calculate_witness_size(self) -> int:
        """Calculate witness data size."""
        if not self.is_segwit:
            return 0
            
        witness_size = 2  # marker + flag
        for inp in self.inputs:
            if inp.witness and not inp.witness.is_empty:
                witness_size += 107  # typical witness size
        return witness_size
        
    def _calculate_base_size(self) -> int:
        """Calculate base transaction size (without witness data)."""
        return (
            4 +  # version
            1 +  # input count (compact)
            len(self.inputs) * 41 +  # inputs (approx)
            1 +  # output count (compact)  
            len(self.outputs) * 33 +  # outputs (approx)
            4    # locktime
        )
        
    def estimate_vsize(self) -> int:
        """Estimate virtual size for fee calculation."""
        base_size = self._calculate_base_size()
        witness_size = self._calculate_witness_size()
        
        if witness_size == 0:
            return base_size
            
        # Calculate weight: base_size * 4 + witness_size
        total_weight = base_size * 4 + witness_size
        return (total_weight + 3) // 4  # Round up


@dataclass
class TransactionBuilder:
    """
    High-level transaction builder.
    
    Provides convenient methods for building transactions with
    automatic fee estimation and change calculation.
    """
    
    raw_tx: RawTransaction = field(default_factory=RawTransaction)
    fee_rate: Optional[float] = None  # sats/vByte
    change_address: Optional[Address] = None
    
    def add_input(self, *args, **kwargs) -> "TransactionBuilder":
        """Add input to transaction."""
        self.raw_tx.add_input(*args, **kwargs)
        return self
        
    def add_output(self, *args, **kwargs) -> "TransactionBuilder":
        """Add output to transaction."""
        self.raw_tx.add_output(*args, **kwargs)
        return self
        
    def set_fee_rate(self, fee_rate: float) -> "TransactionBuilder":
        """Set fee rate in sats/vByte."""
        self.fee_rate = fee_rate
        return self
        
    def set_change_address(self, address: Union[Address, str]) -> "TransactionBuilder":
        """Set change address."""
        self.change_address = Address(address)
        return self
        
    def calculate_fee(self) -> Satoshi:
        """Calculate transaction fee."""
        if not self.fee_rate:
            raise ValueError("Fee rate not set")
            
        vsize = self.raw_tx.estimate_vsize()
        return Satoshi(int(vsize * self.fee_rate))