"""Transaction module for Fractal Bitcoin."""

import logging
from typing import Optional, Dict, Any, List, Union

from ..exceptions import TransactionError, ValidationError, APIError
from ..providers.base import BaseProvider
from ..providers.http import HTTPProvider
from ..types.common import TxId, HexStr, TransactionIdentifier
from ..types.transaction import (
    Transaction,
    TransactionInput,
    TransactionOutput,
    OutPoint,
    WitnessData,
)
from ..utils.validation import validate_txid

__all__ = ["TransactionModule"]

logger = logging.getLogger(__name__)


class TransactionModule:
    """
    Transaction-related operations.
    
    Handles transaction retrieval, broadcasting, and analysis.
    """
    
    def __init__(self, provider: BaseProvider) -> None:
        """
        Initialize transaction module.
        
        Args:
            provider: Provider instance
        """
        self._provider = provider
        self._logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
    async def get(self, txid: TransactionIdentifier) -> Transaction:
        """
        Get transaction by ID.
        
        Args:
            txid: Transaction ID
            
        Returns:
            Transaction details
            
        Raises:
            TransactionError: If transaction not found
        """
        txid = validate_txid(str(txid))
        
        try:
            data = await self._provider.request(f"/tx/{txid}")
            
            # Parse inputs
            inputs = []
            for vin in data.get("vin", []):
                witness = None
                if vin.get("witness"):
                    witness = WitnessData(stack=vin["witness"])
                    
                inputs.append(TransactionInput(
                    outpoint=OutPoint(
                        txid=TxId(vin.get("txid", "")),
                        vout=vin.get("vout", 0)
                    ),
                    sequence=vin.get("sequence", 0xFFFFFFFF),
                    script_sig=HexStr(vin.get("scriptsig", "")),
                    script_sig_asm=vin.get("scriptsig_asm"),
                    witness=witness,
                    is_coinbase=vin.get("is_coinbase", False),
                    prevout=vin.get("prevout"),
                ))
                
            # Parse outputs
            outputs = []
            for vout in data.get("vout", []):
                outputs.append(TransactionOutput(
                    value=vout["value"],
                    script_pubkey=vout["scriptpubkey"],
                    script_pubkey_asm=vout.get("scriptpubkey_asm"),
                    script_pubkey_type=vout.get("scriptpubkey_type"),
                    script_pubkey_address=vout.get("scriptpubkey_address"),
                ))
                
            return Transaction(
                txid=TxId(data["txid"]),
                version=data["version"],
                locktime=data["locktime"],
                size=data["size"],
                vsize=data.get("weight", data["size"] * 4) // 4,  # Calculate vsize
                weight=data.get("weight", data["size"] * 4),
                fee=data.get("fee", 0),
                vin=inputs,
                vout=outputs,
                status=data.get("status", {}),
                blockhash=data["status"].get("block_hash") if data.get("status") else None,
                blockheight=data["status"].get("block_height") if data.get("status") else None,
                blocktime=data["status"].get("block_time") if data.get("status") else None,
                confirmations=data["status"].get("confirmations", 0) if data.get("status") else 0,
            )
            
        except APIError as e:
            if e.code == 404:
                raise TransactionError(f"Transaction not found: {txid}") from e
            raise TransactionError(f"Failed to get transaction: {e}") from e
        except Exception as e:
            self._logger.error(f"Failed to get transaction: {e}")
            raise TransactionError(f"Failed to get transaction: {e}") from e
            
    async def get_hex(self, txid: TransactionIdentifier) -> HexStr:
        """
        Get raw transaction hex.
        
        Args:
            txid: Transaction ID
            
        Returns:
            Raw transaction hex
        """
        txid = validate_txid(str(txid))
        
        try:
            data = await self._provider.request(f"/tx/{txid}/hex")
            return HexStr(data)
        except Exception as e:
            self._logger.error(f"Failed to get transaction hex: {e}")
            raise TransactionError(f"Failed to get transaction hex: {e}") from e
            
    async def get_merkle_proof(self, txid: TransactionIdentifier) -> Dict[str, Any]:
        """
        Get merkle proof for transaction.
        
        Args:
            txid: Transaction ID
            
        Returns:
            Merkle proof data
        """
        txid = validate_txid(str(txid))
        
        try:
            return await self._provider.request(f"/tx/{txid}/merkle-proof")
        except Exception as e:
            self._logger.error(f"Failed to get merkle proof: {e}")
            raise TransactionError(f"Failed to get merkle proof: {e}") from e
            
    async def get_outspend(
        self,
        txid: TransactionIdentifier,
        vout: int
    ) -> Dict[str, Any]:
        """
        Get spending status of transaction output.
        
        Args:
            txid: Transaction ID
            vout: Output index
            
        Returns:
            Outspend information
        """
        txid = validate_txid(str(txid))
        
        if vout < 0:
            raise ValidationError(f"Invalid output index: {vout}")
            
        try:
            return await self._provider.request(f"/tx/{txid}/outspend/{vout}")
        except Exception as e:
            self._logger.error(f"Failed to get outspend: {e}")
            raise TransactionError(f"Failed to get outspend: {e}") from e
            
    async def get_outspends(self, txid: TransactionIdentifier) -> List[Dict[str, Any]]:
        """
        Get spending status for all outputs.
        
        Args:
            txid: Transaction ID
            
        Returns:
            List of outspend information
        """
        txid = validate_txid(str(txid))
        
        try:
            return await self._provider.request(f"/tx/{txid}/outspends")
        except Exception as e:
            self._logger.error(f"Failed to get outspends: {e}")
            raise TransactionError(f"Failed to get outspends: {e}") from e
            
    async def get_status(self, txid: TransactionIdentifier) -> Dict[str, Any]:
        """
        Get transaction confirmation status.
        
        Args:
            txid: Transaction ID
            
        Returns:
            Status information
        """
        txid = validate_txid(str(txid))
        
        try:
            return await self._provider.request(f"/tx/{txid}/status")
        except Exception as e:
            self._logger.error(f"Failed to get transaction status: {e}")
            raise TransactionError(f"Failed to get transaction status: {e}") from e
            
    async def broadcast(self, raw_tx: Union[str, bytes]) -> TxId:
        """
        Broadcast raw transaction to network.
        
        Args:
            raw_tx: Raw transaction hex or bytes
            
        Returns:
            Transaction ID
            
        Raises:
            TransactionError: If broadcast fails
        """
        # Only HTTP provider supports POST
        if not isinstance(self._provider, HTTPProvider):
            raise TransactionError("Broadcasting requires HTTP provider")
            
        if isinstance(raw_tx, bytes):
            raw_tx = raw_tx.hex()
            
        try:
            result = await self._provider.post("/tx", raw_tx)
            txid = result.strip()
            
            # Validate returned txid
            if not txid or len(txid) != 64:
                raise TransactionError(f"Invalid txid returned: {txid}")
                
            self._logger.info(f"Broadcasted transaction: {txid}")
            return TxId(txid)
            
        except APIError as e:
            # Parse common errors
            error_msg = str(e).lower()
            if "insufficient fee" in error_msg:
                raise TransactionError("Insufficient fee") from e
            elif "dust" in error_msg:
                raise TransactionError("Output value below dust limit") from e
            elif "already in block chain" in error_msg:
                raise TransactionError("Transaction already confirmed") from e
            elif "conflict" in error_msg or "double spend" in error_msg:
                raise TransactionError("Transaction conflicts with existing transaction") from e
            else:
                raise TransactionError(f"Broadcast failed: {e}") from e
        except Exception as e:
            self._logger.error(f"Failed to broadcast transaction: {e}")
            raise TransactionError(f"Failed to broadcast transaction: {e}") from e
            
    async def decode_raw(self, raw_tx: Union[str, bytes]) -> Dict[str, Any]:
        """
        Decode raw transaction without broadcasting.
        
        Args:
            raw_tx: Raw transaction hex or bytes
            
        Returns:
            Decoded transaction data
            
        Note:
            This would need local transaction parsing implementation
        """
        raise NotImplementedError("Local transaction decoding not implemented")
        
    async def get_rbf_history(self, txid: TransactionIdentifier) -> Dict[str, Any]:
        """
        Get RBF (Replace-By-Fee) history for transaction.
        
        Args:
            txid: Transaction ID
            
        Returns:
            RBF timeline data
        """
        txid = validate_txid(str(txid))
        
        try:
            return await self._provider.request(f"/v1/tx/{txid}/rbf")
        except Exception as e:
            self._logger.error(f"Failed to get RBF history: {e}")
            raise TransactionError(f"Failed to get RBF history: {e}") from e
            
    async def estimate_fee(
        self,
        num_inputs: int,
        num_outputs: int,
        fee_rate: float
    ) -> int:
        """
        Estimate transaction fee.
        
        Args:
            num_inputs: Number of inputs
            num_outputs: Number of outputs  
            fee_rate: Fee rate in sats/vByte
            
        Returns:
            Estimated fee in satoshis
        """
        # Basic size estimation
        # 10 (header) + inputs * 148 + outputs * 34 + 2 (var ints)
        base_size = 10 + (num_inputs * 148) + (num_outputs * 34) + 2
        
        # For SegWit, assume 25% discount
        vsize = int(base_size * 0.75)
        
        return int(vsize * fee_rate)
        
    async def subscribe_to_transaction(
        self,
        txid: TransactionIdentifier,
        callback: Optional[Any] = None
    ) -> None:
        """
        Subscribe to transaction confirmations (WebSocket only).
        
        Args:
            txid: Transaction to monitor
            callback: Function to call on updates
        """
        from ..providers.websocket import WebSocketProvider
        
        if not isinstance(self._provider, WebSocketProvider):
            raise TransactionError("Transaction subscriptions require WebSocket provider")
            
        txid = validate_txid(str(txid))
        
        # Subscribe to transaction channel
        await self._provider.subscribe(f"tx:{txid}", callback=callback)
        self._logger.info(f"Subscribed to transaction: {txid}")
        
    async def unsubscribe_from_transaction(self, txid: TransactionIdentifier) -> None:
        """Unsubscribe from transaction updates."""
        from ..providers.websocket import WebSocketProvider
        
        if isinstance(self._provider, WebSocketProvider):
            txid = validate_txid(str(txid))
            await self._provider.unsubscribe(f"tx:{txid}")
            self._logger.info(f"Unsubscribed from transaction: {txid}")