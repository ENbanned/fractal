"""Address module for Fractal Bitcoin."""

import logging
from typing import List, Optional, Dict, Any

from ..api_types import AddressStats
from ..exceptions import AddressError, ValidationError
from ..providers.base import BaseProvider
from ..types.address import AddressInfo, UTXO, AddressTransaction
from ..types.common import Address as AddressStr, TxId, Satoshi
from ..types.transaction import OutPoint
from ..utils.validation import validate_address

__all__ = ["AddressModule"]

logger = logging.getLogger(__name__)


class AddressModule:
    """
    Address-related operations.
    
    Handles address information retrieval, balance checking,
    UTXO management, and transaction history.
    """
    
    def __init__(self, provider: BaseProvider) -> None:
        """
        Initialize address module.
        
        Args:
            provider: Provider instance
        """
        self._provider = provider
        self._logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
    async def get_info(self, address: str) -> AddressInfo:
        """
        Get address information including balance.
        
        Args:
            address: Bitcoin address
            
        Returns:
            AddressInfo with balance and statistics
            
        Raises:
            AddressError: If address is invalid or not found
        """
        # Validate address
        try:
            address = validate_address(address)
        except ValidationError as e:
            raise AddressError(f"Invalid address: {e}") from e
            
        try:
            # Get address stats
            data: AddressStats = await self._provider.request(f"/address/{address}")
            
            return AddressInfo(
                address=AddressStr(data["address"]),
                chain_stats=data["chain_stats"],
                mempool_stats=data["mempool_stats"],
            )
            
        except Exception as e:
            self._logger.error(f"Failed to get address info: {e}")
            raise AddressError(f"Failed to get address info: {e}") from e
            
    async def get_balance(self, address: str) -> Satoshi:
        """
        Get address balance (confirmed + unconfirmed).
        
        Args:
            address: Bitcoin address
            
        Returns:
            Total balance in satoshis
        """
        info = await self.get_info(address)
        return info.balance
        
    async def get_confirmed_balance(self, address: str) -> Satoshi:
        """
        Get confirmed balance only.
        
        Args:
            address: Bitcoin address
            
        Returns:
            Confirmed balance in satoshis
        """
        info = await self.get_info(address)
        return info.confirmed_balance
        
    async def get_unconfirmed_balance(self, address: str) -> Satoshi:
        """
        Get unconfirmed balance.
        
        Args:
            address: Bitcoin address
            
        Returns:
            Unconfirmed balance in satoshis
        """
        info = await self.get_info(address)
        return info.unconfirmed_balance
        
    async def get_utxos(
        self,
        address: str,
        confirmed_only: bool = False
    ) -> List[UTXO]:
        """
        Get unspent transaction outputs for address.
        
        Args:
            address: Bitcoin address
            confirmed_only: Filter to only confirmed UTXOs
            
        Returns:
            List of UTXOs
        """
        address = validate_address(address)
        
        try:
            data = await self._provider.request(f"/address/{address}/utxo")
            
            utxos = []
            for utxo_data in data:
                utxo = UTXO(
                    outpoint=OutPoint(
                        txid=TxId(utxo_data["txid"]),
                        vout=utxo_data["vout"]
                    ),
                    value=Satoshi(utxo_data["value"]),
                    status=utxo_data["status"],
                )
                
                # Filter if needed
                if confirmed_only and not utxo.is_confirmed:
                    continue
                    
                utxos.append(utxo)
                
            return utxos
            
        except Exception as e:
            self._logger.error(f"Failed to get UTXOs: {e}")
            raise AddressError(f"Failed to get UTXOs: {e}") from e
            
    async def get_transactions(
        self,
        address: str,
        after_txid: Optional[str] = None,
        limit: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """
        Get transactions for address.
        
        Args:
            address: Bitcoin address
            after_txid: Get transactions after this txid
            limit: Maximum number of transactions
            
        Returns:
            List of transaction data
            
        Note:
            Returns up to 50 mempool transactions plus the first 25
            confirmed transactions by default.
        """
        address = validate_address(address)
        
        endpoint = f"/address/{address}/txs"
        if after_txid:
            endpoint += f"/{after_txid}"
            
        try:
            transactions = await self._provider.request(endpoint)
            
            if limit and len(transactions) > limit:
                transactions = transactions[:limit]
                
            return transactions
            
        except Exception as e:
            self._logger.error(f"Failed to get transactions: {e}")
            raise AddressError(f"Failed to get transactions: {e}") from e
            
    async def get_confirmed_transactions(
        self,
        address: str,
        last_seen_txid: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get confirmed transaction history.
        
        Args:
            address: Bitcoin address
            last_seen_txid: Last transaction ID for pagination
            
        Returns:
            List of confirmed transactions (25 per page)
        """
        address = validate_address(address)
        
        endpoint = f"/address/{address}/txs/chain"
        if last_seen_txid:
            endpoint += f"/{last_seen_txid}"
            
        try:
            return await self._provider.request(endpoint)
        except Exception as e:
            self._logger.error(f"Failed to get confirmed transactions: {e}")
            raise AddressError(f"Failed to get confirmed transactions: {e}") from e
            
    async def get_mempool_transactions(self, address: str) -> List[Dict[str, Any]]:
        """
        Get unconfirmed transactions in mempool.
        
        Args:
            address: Bitcoin address
            
        Returns:
            List of mempool transactions (up to 50)
        """
        address = validate_address(address)
        
        try:
            return await self._provider.request(f"/address/{address}/txs/mempool")
        except Exception as e:
            self._logger.error(f"Failed to get mempool transactions: {e}")
            raise AddressError(f"Failed to get mempool transactions: {e}") from e
            
    async def validate(self, address: str) -> Dict[str, Any]:
        """
        Validate address format.
        
        Args:
            address: Address to validate
            
        Returns:
            Validation result with address details
        """
        try:
            return await self._provider.request(f"/v1/validate-address/{address}")
        except Exception as e:
            self._logger.error(f"Failed to validate address: {e}")
            raise AddressError(f"Failed to validate address: {e}") from e
            
    async def subscribe_to_address(
        self,
        address: str,
        callback: Optional[Any] = None
    ) -> None:
        """
        Subscribe to address updates (WebSocket only).
        
        Args:
            address: Address to monitor
            callback: Function to call on updates
            
        Raises:
            AddressError: If provider doesn't support subscriptions
        """
        from ..providers.websocket import WebSocketProvider
        
        if not isinstance(self._provider, WebSocketProvider):
            raise AddressError("Address subscriptions require WebSocket provider")
            
        address = validate_address(address)
        
        # Subscribe to address channel
        await self._provider.subscribe(
            f"address:{address}",
            callback=callback
        )
        
        self._logger.info(f"Subscribed to address: {address}")
        
    async def unsubscribe_from_address(self, address: str) -> None:
        """
        Unsubscribe from address updates.
        
        Args:
            address: Address to stop monitoring
        """
        from ..providers.websocket import WebSocketProvider
        
        if isinstance(self._provider, WebSocketProvider):
            address = validate_address(address)
            await self._provider.unsubscribe(f"address:{address}")
            self._logger.info(f"Unsubscribed from address: {address}")