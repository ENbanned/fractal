"""Mempool module for Fractal Bitcoin."""

import logging
from typing import List, Dict, Any, Optional

from ..api_types import MempoolInfo
from ..exceptions import FractalError
from ..providers.base import BaseProvider
from ..types.common import TxId

__all__ = ["MempoolModule"]

logger = logging.getLogger(__name__)


class MempoolModule:
    """
    Mempool-related operations.
    
    Provides access to mempool statistics, pending transactions,
    and real-time mempool monitoring.
    """
    
    def __init__(self, provider: BaseProvider) -> None:
        """
        Initialize mempool module.
        
        Args:
            provider: Provider instance
        """
        self._provider = provider
        self._logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
    async def get_info(self) -> MempoolInfo:
        """
        Get mempool statistics.
        
        Returns:
            Mempool information including size and fee histogram
        """
        try:
            data = await self._provider.request("/mempool")
            return MempoolInfo(
                count=data["count"],
                vsize=data["vsize"],
                total_fee=data["total_fee"],
                fee_histogram=data.get("fee_histogram", []),
            )
        except Exception as e:
            self._logger.error(f"Failed to get mempool info: {e}")
            raise FractalError(f"Failed to get mempool info: {e}") from e
            
    async def get_txids(self) -> List[TxId]:
        """
        Get all transaction IDs in mempool.
        
        Returns:
            List of transaction IDs (arbitrary order)
        """
        try:
            data = await self._provider.request("/mempool/txids")
            return [TxId(txid) for txid in data]
        except Exception as e:
            self._logger.error(f"Failed to get mempool txids: {e}")
            raise FractalError(f"Failed to get mempool txids: {e}") from e
            
    async def get_recent(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get recent mempool transactions.
        
        Args:
            limit: Maximum number of transactions
            
        Returns:
            List of recent transactions with basic info
        """
        try:
            data = await self._provider.request("/mempool/recent")
            return data[:limit] if limit else data
        except Exception as e:
            self._logger.error(f"Failed to get recent transactions: {e}")
            raise FractalError(f"Failed to get recent transactions: {e}") from e
            
    async def get_rbf_transactions(self) -> List[Dict[str, Any]]:
        """
        Get RBF (Replace-By-Fee) transactions in mempool.
        
        Returns:
            List of RBF transaction chains
        """
        try:
            return await self._provider.request("/v1/replacements")
        except Exception as e:
            self._logger.error(f"Failed to get RBF transactions: {e}")
            raise FractalError(f"Failed to get RBF transactions: {e}") from e
            
    async def get_fullrbf_transactions(self) -> List[Dict[str, Any]]:
        """
        Get Full-RBF transactions in mempool.
        
        Returns:
            List of Full-RBF transaction chains
        """
        try:
            return await self._provider.request("/v1/fullrbf/replacements")
        except Exception as e:
            self._logger.error(f"Failed to get Full-RBF transactions: {e}")
            raise FractalError(f"Failed to get Full-RBF transactions: {e}") from e
            
    async def get_size(self) -> int:
        """
        Get mempool size in vBytes.
        
        Returns:
            Total virtual size of all transactions
        """
        info = await self.get_info()
        return info["vsize"]
        
    async def get_count(self) -> int:
        """
        Get number of transactions in mempool.
        
        Returns:
            Transaction count
        """
        info = await self.get_info()
        return info["count"]
        
    async def get_total_fee(self) -> int:
        """
        Get total fees of all mempool transactions.
        
        Returns:
            Total fees in satoshis
        """
        info = await self.get_info()
        return info["total_fee"]
        
    async def analyze_fee_distribution(self) -> Dict[str, Any]:
        """
        Analyze fee distribution in mempool.
        
        Returns:
            Detailed fee analysis
        """
        info = await self.get_info()
        
        if not info.get("fee_histogram"):
            return {
                "ranges": [],
                "total_transactions": info["count"],
                "total_vsize": info["vsize"],
                "average_fee_rate": 0,
            }
            
        # Process fee histogram
        ranges = []
        total_fee_rate = 0
        
        for fee_range in info["fee_histogram"]:
            if len(fee_range) >= 2:
                ranges.append({
                    "min_fee": fee_range[0],
                    "max_fee": fee_range[1] if len(fee_range) > 1 else fee_range[0],
                    "count": fee_range[2] if len(fee_range) > 2 else 0,
                })
                
        # Calculate average fee rate
        if info["vsize"] > 0:
            average_fee_rate = info["total_fee"] / info["vsize"]
        else:
            average_fee_rate = 0
            
        return {
            "ranges": ranges,
            "total_transactions": info["count"],
            "total_vsize": info["vsize"],
            "average_fee_rate": average_fee_rate,
        }
        
    async def is_transaction_in_mempool(self, txid: str) -> bool:
        """
        Check if transaction is in mempool.
        
        Args:
            txid: Transaction ID to check
            
        Returns:
            True if in mempool, False otherwise
        """
        try:
            status = await self._provider.request(f"/tx/{txid}/status")
            return not status.get("confirmed", True)
        except:
            return False
            
    async def subscribe_to_mempool(
        self,
        callback: Optional[Any] = None
    ) -> None:
        """
        Subscribe to mempool updates (WebSocket only).
        
        Args:
            callback: Function to call on mempool updates
        """
        from ..providers.websocket import WebSocketProvider
        
        if not isinstance(self._provider, WebSocketProvider):
            raise FractalError("Mempool subscriptions require WebSocket provider")
            
        # Subscribe to mempool channel
        await self._provider.subscribe("mempool", callback=callback)
        self._logger.info("Subscribed to mempool updates")
        
    async def unsubscribe_from_mempool(self) -> None:
        """Unsubscribe from mempool updates."""
        from ..providers.websocket import WebSocketProvider
        
        if isinstance(self._provider, WebSocketProvider):
            await self._provider.unsubscribe("mempool")
            self._logger.info("Unsubscribed from mempool updates")