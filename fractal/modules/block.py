"""Block module for Fractal Bitcoin."""

import logging
from typing import List, Optional, Union, Dict, Any

from ..api_types import BlockExtra
from ..exceptions import BlockNotFoundError, ValidationError
from ..providers.base import BaseProvider
from ..types.block import Block, BlockStats, BlockHeader
from ..types.common import BlockHash, BlockHeight, BlockIdentifier
from ..utils.validation import validate_block_hash

__all__ = ["BlockModule"]

logger = logging.getLogger(__name__)


class BlockModule:
    """
    Block-related operations.
    
    Handles block retrieval, validation, and chain state queries.
    """
    
    def __init__(self, provider: BaseProvider) -> None:
        """
        Initialize block module.
        
        Args:
            provider: Provider instance
        """
        self._provider = provider
        self._logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
    async def get_height(self) -> BlockHeight:
        """
        Get current block height.
        
        Returns:
            Current chain height
        """
        try:
            data = await self._provider.request("/blocks/tip/height")
            return BlockHeight(int(data))
        except Exception as e:
            self._logger.error(f"Failed to get block height: {e}")
            raise BlockNotFoundError(f"Failed to get block height: {e}") from e
            
    async def get_hash(self, height: Union[BlockHeight, int]) -> BlockHash:
        """
        Get block hash by height.
        
        Args:
            height: Block height
            
        Returns:
            Block hash
        """
        try:
            data = await self._provider.request(f"/block-height/{height}")
            return BlockHash(data)
        except Exception as e:
            self._logger.error(f"Failed to get block hash: {e}")
            raise BlockNotFoundError(f"Block not found at height {height}") from e
            
    async def get_block(
        self,
        block_id: BlockIdentifier,
        include_transactions: bool = False
    ) -> Block:
        """
        Get block by hash or height.
        
        Args:
            block_id: Block hash or height
            include_transactions: Include full transaction data
            
        Returns:
            Block information
            
        Raises:
            BlockNotFoundError: If block not found
        """
        # Convert height to hash if needed
        if isinstance(block_id, int):
            block_hash = await self.get_hash(BlockHeight(block_id))
        else:
            block_hash = validate_block_hash(str(block_id))
            
        try:
            data = await self._provider.request(f"/block/{block_hash}")
            
            # Extract extra fields
            extras = data.get("extras", {})
            
            block = Block(
                hash=BlockHash(data["id"]),
                height=BlockHeight(data["height"]),
                version=data["version"],
                timestamp=data["timestamp"],
                bits=data["bits"],
                nonce=data["nonce"],
                merkle_root=data["merkle_root"],
                size=data["size"],
                weight=data["weight"],
                tx_count=data["tx_count"],
                difficulty=data["difficulty"],
                previousblockhash=BlockHash(data.get("previousblockhash")) if data.get("previousblockhash") else None,
                mediantime=data.get("mediantime"),
                extras=extras,
            )
            
            # Fetch transactions if requested
            if include_transactions:
                txs = await self.get_transactions(block_hash)
                block.transactions = txs
                
            return block
            
        except Exception as e:
            self._logger.error(f"Failed to get block: {e}")
            raise BlockNotFoundError(f"Block not found: {block_id}") from e
            
    async def get_latest(self) -> Block:
        """
        Get the latest block.
        
        Returns:
            Latest block information
        """
        height = await self.get_height()
        return await self.get_block(height)
        
    async def get_blocks(
        self,
        start_height: Optional[BlockHeight] = None,
        limit: int = 15
    ) -> List[Block]:
        """
        Get list of recent blocks.
        
        Args:
            start_height: Starting height (default: latest)
            limit: Number of blocks to return
            
        Returns:
            List of blocks in descending order
        """
        endpoint = "/v1/blocks"
        if start_height is not None:
            endpoint += f"/{start_height}"
            
        try:
            data = await self._provider.request(endpoint)
            
            blocks = []
            for block_data in data[:limit]:
                blocks.append(Block(
                    hash=BlockHash(block_data["id"]),
                    height=BlockHeight(block_data["height"]),
                    version=block_data["version"],
                    timestamp=block_data["timestamp"],
                    bits=block_data["bits"],
                    nonce=block_data["nonce"],
                    merkle_root=block_data["merkle_root"],
                    size=block_data["size"],
                    weight=block_data["weight"],
                    tx_count=block_data["tx_count"],
                    difficulty=block_data["difficulty"],
                    previousblockhash=BlockHash(block_data.get("previousblockhash")) if block_data.get("previousblockhash") else None,
                    extras=block_data.get("extras"),
                ))
                
            return blocks
            
        except Exception as e:
            self._logger.error(f"Failed to get blocks: {e}")
            raise BlockNotFoundError(f"Failed to get blocks: {e}") from e
            
    async def get_header(self, block_id: BlockIdentifier) -> str:
        """
        Get block header as hex.
        
        Args:
            block_id: Block hash or height
            
        Returns:
            Hex-encoded block header
        """
        # Convert height to hash if needed
        if isinstance(block_id, int):
            block_hash = await self.get_hash(BlockHeight(block_id))
        else:
            block_hash = validate_block_hash(str(block_id))
            
        try:
            return await self._provider.request(f"/block/{block_hash}/header")
        except Exception as e:
            self._logger.error(f"Failed to get block header: {e}")
            raise BlockNotFoundError(f"Failed to get block header: {e}") from e
            
    async def get_stats(self, block_id: BlockIdentifier) -> BlockStats:
        """
        Get block statistics.
        
        Args:
            block_id: Block hash or height
            
        Returns:
            Block statistics
        """
        # Convert height to hash if needed
        if isinstance(block_id, int):
            block_hash = await self.get_hash(BlockHeight(block_id))
        else:
            block_hash = validate_block_hash(str(block_id))
            
        try:
            data = await self._provider.request(f"/block/{block_hash}/stats")
            return BlockStats(**data)
        except Exception as e:
            self._logger.error(f"Failed to get block stats: {e}")
            raise BlockNotFoundError(f"Failed to get block stats: {e}") from e
            
    async def get_transactions(
        self,
        block_id: BlockIdentifier,
        start_index: int = 0
    ) -> List[Dict[str, Any]]:
        """
        Get transactions in block.
        
        Args:
            block_id: Block hash or height
            start_index: Starting index for pagination
            
        Returns:
            List of transactions (up to 25)
        """
        # Convert height to hash if needed
        if isinstance(block_id, int):
            block_hash = await self.get_hash(BlockHeight(block_id))
        else:
            block_hash = validate_block_hash(str(block_id))
            
        try:
            return await self._provider.request(f"/block/{block_hash}/txs/{start_index}")
        except Exception as e:
            self._logger.error(f"Failed to get block transactions: {e}")
            raise BlockNotFoundError(f"Failed to get block transactions: {e}") from e
            
    async def get_transaction_ids(self, block_id: BlockIdentifier) -> List[str]:
        """
        Get all transaction IDs in block.
        
        Args:
            block_id: Block hash or height
            
        Returns:
            List of transaction IDs
        """
        # Convert height to hash if needed
        if isinstance(block_id, int):
            block_hash = await self.get_hash(BlockHeight(block_id))
        else:
            block_hash = validate_block_hash(str(block_id))
            
        try:
            return await self._provider.request(f"/block/{block_hash}/txids")
        except Exception as e:
            self._logger.error(f"Failed to get transaction IDs: {e}")
            raise BlockNotFoundError(f"Failed to get transaction IDs: {e}") from e
            
    async def get_status(self, block_id: BlockIdentifier) -> Dict[str, Any]:
        """
        Get block confirmation status.
        
        Args:
            block_id: Block hash or height
            
        Returns:
            Status information
        """
        # Convert height to hash if needed
        if isinstance(block_id, int):
            block_hash = await self.get_hash(BlockHeight(block_id))
        else:
            block_hash = validate_block_hash(str(block_id))
            
        try:
            return await self._provider.request(f"/block/{block_hash}/status")
        except Exception as e:
            self._logger.error(f"Failed to get block status: {e}")
            raise BlockNotFoundError(f"Failed to get block status: {e}") from e
            
    async def subscribe_to_blocks(
        self,
        callback: Optional[Any] = None
    ) -> None:
        """
        Subscribe to new blocks (WebSocket only).
        
        Args:
            callback: Function to call on new blocks
            
        Raises:
            BlockNotFoundError: If provider doesn't support subscriptions
        """
        from ..providers.websocket import WebSocketProvider
        
        if not isinstance(self._provider, WebSocketProvider):
            raise BlockNotFoundError("Block subscriptions require WebSocket provider")
            
        # Subscribe to blocks channel
        await self._provider.subscribe("blocks", callback=callback)
        self._logger.info("Subscribed to new blocks")
        
    async def unsubscribe_from_blocks(self) -> None:
        """Unsubscribe from new blocks."""
        from ..providers.websocket import WebSocketProvider
        
        if isinstance(self._provider, WebSocketProvider):
            await self._provider.unsubscribe("blocks")
            self._logger.info("Unsubscribed from blocks")