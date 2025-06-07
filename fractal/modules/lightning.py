"""Lightning Network module for Fractal Bitcoin."""

import logging
from typing import List, Dict, Any, Optional

from ..api_types import LightningNodeInfo
from ..exceptions import FractalError
from ..providers.base import BaseProvider

__all__ = ["LightningModule"]

logger = logging.getLogger(__name__)


class LightningModule:
    """
    Lightning Network operations.
    
    Provides access to Lightning Network statistics and node information.
    Note: This is for querying Lightning data, not running a Lightning node.
    """
    
    def __init__(self, provider: BaseProvider) -> None:
        """
        Initialize Lightning module.
        
        Args:
            provider: Provider instance
        """
        self._provider = provider
        self._logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
    async def get_statistics(
        self,
        interval: str = "latest"
    ) -> Dict[str, Any]:
        """
        Get network-wide Lightning statistics.
        
        Args:
            interval: Time interval (latest, 24h, 3d, 1w, 1m, 3m, 6m, 1y, 2y, 3y)
            
        Returns:
            Network statistics
        """
        try:
            return await self._provider.request(f"/v1/lightning/statistics/{interval}")
        except Exception as e:
            self._logger.error(f"Failed to get Lightning statistics: {e}")
            raise FractalError(f"Failed to get Lightning statistics: {e}") from e
            
    async def search(self, query: str) -> Dict[str, Any]:
        """
        Search for Lightning nodes and channels.
        
        Args:
            query: Search query
            
        Returns:
            Search results with nodes and channels
        """
        try:
            return await self._provider.request(
                "/v1/lightning/search",
                params={"searchText": query}
            )
        except Exception as e:
            self._logger.error(f"Failed to search Lightning data: {e}")
            raise FractalError(f"Failed to search Lightning data: {e}") from e
            
    async def get_node(self, pubkey: str) -> LightningNodeInfo:
        """
        Get Lightning node information.
        
        Args:
            pubkey: Node public key
            
        Returns:
            Node details
        """
        try:
            data = await self._provider.request(f"/v1/lightning/nodes/{pubkey}")
            return LightningNodeInfo(**data)
        except Exception as e:
            self._logger.error(f"Failed to get node info: {e}")
            raise FractalError(f"Failed to get node info: {e}") from e
            
    async def get_node_statistics(
        self,
        pubkey: str
    ) -> List[Dict[str, Any]]:
        """
        Get historical statistics for node.
        
        Args:
            pubkey: Node public key
            
        Returns:
            Historical node data
        """
        try:
            return await self._provider.request(f"/v1/lightning/nodes/{pubkey}/statistics")
        except Exception as e:
            self._logger.error(f"Failed to get node statistics: {e}")
            raise FractalError(f"Failed to get node statistics: {e}") from e
            
    async def get_channel(self, channel_id: str) -> Dict[str, Any]:
        """
        Get Lightning channel information.
        
        Args:
            channel_id: Channel ID
            
        Returns:
            Channel details
        """
        try:
            return await self._provider.request(f"/v1/lightning/channels/{channel_id}")
        except Exception as e:
            self._logger.error(f"Failed to get channel info: {e}")
            raise FractalError(f"Failed to get channel info: {e}") from e
            
    async def get_channels_from_txids(
        self,
        txids: List[str]
    ) -> List[Dict[str, Any]]:
        """
        Get channels from transaction IDs.
        
        Args:
            txids: List of transaction IDs
            
        Returns:
            Channel information
        """
        params = {"txId[]": txids}
        
        try:
            return await self._provider.request(
                "/v1/lightning/channels/txids",
                params=params
            )
        except Exception as e:
            self._logger.error(f"Failed to get channels from txids: {e}")
            raise FractalError(f"Failed to get channels from txids: {e}") from e
            
    async def get_node_channels(
        self,
        pubkey: str,
        status: str = "open",
        index: int = 0
    ) -> List[Dict[str, Any]]:
        """
        Get channels for a node.
        
        Args:
            pubkey: Node public key
            status: Channel status (open, active, closed)
            index: Pagination index
            
        Returns:
            List of channels
        """
        params = {
            "public_key": pubkey,
            "status": status,
            "index": index,
        }
        
        try:
            return await self._provider.request("/v1/lightning/channels", params=params)
        except Exception as e:
            self._logger.error(f"Failed to get node channels: {e}")
            raise FractalError(f"Failed to get node channels: {e}") from e
            
    async def get_top_nodes(
        self,
        by: str = "capacity"
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Get top Lightning nodes.
        
        Args:
            by: Ranking criteria (capacity, channels)
            
        Returns:
            Top nodes lists
        """
        endpoint = "/v1/lightning/nodes/rankings"
        if by in ("capacity", "liquidity"):
            endpoint += "/liquidity"
        elif by in ("channels", "connectivity"):
            endpoint += "/connectivity"
            
        try:
            data = await self._provider.request(endpoint)
            
            # Normalize response format
            if isinstance(data, list):
                return {"nodes": data}
            return data
        except Exception as e:
            self._logger.error(f"Failed to get top nodes: {e}")
            raise FractalError(f"Failed to get top nodes: {e}") from e
            
    async def get_nodes_by_country(
        self,
        country: str
    ) -> Dict[str, Any]:
        """
        Get Lightning nodes in a country.
        
        Args:
            country: ISO Alpha-2 country code
            
        Returns:
            Nodes in country
        """
        try:
            return await self._provider.request(f"/v1/lightning/nodes/country/{country}")
        except Exception as e:
            self._logger.error(f"Failed to get nodes by country: {e}")
            raise FractalError(f"Failed to get nodes by country: {e}") from e
            
    async def get_nodes_by_isp(
        self,
        asn: int
    ) -> Dict[str, Any]:
        """
        Get Lightning nodes hosted by ISP.
        
        Args:
            asn: ISP's ASN number
            
        Returns:
            Nodes hosted by ISP
        """
        try:
            return await self._provider.request(f"/v1/lightning/nodes/isp/{asn}")
        except Exception as e:
            self._logger.error(f"Failed to get nodes by ISP: {e}")
            raise FractalError(f"Failed to get nodes by ISP: {e}") from e
            
    async def get_channel_geodata(
        self,
        pubkey: Optional[str] = None
    ) -> List[List[Any]]:
        """
        Get channel geodata for visualization.
        
        Args:
            pubkey: Optional node pubkey to filter
            
        Returns:
            Channel geodata
        """
        endpoint = "/v1/lightning/channels-geo"
        if pubkey:
            endpoint += f"/{pubkey}"
            
        try:
            return await self._provider.request(endpoint)
        except Exception as e:
            self._logger.error(f"Failed to get channel geodata: {e}")
            raise FractalError(f"Failed to get channel geodata: {e}") from e