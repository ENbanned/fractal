"""Mining module for Fractal Bitcoin."""

import logging
from typing import List, Dict, Any, Optional

from ..api_types import MiningPoolInfo, DifficultyAdjustment
from ..exceptions import FractalError
from ..providers.base import BaseProvider
from ..types.common import BlockHeight

__all__ = ["MiningModule"]

logger = logging.getLogger(__name__)


class MiningModule:
    """
    Mining-related operations.
    
    Provides mining statistics, pool information, and difficulty data.
    """
    
    def __init__(self, provider: BaseProvider) -> None:
        """
        Initialize mining module.
        
        Args:
            provider: Provider instance
        """
        self._provider = provider
        self._logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
    async def get_difficulty_adjustment(self) -> DifficultyAdjustment:
        """
        Get difficulty adjustment information.
        
        Returns:
            Current difficulty adjustment status
        """
        try:
            return await self._provider.request("/v1/difficulty-adjustment")
        except Exception as e:
            self._logger.error(f"Failed to get difficulty adjustment: {e}")
            raise FractalError(f"Failed to get difficulty adjustment: {e}") from e
            
    async def get_hashrate(
        self,
        time_period: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get network hashrate statistics.
        
        Args:
            time_period: Period (1m, 3m, 6m, 1y, 2y, 3y)
            
        Returns:
            Hashrate data including current and historical
        """
        endpoint = "/v1/mining/hashrate"
        if time_period:
            endpoint += f"/{time_period}"
            
        try:
            return await self._provider.request(endpoint)
        except Exception as e:
            self._logger.error(f"Failed to get hashrate: {e}")
            raise FractalError(f"Failed to get hashrate: {e}") from e
            
    async def get_mining_pools(
        self,
        time_period: str = "1w"
    ) -> Dict[str, Any]:
        """
        Get mining pool statistics.
        
        Args:
            time_period: Period (24h, 3d, 1w, 1m, 3m, 6m, 1y, 2y, 3y)
            
        Returns:
            Pool statistics and rankings
        """
        try:
            data = await self._provider.request(f"/v1/mining/pools/{time_period}")
            
            # Convert pool data
            pools = []
            for pool_data in data.get("pools", []):
                pools.append(MiningPoolInfo(**pool_data))
                
            return {
                "pools": pools,
                "blockCount": data.get("blockCount", 0),
                "lastEstimatedHashrate": data.get("lastEstimatedHashrate", 0),
            }
        except Exception as e:
            self._logger.error(f"Failed to get mining pools: {e}")
            raise FractalError(f"Failed to get mining pools: {e}") from e
            
    async def get_pool_info(self, pool_slug: str) -> Dict[str, Any]:
        """
        Get specific mining pool details.
        
        Args:
            pool_slug: Pool identifier slug
            
        Returns:
            Detailed pool information
        """
        try:
            return await self._provider.request(f"/v1/mining/pool/{pool_slug}")
        except Exception as e:
            self._logger.error(f"Failed to get pool info: {e}")
            raise FractalError(f"Failed to get pool info: {e}") from e
            
    async def get_pool_hashrate(
        self,
        pool_slug: str
    ) -> List[Dict[str, Any]]:
        """
        Get hashrate history for mining pool.
        
        Args:
            pool_slug: Pool identifier slug
            
        Returns:
            Historical hashrate data
        """
        try:
            return await self._provider.request(f"/v1/mining/pool/{pool_slug}/hashrate")
        except Exception as e:
            self._logger.error(f"Failed to get pool hashrate: {e}")
            raise FractalError(f"Failed to get pool hashrate: {e}") from e
            
    async def get_pool_blocks(
        self,
        pool_slug: str,
        before_height: Optional[BlockHeight] = None
    ) -> List[Dict[str, Any]]:
        """
        Get blocks mined by pool.
        
        Args:
            pool_slug: Pool identifier slug
            before_height: Get blocks before this height
            
        Returns:
            List of blocks mined by pool
        """
        endpoint = f"/v1/mining/pool/{pool_slug}/blocks"
        if before_height:
            endpoint += f"/{before_height}"
            
        try:
            return await self._provider.request(endpoint)
        except Exception as e:
            self._logger.error(f"Failed to get pool blocks: {e}")
            raise FractalError(f"Failed to get pool blocks: {e}") from e
            
    async def get_reward_stats(
        self,
        block_count: int = 100
    ) -> Dict[str, Any]:
        """
        Get mining reward statistics.
        
        Args:
            block_count: Number of blocks to analyze
            
        Returns:
            Reward statistics
        """
        try:
            return await self._provider.request(f"/v1/mining/reward-stats/{block_count}")
        except Exception as e:
            self._logger.error(f"Failed to get reward stats: {e}")
            raise FractalError(f"Failed to get reward stats: {e}") from e
            
    async def get_block_fees(
        self,
        time_period: str = "1w"
    ) -> List[Dict[str, Any]]:
        """
        Get historical block fee data.
        
        Args:
            time_period: Period (24h, 3d, 1w, 1m, 3m, 6m, 1y, 2y, 3y)
            
        Returns:
            Historical fee data
        """
        try:
            return await self._provider.request(f"/v1/mining/blocks/fees/{time_period}")
        except Exception as e:
            self._logger.error(f"Failed to get block fees: {e}")
            raise FractalError(f"Failed to get block fees: {e}") from e
            
    async def get_block_rewards(
        self,
        time_period: str = "1w"
    ) -> List[Dict[str, Any]]:
        """
        Get historical block reward data.
        
        Args:
            time_period: Period (24h, 3d, 1w, 1m, 3m, 6m, 1y, 2y, 3y)
            
        Returns:
            Historical reward data
        """
        try:
            return await self._provider.request(f"/v1/mining/blocks/rewards/{time_period}")
        except Exception as e:
            self._logger.error(f"Failed to get block rewards: {e}")
            raise FractalError(f"Failed to get block rewards: {e}") from e
            
    async def get_block_sizes(
        self,
        time_period: str = "1w"
    ) -> Dict[str, Any]:
        """
        Get historical block size data.
        
        Args:
            time_period: Period (24h, 3d, 1w, 1m, 3m, 6m, 1y, 2y, 3y)
            
        Returns:
            Size and weight statistics
        """
        try:
            return await self._provider.request(f"/v1/mining/blocks/sizes-weights/{time_period}")
        except Exception as e:
            self._logger.error(f"Failed to get block sizes: {e}")
            raise FractalError(f"Failed to get block sizes: {e}") from e
            
    async def calculate_mining_revenue(
        self,
        hashrate: float,
        power_cost: float = 0.05,
        power_consumption: float = 3000
    ) -> Dict[str, float]:
        """
        Calculate estimated mining revenue.
        
        Args:
            hashrate: Hashrate in TH/s
            power_cost: Cost per kWh
            power_consumption: Power usage in watts
            
        Returns:
            Revenue calculations
        """
        # Get current network stats
        hashrate_data = await self.get_hashrate()
        reward_stats = await self.get_reward_stats(1)
        
        network_hashrate = hashrate_data.get("currentHashrate", 0) / 1e12  # Convert to TH/s
        block_reward = reward_stats.get("totalReward", 0) / 100_000_000  # Convert to BTC
        
        if network_hashrate == 0:
            return {
                "daily_revenue_btc": 0,
                "daily_power_cost": 0,
                "daily_profit": 0,
            }
            
        # Calculate share of network
        hash_share = hashrate / network_hashrate
        
        # Blocks per day (Fractal: 30 second blocks)
        blocks_per_day = 86400 / 30
        
        # Daily revenue
        daily_revenue_btc = hash_share * blocks_per_day * block_reward
        
        # Power cost
        daily_power_cost = (power_consumption / 1000) * 24 * power_cost
        
        return {
            "daily_revenue_btc": daily_revenue_btc,
            "daily_power_cost": daily_power_cost,
            "hash_share_percent": hash_share * 100,
            "network_hashrate_th": network_hashrate,
        }