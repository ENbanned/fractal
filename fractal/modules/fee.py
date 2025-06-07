"""Fee estimation module for Fractal Bitcoin."""

import logging
from typing import Dict, List, Optional, Union

from ..api_types import FeeEstimates
from ..exceptions import FractalError
from ..providers.base import BaseProvider
from ..types.common import Satoshi

__all__ = ["FeeModule"]

logger = logging.getLogger(__name__)


class FeePriority:
    """Fee priority levels."""
    FASTEST = "fastest"      # Next block
    HALF_HOUR = "halfHour"   # ~30 minutes
    HOUR = "hour"            # ~60 minutes  
    ECONOMY = "economy"      # ~3 hours
    MINIMUM = "minimum"      # Minimum relay fee


class FeeModule:
    """
    Fee estimation operations.
    
    Provides fee rate recommendations and historical fee data.
    """
    
    def __init__(self, provider: BaseProvider) -> None:
        """
        Initialize fee module.
        
        Args:
            provider: Provider instance
        """
        self._provider = provider
        self._logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
    async def get_estimates(self) -> FeeEstimates:
        """
        Get all fee estimates.
        
        Returns:
            Dictionary with fee rates for different priorities
        """
        try:
            return await self._provider.request("/v1/fees/recommended")
        except Exception as e:
            self._logger.error(f"Failed to get fee estimates: {e}")
            raise FractalError(f"Failed to get fee estimates: {e}") from e
            
    async def get_priority_fee(
        self,
        priority: str = FeePriority.HALF_HOUR
    ) -> int:
        """
        Get fee rate for specific priority.
        
        Args:
            priority: Fee priority level
            
        Returns:
            Fee rate in sats/vByte
        """
        estimates = await self.get_estimates()
        
        # Map priority to API field
        priority_map = {
            FeePriority.FASTEST: "fastestFee",
            FeePriority.HALF_HOUR: "halfHourFee",
            FeePriority.HOUR: "hourFee",
            FeePriority.ECONOMY: "economyFee",
            FeePriority.MINIMUM: "minimumFee",
        }
        
        fee_key = priority_map.get(priority, "halfHourFee")
        return estimates.get(fee_key, 1)
        
    async def estimate_transaction_fee(
        self,
        vsize: int,
        priority: str = FeePriority.HALF_HOUR
    ) -> Satoshi:
        """
        Estimate total transaction fee.
        
        Args:
            vsize: Transaction virtual size in vBytes
            priority: Fee priority level
            
        Returns:
            Total fee in satoshis
        """
        fee_rate = await self.get_priority_fee(priority)
        return Satoshi(vsize * fee_rate)
        
    async def get_mempool_blocks(self) -> List[Dict[str, any]]:
        """
        Get current mempool as projected blocks.
        
        Returns:
            List of projected blocks with fee information
        """
        try:
            return await self._provider.request("/v1/fees/mempool-blocks")
        except Exception as e:
            self._logger.error(f"Failed to get mempool blocks: {e}")
            raise FractalError(f"Failed to get mempool blocks: {e}") from e
            
    async def get_block_fees(
        self,
        time_period: str = "1w"
    ) -> List[Dict[str, any]]:
        """
        Get historical block fees.
        
        Args:
            time_period: Time period (24h, 3d, 1w, 1m, 3m, 6m, 1y, 2y, 3y)
            
        Returns:
            Historical fee data
        """
        try:
            return await self._provider.request(f"/v1/mining/blocks/fees/{time_period}")
        except Exception as e:
            self._logger.error(f"Failed to get block fees: {e}")
            raise FractalError(f"Failed to get block fees: {e}") from e
            
    async def get_fee_distribution(self) -> Dict[str, any]:
        """
        Get current fee distribution in mempool.
        
        Returns:
            Fee distribution statistics
        """
        blocks = await self.get_mempool_blocks()
        
        if not blocks:
            return {
                "min": 0,
                "max": 0,
                "median": 0,
                "average": 0,
                "percentiles": {}
            }
            
        # Extract all fee rates
        all_fees = []
        for block in blocks:
            if "feeRange" in block:
                all_fees.extend(block["feeRange"])
                
        if not all_fees:
            return {
                "min": 0,
                "max": 0,
                "median": 0,
                "average": 0,
                "percentiles": {}
            }
            
        all_fees.sort()
        
        # Calculate statistics
        return {
            "min": all_fees[0],
            "max": all_fees[-1],
            "median": all_fees[len(all_fees) // 2],
            "average": sum(all_fees) / len(all_fees),
            "percentiles": {
                "10": all_fees[int(len(all_fees) * 0.1)],
                "25": all_fees[int(len(all_fees) * 0.25)],
                "50": all_fees[int(len(all_fees) * 0.5)],
                "75": all_fees[int(len(all_fees) * 0.75)],
                "90": all_fees[int(len(all_fees) * 0.9)],
            }
        }
        
    async def calculate_priority_for_fee(
        self,
        fee_rate: int
    ) -> Optional[str]:
        """
        Determine priority level for given fee rate.
        
        Args:
            fee_rate: Fee rate in sats/vByte
            
        Returns:
            Matching priority level or None
        """
        estimates = await self.get_estimates()
        
        # Check from fastest to slowest
        if fee_rate >= estimates.get("fastestFee", float("inf")):
            return FeePriority.FASTEST
        elif fee_rate >= estimates.get("halfHourFee", float("inf")):
            return FeePriority.HALF_HOUR
        elif fee_rate >= estimates.get("hourFee", float("inf")):
            return FeePriority.HOUR
        elif fee_rate >= estimates.get("economyFee", float("inf")):
            return FeePriority.ECONOMY
        elif fee_rate >= estimates.get("minimumFee", 1):
            return FeePriority.MINIMUM
        else:
            return None
            
    async def estimate_confirmation_time(
        self,
        fee_rate: int
    ) -> Optional[int]:
        """
        Estimate confirmation time for fee rate.
        
        Args:
            fee_rate: Fee rate in sats/vByte
            
        Returns:
            Estimated time in minutes or None
        """
        priority = await self.calculate_priority_for_fee(fee_rate)
        
        if priority == FeePriority.FASTEST:
            return 10  # Next block (~10 minutes average)
        elif priority == FeePriority.HALF_HOUR:
            return 30
        elif priority == FeePriority.HOUR:
            return 60
        elif priority == FeePriority.ECONOMY:
            return 180  # 3 hours
        elif priority == FeePriority.MINIMUM:
            return 360  # 6 hours
        else:
            return None  # Below minimum, may not confirm