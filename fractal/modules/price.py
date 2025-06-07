"""Price module for Fractal Bitcoin."""

import logging
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone

from ..api_types import PriceInfo
from ..exceptions import FractalError
from ..providers.base import BaseProvider

__all__ = ["PriceModule"]

logger = logging.getLogger(__name__)


class PriceModule:
    """
    Price data operations.
    
    Provides current and historical Bitcoin price information
    in multiple fiat currencies.
    """
    
    def __init__(self, provider: BaseProvider) -> None:
        """
        Initialize price module.
        
        Args:
            provider: Provider instance
        """
        self._provider = provider
        self._logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
    async def get_current(self) -> PriceInfo:
        """
        Get current Bitcoin prices in major currencies.
        
        Returns:
            Current price data
        """
        try:
            return await self._provider.request("/v1/prices")
        except Exception as e:
            self._logger.error(f"Failed to get current prices: {e}")
            raise FractalError(f"Failed to get current prices: {e}") from e
            
    async def get_historical(
        self,
        currency: Optional[str] = None,
        timestamp: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Get historical Bitcoin prices.
        
        Args:
            currency: Specific currency (USD, EUR, GBP, etc.)
            timestamp: Unix timestamp for historical price
            
        Returns:
            Historical price data
        """
        params = {}
        if currency:
            params["currency"] = currency
        if timestamp:
            params["timestamp"] = timestamp
            
        try:
            return await self._provider.request("/v1/historical-price", params=params)
        except Exception as e:
            self._logger.error(f"Failed to get historical prices: {e}")
            raise FractalError(f"Failed to get historical prices: {e}") from e
            
    async def get_price_at_time(
        self,
        timestamp: int,
        currency: str = "USD"
    ) -> float:
        """
        Get Bitcoin price at specific time.
        
        Args:
            timestamp: Unix timestamp
            currency: Target currency
            
        Returns:
            Price in specified currency
        """
        data = await self.get_historical(currency=currency, timestamp=timestamp)
        
        prices = data.get("prices", [])
        if prices and currency in prices[0]:
            return float(prices[0][currency])
            
        raise FractalError(f"No price data for {currency} at timestamp {timestamp}")
        
    async def get_exchange_rates(self) -> Dict[str, float]:
        """
        Get current exchange rates.
        
        Returns:
            Exchange rates relative to USD
        """
        data = await self.get_historical()
        return data.get("exchangeRates", {})
        
    async def convert_currency(
        self,
        amount: float,
        from_currency: str,
        to_currency: str
    ) -> float:
        """
        Convert amount between currencies.
        
        Args:
            amount: Amount to convert
            from_currency: Source currency
            to_currency: Target currency
            
        Returns:
            Converted amount
        """
        if from_currency == to_currency:
            return amount
            
        # Get current prices
        prices = await self.get_current()
        
        # Convert through BTC if needed
        if from_currency == "BTC":
            if to_currency in prices:
                return amount * prices[to_currency]
        elif to_currency == "BTC":
            if from_currency in prices:
                return amount / prices[from_currency]
        else:
            # Convert through BTC
            btc_amount = amount / prices.get(from_currency, 1)
            return btc_amount * prices.get(to_currency, 1)
            
        raise FractalError(f"Cannot convert {from_currency} to {to_currency}")
        
    async def get_price_change(
        self,
        hours: int = 24,
        currency: str = "USD"
    ) -> Dict[str, float]:
        """
        Calculate price change over time period.
        
        Args:
            hours: Number of hours to look back
            currency: Currency for comparison
            
        Returns:
            Price change statistics
        """
        # Get current price
        current_prices = await self.get_current()
        current_price = current_prices.get(currency, 0)
        
        # Get historical price
        past_timestamp = int(datetime.now(timezone.utc).timestamp()) - (hours * 3600)
        past_price = await self.get_price_at_time(past_timestamp, currency)
        
        # Calculate changes
        change_absolute = current_price - past_price
        change_percent = ((current_price - past_price) / past_price) * 100 if past_price > 0 else 0
        
        return {
            "current_price": current_price,
            "past_price": past_price,
            "change_absolute": change_absolute,
            "change_percent": change_percent,
            "period_hours": hours,
            "currency": currency,
        }
        
    async def get_market_cap(
        self,
        currency: str = "USD",
        circulating_supply: float = 21_000_000
    ) -> float:
        """
        Calculate market capitalization.
        
        Args:
            currency: Currency for market cap
            circulating_supply: Circulating supply in BTC
            
        Returns:
            Market cap in specified currency
        """
        prices = await self.get_current()
        price = prices.get(currency, 0)
        return price * circulating_supply
        
    async def get_supported_currencies(self) -> List[str]:
        """
        Get list of supported currencies.
        
        Returns:
            List of currency codes
        """
        prices = await self.get_current()
        # Filter out non-currency fields
        return [k for k in prices.keys() if k != "time" and isinstance(prices[k], (int, float))]