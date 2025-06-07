"""Base provider interface for Fractal Bitcoin."""

from abc import ABC, abstractmethod
from typing import Any, Optional, TypeVar, Generic
import logging

from ..constants import Network

__all__ = ["BaseProvider", "T"]

T = TypeVar("T")
logger = logging.getLogger(__name__)


class BaseProvider(ABC, Generic[T]):
    """
    Abstract base provider for Fractal Bitcoin connections.
    
    This class defines the interface that all providers must implement.
    Inspired by web3.py provider architecture.
    """
    
    def __init__(self, network: Network = Network.MAINNET) -> None:
        """
        Initialize provider with network.
        
        Args:
            network: Fractal Bitcoin network to connect to
        """
        self.network = network
        self._logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
    @abstractmethod
    async def request(
        self, 
        method: str, 
        params: Optional[dict[str, Any]] = None,
        **kwargs: Any
    ) -> T:
        """
        Make a request to the provider.
        
        Args:
            method: API method/endpoint to call
            params: Optional parameters for the request
            **kwargs: Additional provider-specific arguments
            
        Returns:
            Response data from the provider
            
        Raises:
            ProviderError: If the request fails
        """
        raise NotImplementedError
        
    @abstractmethod
    async def connect(self) -> None:
        """
        Connect to the provider.
        
        Raises:
            ProviderError: If connection fails
        """
        raise NotImplementedError
        
    @abstractmethod
    async def disconnect(self) -> None:
        """
        Disconnect from the provider.
        """
        raise NotImplementedError
        
    @property
    @abstractmethod
    def is_connected(self) -> bool:
        """
        Check if provider is connected.
        
        Returns:
            True if connected, False otherwise
        """
        raise NotImplementedError
        
    async def __aenter__(self) -> "BaseProvider[T]":
        """Async context manager entry."""
        await self.connect()
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        await self.disconnect()
        
    def __repr__(self) -> str:
        """String representation of provider."""
        return f"{self.__class__.__name__}(network={self.network.value})"