"""Main Fractal Bitcoin client."""

import logging
from typing import Optional, Dict, Any, Union

from .constants import Network
from .exceptions import FractalError
from .providers import BaseProvider, HTTPProvider, WebSocketProvider
from .modules import (
    AccountModule,
    AddressModule,
    BlockModule,
    FeeModule,
    MempoolModule,
    TransactionModule,
    WalletModule,
    MiningModule,
    LightningModule,
    PriceModule,
)

__all__ = ["Fractal"]

logger = logging.getLogger(__name__)


class Fractal:
    """
    Main client for interacting with Fractal Bitcoin.
    
    This is the primary interface for all Fractal Bitcoin operations,
    similar to Web3 for Ethereum. It provides access to all modules
    and manages the provider connection.
    """
    
    def __init__(
        self,
        provider: Optional[BaseProvider] = None,
        network: Network = Network.MAINNET,
        modules: Optional[Dict[str, bool]] = None,
    ) -> None:
        """
        Initialize Fractal client.
        
        Args:
            provider: Provider instance (default: HTTPProvider)
            network: Network to connect to
            modules: Dict of module names to enable/disable
        """
        # Setup provider
        self._provider = provider or HTTPProvider(network=network)
        self._network = network
        
        # Module configuration
        self._modules_config = modules or {}
        
        # Initialize core modules (always enabled)
        self._address = AddressModule(self._provider)
        self._block = BlockModule(self._provider)
        self._tx = TransactionModule(self._provider)
        self._mempool = MempoolModule(self._provider)
        self._fee = FeeModule(self._provider)
        
        # Initialize optional modules
        self._account: Optional[AccountModule] = None
        self._wallet: Optional[WalletModule] = None
        self._mining: Optional[MiningModule] = None
        self._lightning: Optional[LightningModule] = None
        self._price: Optional[PriceModule] = None
        
        # Enable modules based on configuration
        self._init_optional_modules()
        
        logger.info(
            f"Initialized Fractal client for {network.value} "
            f"with {self._provider.__class__.__name__}"
        )
        
    def _init_optional_modules(self) -> None:
        """Initialize optional modules based on configuration."""
        # Account/Wallet modules
        if self._modules_config.get("wallet", True):
            self._account = AccountModule(self._provider)
            self._wallet = WalletModule(self._provider)
            
        # Mining module
        if self._modules_config.get("mining", True):
            self._mining = MiningModule(self._provider)
            
        # Lightning module
        if self._modules_config.get("lightning", False):
            self._lightning = LightningModule(self._provider)
            
        # Price module
        if self._modules_config.get("price", True):
            self._price = PriceModule(self._provider)
            
    # Core module properties
    @property
    def address(self) -> AddressModule:
        """Get address module."""
        return self._address
        
    @property
    def block(self) -> BlockModule:
        """Get block module."""
        return self._block
        
    @property
    def tx(self) -> TransactionModule:
        """Get transaction module."""
        return self._tx
        
    @property
    def mempool(self) -> MempoolModule:
        """Get mempool module."""
        return self._mempool
        
    @property
    def fee(self) -> FeeModule:
        """Get fee module."""
        return self._fee
        
    # Optional module properties
    @property
    def account(self) -> AccountModule:
        """Get account module."""
        if self._account is None:
            raise FractalError("Account module not enabled")
        return self._account
        
    @property
    def wallet(self) -> WalletModule:
        """Get wallet module."""
        if self._wallet is None:
            raise FractalError("Wallet module not enabled")
        return self._wallet
        
    @property
    def mining(self) -> MiningModule:
        """Get mining module."""
        if self._mining is None:
            raise FractalError("Mining module not enabled")
        return self._mining
        
    @property
    def lightning(self) -> LightningModule:
        """Get lightning module."""
        if self._lightning is None:
            raise FractalError("Lightning module not enabled")
        return self._lightning
        
    @property
    def price(self) -> PriceModule:
        """Get price module."""
        if self._price is None:
            raise FractalError("Price module not enabled")
        return self._price
        
    # Provider management
    @property
    def provider(self) -> BaseProvider:
        """Get current provider."""
        return self._provider
        
    @property
    def network(self) -> Network:
        """Get current network."""
        return self._network
        
    async def connect(self) -> None:
        """Connect to provider."""
        await self._provider.connect()
        logger.info("Connected to Fractal Bitcoin")
        
    async def disconnect(self) -> None:
        """Disconnect from provider."""
        await self._provider.disconnect()
        logger.info("Disconnected from Fractal Bitcoin")
        
    async def is_connected(self) -> bool:
        """Check if client is connected."""
        return self._provider.is_connected
        
    # Context manager support
    async def __aenter__(self) -> "Fractal":
        """Async context manager entry."""
        await self.connect()
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        await self.disconnect()
        
    # Factory methods
    @classmethod
    def create_http_client(
        cls,
        network: Network = Network.MAINNET,
        endpoint: Optional[str] = None,
        **kwargs: Any
    ) -> "Fractal":
        """
        Create client with HTTP provider.
        
        Args:
            network: Network to connect to
            endpoint: Custom API endpoint
            **kwargs: Additional provider arguments
            
        Returns:
            Configured Fractal client
        """
        provider = HTTPProvider(network=network, endpoint=endpoint, **kwargs)
        return cls(provider=provider, network=network)
        
    @classmethod
    def create_websocket_client(
        cls,
        network: Network = Network.MAINNET,
        endpoint: Optional[str] = None,
        **kwargs: Any
    ) -> "Fractal":
        """
        Create client with WebSocket provider.
        
        Args:
            network: Network to connect to
            endpoint: Custom WebSocket endpoint
            **kwargs: Additional provider arguments
            
        Returns:
            Configured Fractal client
        """
        provider = WebSocketProvider(network=network, endpoint=endpoint, **kwargs)
        return cls(provider=provider, network=network)
        
    @classmethod
    def create_local_client(
        cls,
        endpoint: str = "http://localhost:8332",
        rpc_user: Optional[str] = None,
        rpc_password: Optional[str] = None,
        **kwargs: Any
    ) -> "Fractal":
        """
        Create client for local node.
        
        Args:
            endpoint: Local node RPC endpoint
            rpc_user: RPC username
            rpc_password: RPC password
            **kwargs: Additional arguments
            
        Returns:
            Configured Fractal client
            
        Note:
            This would need RPC provider implementation
        """
        raise NotImplementedError("Local RPC provider not implemented")
        
    # Utility methods
    def enable_module(self, module_name: str) -> None:
        """
        Enable a module dynamically.
        
        Args:
            module_name: Name of module to enable
        """
        self._modules_config[module_name] = True
        self._init_optional_modules()
        
    def disable_module(self, module_name: str) -> None:
        """
        Disable a module dynamically.
        
        Args:
            module_name: Name of module to disable
        """
        self._modules_config[module_name] = False
        
        # Clear module reference
        module_attr = f"_{module_name}"
        if hasattr(self, module_attr):
            setattr(self, module_attr, None)
            
    async def get_chain_info(self) -> Dict[str, Any]:
        """
        Get general chain information.
        
        Returns:
            Dict with chain info including height, difficulty, etc.
        """
        # Gather info from various modules
        height = await self.block.get_height()
        latest_block = await self.block.get_latest()
        mempool_info = await self.mempool.get_info()
        fee_estimates = await self.fee.get_estimates()
        
        # Get price if available
        price = None
        if self._price:
            try:
                prices = await self.price.get_current()
                price = prices.get("USD")
            except:
                pass
                
        return {
            "network": self.network.value,
            "height": height,
            "latest_block": latest_block.hash,
            "difficulty": latest_block.difficulty,
            "mempool_size": mempool_info["vsize"],
            "mempool_count": mempool_info["count"],
            "fee_estimates": fee_estimates,
            "price_usd": price,
        }
        
    def __repr__(self) -> str:
        """String representation."""
        return (
            f"<Fractal "
            f"network={self.network.value} "
            f"provider={self.provider.__class__.__name__} "
            f"connected={self.provider.is_connected}>"
        )