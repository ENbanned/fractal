"""
Fractal Bitcoin Python Library

A comprehensive Python library for interacting with the Fractal Bitcoin network,
inspired by web3.py design principles.
"""

from .client import Fractal
from .constants import Network
from .exceptions import (
    FractalError,
    ProviderError,
    ValidationError,
    TransactionError,
    InsufficientFundsError,
)
from .providers import HTTPProvider, WebSocketProvider
from .crypto import PrivateKey, PublicKey
from .types import (
    Address,
    Transaction,
    Block,
    UTXO,
)

__version__ = "1.0.0"
__author__ = "Fractal Bitcoin Python Library"

__all__ = [
    # Main client
    "Fractal",
    
    # Network
    "Network",
    
    # Providers
    "HTTPProvider",
    "WebSocketProvider",
    
    # Exceptions
    "FractalError",
    "ProviderError", 
    "ValidationError",
    "TransactionError",
    "InsufficientFundsError",
    
    # Crypto
    "PrivateKey",
    "PublicKey",
    
    # Types
    "Address",
    "Transaction",
    "Block",
    "UTXO",
]


def connect(
    network: Network = Network.MAINNET,
    provider: str = "http",
    **kwargs
) -> Fractal:
    """
    Create and connect to Fractal Bitcoin network.
    
    Args:
        network: Network to connect to (mainnet or testnet)
        provider: Provider type ('http' or 'websocket')
        **kwargs: Additional provider arguments
        
    Returns:
        Connected Fractal client instance
        
    Example:
        >>> client = fractal.connect()
        >>> client = fractal.connect(network=Network.TESTNET)
        >>> client = fractal.connect(provider='websocket')
    """
    if provider == "http":
        provider_instance = HTTPProvider(network=network, **kwargs)
    elif provider == "websocket":
        provider_instance = WebSocketProvider(network=network, **kwargs)
    else:
        raise ValueError(f"Unknown provider type: {provider}")
        
    return Fractal(provider=provider_instance, network=network)