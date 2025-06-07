"""Fractal Bitcoin exceptions hierarchy."""

from typing import Any, Optional

__all__ = [
    "FractalError",
    "ProviderError",
    "ValidationError", 
    "TransactionError",
    "InsufficientFundsError",
    "BlockNotFoundError",
    "AddressError",
    "TimeoutError",
    "RateLimitError",
    "NetworkError",
    "APIError",
    "CryptoError",
    "WalletError",
    "SerializationError",
]


class FractalError(Exception):
    """Base exception for all Fractal Bitcoin errors."""
    
    def __init__(
        self, 
        message: str, 
        code: Optional[int] = None, 
        data: Optional[Any] = None
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.data = data
        
    def __str__(self) -> str:
        if self.code:
            return f"[{self.code}] {self.message}"
        return self.message


class ProviderError(FractalError):
    """Raised when provider encounters an error."""
    pass


class NetworkError(ProviderError):
    """Raised when network communication fails."""
    pass


class APIError(ProviderError):
    """Raised when API returns an error response."""
    pass


class ValidationError(FractalError):
    """Raised when validation fails."""
    pass


class TransactionError(FractalError):
    """Raised when transaction operation fails."""
    pass


class InsufficientFundsError(TransactionError):
    """Raised when insufficient funds for transaction."""
    
    def __init__(
        self, 
        required: int, 
        available: int, 
        message: Optional[str] = None
    ) -> None:
        if message is None:
            message = f"Insufficient funds: required {required} sats, available {available} sats"
        super().__init__(message)
        self.required = required
        self.available = available


class BlockNotFoundError(FractalError):
    """Raised when block is not found."""
    pass


class AddressError(FractalError):
    """Raised when address operation fails."""
    pass


class TimeoutError(NetworkError):
    """Raised when operation times out."""
    pass


class RateLimitError(NetworkError):
    """Raised when rate limit is exceeded."""
    
    def __init__(
        self, 
        message: str = "Rate limit exceeded",
        retry_after: Optional[int] = None
    ) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class CryptoError(FractalError):
    """Raised when cryptographic operation fails."""
    pass


class WalletError(FractalError):
    """Raised when wallet operation fails."""
    pass


class SerializationError(FractalError):
    """Raised when serialization/deserialization fails."""
    pass