"""HTTP provider implementation for Fractal Bitcoin."""

import asyncio
import json
import logging
from typing import Any, Optional, Union
from urllib.parse import urljoin

import aiohttp
from aiohttp import ClientTimeout, ClientSession, ClientResponse

from ..constants import (
    API_ENDPOINTS,
    DEFAULT_TIMEOUT,
    MAX_RETRIES,
    RETRY_DELAY,
    USER_AGENT,
    Network,
)
from ..exceptions import (
    ProviderError,
    NetworkError,
    APIError,
    RateLimitError,
    TimeoutError,
)
from ..providers.base import BaseProvider

__all__ = ["HTTPProvider"]

logger = logging.getLogger(__name__)


class HTTPProvider(BaseProvider[Any]):
    """
    HTTP provider for Fractal Bitcoin API.
    
    Handles all HTTP communication with the Fractal Bitcoin nodes.
    Includes automatic retry logic, proxy support, and custom headers.
    """
    
    def __init__(
        self,
        network: Network = Network.MAINNET,
        endpoint: Optional[str] = None,
        timeout: int = DEFAULT_TIMEOUT,
        session: Optional[ClientSession] = None,
        proxy: Optional[str] = None,
        headers: Optional[dict[str, str]] = None,
        api_key: Optional[str] = None,
    ) -> None:
        """
        Initialize HTTP provider.
        
        Args:
            network: Network to connect to
            endpoint: Custom API endpoint (overrides default)
            timeout: Request timeout in seconds
            session: Existing aiohttp session to use
            proxy: Proxy URL for requests
            headers: Additional headers for requests
            api_key: API key for authenticated endpoints
        """
        super().__init__(network)
        
        self.endpoint = self._normalize_endpoint(endpoint or API_ENDPOINTS[network])
        self.timeout = ClientTimeout(total=timeout)
        self.proxy = proxy
        self.api_key = api_key
        
        # Setup headers
        self.headers = {
            "User-Agent": USER_AGENT,
            "Content-Type": "application/json",
            **(headers or {}),
        }
        
        if api_key:
            self.headers["X-Mempool-Auth"] = api_key
            
        # Session management
        self._session = session
        self._owns_session = session is None
        self._connected = False
        
    def _normalize_endpoint(self, endpoint: str) -> str:
        """Normalize API endpoint URL."""
        endpoint = endpoint.rstrip("/")
        if not endpoint.endswith("/api"):
            endpoint += "/api"
        return endpoint
        
    async def connect(self) -> None:
        """Initialize HTTP session."""
        if self._session is None:
            connector = aiohttp.TCPConnector(
                ssl=True,
                limit=100,
                limit_per_host=10,
            )
            self._session = ClientSession(
                connector=connector,
                timeout=self.timeout,
                headers=self.headers,
            )
            
        self._connected = True
        self._logger.info(f"Connected to {self.endpoint}")
        
    async def disconnect(self) -> None:
        """Close HTTP session."""
        if self._session and self._owns_session:
            await self._session.close()
            self._session = None
            
        self._connected = False
        self._logger.info("Disconnected from provider")
        
    @property
    def is_connected(self) -> bool:
        """Check if provider is connected."""
        return (
            self._connected 
            and self._session is not None 
            and not self._session.closed
        )
        
    async def request(
        self,
        method: str,
        params: Optional[dict[str, Any]] = None,
        raw_response: bool = False,
        **kwargs: Any
    ) -> Any:
        """
        Make HTTP request to API.
        
        Args:
            method: API endpoint path
            params: Query parameters
            raw_response: Return raw response without parsing
            **kwargs: Additional request arguments
            
        Returns:
            Parsed JSON response or raw text
            
        Raises:
            ProviderError: If request fails
            RateLimitError: If rate limited
            TimeoutError: If request times out
        """
        if not self.is_connected:
            await self.connect()
            
        # Ensure method starts with /
        if not method.startswith("/"):
            method = f"/{method}"
            
        url = f"{self.endpoint}{method}"
        
        for attempt in range(MAX_RETRIES):
            try:
                response = await self._make_request(url, params, **kwargs)
                
                if raw_response:
                    return await response.text()
                    
                return await self._parse_response(response)
                
            except (RateLimitError, TimeoutError):
                if attempt == MAX_RETRIES - 1:
                    raise
                    
            except (aiohttp.ClientError, NetworkError) as e:
                if attempt == MAX_RETRIES - 1:
                    raise NetworkError(f"Request failed after {MAX_RETRIES} attempts") from e
                    
            # Exponential backoff
            await asyncio.sleep(RETRY_DELAY * (2 ** attempt))
            
    async def _make_request(
        self,
        url: str,
        params: Optional[dict[str, Any]] = None,
        **kwargs: Any
    ) -> ClientResponse:
        """Make actual HTTP request."""
        try:
            self._logger.debug(f"Request: GET {url} params={params}")
            
            async with self._session.get(
                url,
                params=params,
                proxy=self.proxy,
                **kwargs
            ) as response:
                self._logger.debug(f"Response: {response.status}")
                
                if response.status == 429:
                    retry_after = response.headers.get("Retry-After")
                    raise RateLimitError(
                        "Rate limit exceeded",
                        retry_after=int(retry_after) if retry_after else None
                    )
                    
                if response.status >= 500:
                    text = await response.text()
                    raise NetworkError(f"Server error {response.status}: {text}")
                    
                if response.status >= 400:
                    text = await response.text()
                    raise APIError(f"Client error {response.status}: {text}", code=response.status)
                    
                # Need to return response with content read
                await response.read()
                return response
                
        except asyncio.TimeoutError as e:
            raise TimeoutError("Request timed out") from e
        except aiohttp.ClientError as e:
            raise NetworkError(f"Network error: {e}") from e
            
    async def _parse_response(self, response: ClientResponse) -> Any:
        """Parse response based on content type."""
        content_type = response.headers.get("Content-Type", "")
        text = await response.text()
        
        if "application/json" in content_type:
            try:
                return json.loads(text)
            except json.JSONDecodeError as e:
                raise ProviderError(f"Invalid JSON response: {e}") from e
                
        # For plain text responses (like block height)
        return text.strip()
        
    async def post(
        self,
        method: str,
        data: Union[str, bytes, dict[str, Any]],
        content_type: str = "text/plain",
        **kwargs: Any
    ) -> Any:
        """
        Make POST request to API.
        
        Args:
            method: API endpoint path  
            data: Request body data
            content_type: Content type header
            **kwargs: Additional request arguments
            
        Returns:
            Response data
            
        Raises:
            ProviderError: If request fails
        """
        if not self.is_connected:
            await self.connect()
            
        if not method.startswith("/"):
            method = f"/{method}"
            
        url = f"{self.endpoint}{method}"
        
        # Prepare data based on content type
        if content_type == "application/json" and isinstance(data, dict):
            data = json.dumps(data)
            
        headers = {"Content-Type": content_type}
        
        try:
            self._logger.debug(f"Request: POST {url}")
            
            async with self._session.post(
                url,
                data=data,
                headers=headers,
                proxy=self.proxy,
                **kwargs
            ) as response:
                if response.status >= 400:
                    text = await response.text()
                    raise APIError(
                        f"POST request failed {response.status}: {text}",
                        code=response.status
                    )
                    
                return await response.text()
                
        except aiohttp.ClientError as e:
            raise NetworkError(f"POST request failed: {e}") from e