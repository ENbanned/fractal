"""WebSocket provider implementation for Fractal Bitcoin."""

import asyncio
import json
import logging
from typing import Any, Callable, Optional, Set
from collections import defaultdict

import aiohttp
from aiohttp import ClientSession, ClientWebSocketResponse

from ..constants import Network, WS_ENDPOINTS
from ..exceptions import ProviderError, NetworkError
from ..providers.base import BaseProvider

__all__ = ["WebSocketProvider"]

logger = logging.getLogger(__name__)


class WebSocketProvider(BaseProvider[dict[str, Any]]):
    """
    WebSocket provider for real-time Fractal Bitcoin data.
    
    Handles WebSocket connections for real-time updates from the
    Fractal Bitcoin network. Supports multiple concurrent subscriptions.
    """
    
    def __init__(
        self,
        network: Network = Network.MAINNET,
        endpoint: Optional[str] = None,
        on_message: Optional[Callable[[dict[str, Any]], None]] = None,
        on_error: Optional[Callable[[Exception], None]] = None,
        heartbeat: int = 30,
        reconnect: bool = True,
        max_reconnect_attempts: int = 5,
    ) -> None:
        """
        Initialize WebSocket provider.
        
        Args:
            network: Network to connect to
            endpoint: Custom WebSocket endpoint
            on_message: Global message callback
            on_error: Error callback
            heartbeat: Heartbeat interval in seconds
            reconnect: Auto-reconnect on disconnect
            max_reconnect_attempts: Maximum reconnection attempts
        """
        super().__init__(network)
        
        self.endpoint = endpoint or WS_ENDPOINTS[network]
        self.on_message = on_message
        self.on_error = on_error
        self.heartbeat = heartbeat
        self.reconnect = reconnect
        self.max_reconnect_attempts = max_reconnect_attempts
        
        # Connection state
        self._session: Optional[ClientSession] = None
        self._ws: Optional[ClientWebSocketResponse] = None
        self._subscriptions: Set[str] = set()
        self._callbacks: dict[str, list[Callable]] = defaultdict(list)
        
        # Tasks
        self._message_handler: Optional[asyncio.Task] = None
        self._heartbeat_task: Optional[asyncio.Task] = None
        self._reconnect_attempts = 0
        
    async def connect(self) -> None:
        """Connect to WebSocket endpoint."""
        if self._session is None:
            self._session = ClientSession()
            
        try:
            self._logger.info(f"Connecting to WebSocket: {self.endpoint}")
            self._ws = await self._session.ws_connect(
                self.endpoint,
                heartbeat=self.heartbeat,
            )
            
            self._reconnect_attempts = 0
            self._logger.info("WebSocket connected successfully")
            
            # Start handlers
            self._message_handler = asyncio.create_task(self._handle_messages())
            self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
            
            # Restore subscriptions
            if self._subscriptions:
                for channel in list(self._subscriptions):
                    await self._resubscribe(channel)
                    
        except Exception as e:
            self._logger.error(f"WebSocket connection failed: {e}")
            raise NetworkError(f"Failed to connect to WebSocket: {e}") from e
            
    async def disconnect(self) -> None:
        """Disconnect from WebSocket."""
        # Cancel tasks
        if self._message_handler:
            self._message_handler.cancel()
            self._message_handler = None
            
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            self._heartbeat_task = None
            
        # Close connection
        if self._ws:
            await self._ws.close()
            self._ws = None
            
        if self._session:
            await self._session.close()
            self._session = None
            
        self._logger.info("WebSocket disconnected")
        
    @property
    def is_connected(self) -> bool:
        """Check if WebSocket is connected."""
        return self._ws is not None and not self._ws.closed
        
    async def request(
        self,
        method: str,
        params: Optional[dict[str, Any]] = None,
        **kwargs: Any
    ) -> dict[str, Any]:
        """
        Send request through WebSocket.
        
        Args:
            method: WebSocket action/method
            params: Request parameters
            **kwargs: Additional arguments
            
        Returns:
            Empty dict (WebSocket is async)
            
        Raises:
            ProviderError: If not connected
        """
        if not self.is_connected:
            raise ProviderError("WebSocket not connected")
            
        message = {
            "action": method,
            **(params or {}),
        }
        
        await self._ws.send_json(message)
        self._logger.debug(f"Sent message: {message}")
        
        return {}  # WebSocket responses are handled async
        
    async def subscribe(
        self,
        channel: str,
        callback: Optional[Callable[[dict[str, Any]], None]] = None,
        **params: Any
    ) -> None:
        """
        Subscribe to WebSocket channel.
        
        Args:
            channel: Channel name to subscribe to
            callback: Optional callback for this channel
            **params: Additional subscription parameters
        """
        if not self.is_connected:
            await self.connect()
            
        await self.request("want", {"data": [channel], **params})
        self._subscriptions.add(channel)
        
        if callback:
            self._callbacks[channel].append(callback)
            
        self._logger.info(f"Subscribed to channel: {channel}")
        
    async def unsubscribe(self, channel: str) -> None:
        """
        Unsubscribe from WebSocket channel.
        
        Args:
            channel: Channel name to unsubscribe from
        """
        if not self.is_connected:
            return
            
        await self.request("unwant", {"data": [channel]})
        self._subscriptions.discard(channel)
        self._callbacks.pop(channel, None)
        
        self._logger.info(f"Unsubscribed from channel: {channel}")
        
    async def _handle_messages(self) -> None:
        """Handle incoming WebSocket messages."""
        try:
            async for msg in self._ws:
                if msg.type == aiohttp.WSMsgType.TEXT:
                    try:
                        data = json.loads(msg.data)
                        self._logger.debug(f"Received: {data}")
                        
                        # Call channel-specific callbacks
                        channel = data.get("channel")
                        if channel and channel in self._callbacks:
                            for callback in self._callbacks[channel]:
                                try:
                                    callback(data)
                                except Exception as e:
                                    self._logger.error(f"Callback error: {e}")
                                    
                        # Call global callback
                        if self.on_message:
                            self.on_message(data)
                            
                    except json.JSONDecodeError as e:
                        self._logger.error(f"Invalid JSON received: {e}")
                        
                elif msg.type == aiohttp.WSMsgType.ERROR:
                    error = self._ws.exception()
                    self._logger.error(f"WebSocket error: {error}")
                    if self.on_error:
                        self.on_error(error)
                        
                elif msg.type == aiohttp.WSMsgType.CLOSED:
                    self._logger.warning("WebSocket closed")
                    break
                    
        except Exception as e:
            self._logger.error(f"Message handler error: {e}")
            if self.on_error:
                self.on_error(e)
                
        # Handle reconnection
        if self.reconnect and self._reconnect_attempts < self.max_reconnect_attempts:
            await self._reconnect()
            
    async def _heartbeat_loop(self) -> None:
        """Send periodic heartbeat to keep connection alive."""
        try:
            while self.is_connected:
                await asyncio.sleep(self.heartbeat)
                await self._ws.ping()
                self._logger.debug("Heartbeat sent")
        except Exception as e:
            self._logger.error(f"Heartbeat error: {e}")
            
    async def _reconnect(self) -> None:
        """Attempt to reconnect to WebSocket."""
        self._reconnect_attempts += 1
        wait_time = min(60, 2 ** self._reconnect_attempts)
        
        self._logger.info(
            f"Reconnecting in {wait_time}s "
            f"(attempt {self._reconnect_attempts}/{self.max_reconnect_attempts})"
        )
        
        await asyncio.sleep(wait_time)
        
        try:
            await self.connect()
        except Exception as e:
            self._logger.error(f"Reconnection failed: {e}")
            if self._reconnect_attempts >= self.max_reconnect_attempts:
                raise NetworkError("Maximum reconnection attempts exceeded") from e
                
    async def _resubscribe(self, channel: str) -> None:
        """Resubscribe to a channel after reconnection."""
        try:
            await self.request("want", {"data": [channel]})
            self._logger.debug(f"Resubscribed to channel: {channel}")
        except Exception as e:
            self._logger.error(f"Failed to resubscribe to {channel}: {e}")