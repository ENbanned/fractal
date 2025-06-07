"""Wallet module for Fractal Bitcoin."""

import logging
from typing import Any, Dict, List, Optional, Union
from decimal import Decimal

from ..constants import Network
from ..crypto import PrivateKey
from ..exceptions import WalletError, InsufficientFundsError
from ..modules.account import Account
from ..providers.base import BaseProvider
from ..types.common import Address, Satoshi, TxId, Amount
from ..types.address import UTXO
from ..utils.validation import validate_address, to_satoshi

__all__ = ["WalletModule", "Wallet"]

logger = logging.getLogger(__name__)


class Wallet:
    """
    HD Wallet implementation.
    
    Manages multiple accounts with hierarchical deterministic derivation.
    """
    
    def __init__(
        self,
        name: str,
        network: Network = Network.MAINNET,
        provider: Optional[BaseProvider] = None
    ) -> None:
        """
        Initialize wallet.
        
        Args:
            name: Wallet identifier
            network: Target network
            provider: Optional provider for operations
        """
        self.name = name
        self.network = network
        self._provider = provider
        self._accounts: Dict[str, Account] = {}
        self._default_account: Optional[str] = None
        self._logger = logging.getLogger(f"{__name__}.Wallet.{name}")
        
    def create_account(
        self,
        label: Optional[str] = None,
        index: Optional[int] = None
    ) -> Account:
        """
        Create new account with random key.
        
        Args:
            label: Account label
            index: Specific derivation index
            
        Returns:
            New Account instance
        """
        # Generate new private key
        private_key = PrivateKey.create()
        
        # Create account
        account = Account(
            private_key=private_key,
            network=self.network,
            provider=self._provider,
            label=label or f"Account {len(self._accounts)}",
        )
        
        # Store account
        self._accounts[account.address] = account
        
        # Set as default if first account
        if self._default_account is None:
            self._default_account = account.address
            
        self._logger.info(f"Created account: {account.address}")
        return account
    
    def create_account_from_mnemonic(
        self,
        mnemonic: str,
        passphrase: str = "",
        account_index: int = 0,
        label: Optional[str] = None
    ) -> Account:
        """Create account from BIP39 mnemonic."""
        from ..crypto import derive_key
        
        private_key = derive_key(
            mnemonic=mnemonic,
            passphrase=passphrase,
            account=account_index,
            change=0,
            index=0,
            network=self.network
        )
        
        account = Account(
            private_key=private_key,
            network=self.network,
            provider=self._provider,
            label=label or f"Account {len(self._accounts)}",
        )
        
        self._accounts[account.address] = account
        
        if self._default_account is None:
            self._default_account = account.address
            
        self._logger.info(f"Created account from mnemonic: {account.address}")
        return account
        
    def add_account(
        self,
        private_key: Union[str, bytes, PrivateKey],
        label: Optional[str] = None
    ) -> Account:
        """
        Add account from existing private key.
        
        Args:
            private_key: Private key to import
            label: Account label
            
        Returns:
            Imported Account instance
        """
        if not isinstance(private_key, PrivateKey):
            private_key = PrivateKey(private_key)
            
        account = Account(
            private_key=private_key,
            network=self.network,
            provider=self._provider,
            label=label,
        )
        
        self._accounts[account.address] = account
        
        if self._default_account is None:
            self._default_account = account.address
            
        self._logger.info(f"Added account: {account.address}")
        return account
        
    def import_wif(
        self,
        wif: str,
        label: Optional[str] = None
    ) -> Account:
        """
        Import account from WIF.
        
        Args:
            wif: Wallet Import Format key
            label: Account label
            
        Returns:
            Imported Account instance
        """
        private_key, compressed, network = PrivateKey.from_wif(wif)
        
        if network != self.network:
            raise WalletError(
                f"WIF is for {network.value}, but wallet is on {self.network.value}"
            )
            
        return self.add_account(private_key, label)
        
    def get_account(self, address: Optional[str] = None) -> Account:
        """
        Get account by address or default.
        
        Args:
            address: Account address (optional)
            
        Returns:
            Account instance
        """
        if address is None:
            if self._default_account is None:
                raise WalletError("No accounts in wallet")
            address = self._default_account
            
        if address not in self._accounts:
            raise WalletError(f"Account not found: {address}")
            
        return self._accounts[address]
        
    def list_accounts(self) -> List[Account]:
        """Get all accounts in wallet."""
        return list(self._accounts.values())
        
    @property
    def accounts(self) -> List[Account]:
        """Get all accounts."""
        return self.list_accounts()
        
    @property
    def addresses(self) -> List[str]:
        """Get all addresses."""
        return list(self._accounts.keys())
        
    async def get_balance(self, address: Optional[str] = None) -> Satoshi:
        """
        Get balance for address or total.
        
        Args:
            address: Specific address (optional)
            
        Returns:
            Balance in satoshis
        """
        if not self._provider:
            raise WalletError("Provider required for balance check")
            
        if address:
            account = self.get_account(address)
            return await account.get_balance()
            
        # Get total balance
        total = 0
        for account in self._accounts.values():
            balance = await account.get_balance()
            total += balance
            
        return Satoshi(total)
        
    async def send(
        self,
        to: str,
        amount: Amount,
        from_address: Optional[str] = None,
        fee_rate: Optional[float] = None,
        data: Optional[bytes] = None,
    ) -> TxId:
        """
        Send transaction.
        
        Args:
            to: Recipient address
            amount: Amount to send
            from_address: Source address (optional)
            fee_rate: Fee rate in sats/vByte
            data: Optional OP_RETURN data
            
        Returns:
            Transaction ID
        """
        if not self._provider:
            raise WalletError("Provider required for sending")
            
        account = self.get_account(from_address)
        return await account.send(to, amount, fee_rate=fee_rate, data=data)
        
    def export_private_keys(self) -> Dict[str, str]:
        """
        Export all private keys as WIF.
        
        Returns:
            Dict mapping addresses to WIF keys
        """
        return {
            address: account.export_private_key()
            for address, account in self._accounts.items()
        }
        
    def to_dict(self) -> Dict[str, Any]:
        """Export wallet data."""
        return {
            "name": self.name,
            "network": self.network.value,
            "accounts": [
                {
                    "address": account.address,
                    "label": account.label,
                    "type": account.address_type,
                }
                for account in self._accounts.values()
            ],
            "default_account": self._default_account,
        }


class WalletModule:
    """
    Wallet management module.
    
    Handles creation and management of multiple wallets.
    """
    
    def __init__(self, provider: BaseProvider) -> None:
        """
        Initialize wallet module.
        
        Args:
            provider: Provider instance
        """
        self._provider = provider
        self._wallets: Dict[str, Wallet] = {}
        self._default_wallet: Optional[str] = None
        self._logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
    def create_wallet(
        self,
        name: str,
        network: Optional[Network] = None
    ) -> Wallet:
        """
        Create new wallet.
        
        Args:
            name: Wallet name
            network: Target network
            
        Returns:
            New Wallet instance
        """
        if name in self._wallets:
            raise WalletError(f"Wallet already exists: {name}")
            
        network = network or self._provider.network
        
        wallet = Wallet(
            name=name,
            network=network,
            provider=self._provider
        )
        
        self._wallets[name] = wallet
        
        if self._default_wallet is None:
            self._default_wallet = name
            
        self._logger.info(f"Created wallet: {name}")
        return wallet
        
    def get_wallet(self, name: Optional[str] = None) -> Wallet:
        """
        Get wallet by name or default.
        
        Args:
            name: Wallet name (optional)
            
        Returns:
            Wallet instance
        """
        if name is None:
            if self._default_wallet is None:
                raise WalletError("No wallets available")
            name = self._default_wallet
            
        if name not in self._wallets:
            raise WalletError(f"Wallet not found: {name}")
            
        return self._wallets[name]
        
    def list_wallets(self) -> List[str]:
        """Get all wallet names."""
        return list(self._wallets.keys())
        
    def remove_wallet(self, name: str) -> None:
        """
        Remove wallet.
        
        Args:
            name: Wallet name to remove
        """
        if name not in self._wallets:
            raise WalletError(f"Wallet not found: {name}")
            
        del self._wallets[name]
        
        # Update default if needed
        if self._default_wallet == name:
            self._default_wallet = list(self._wallets.keys())[0] if self._wallets else None
            
        self._logger.info(f"Removed wallet: {name}")
        
    def set_default_wallet(self, name: str) -> None:
        """
        Set default wallet.
        
        Args:
            name: Wallet name
        """
        if name not in self._wallets:
            raise WalletError(f"Wallet not found: {name}")
            
        self._default_wallet = name
        self._logger.info(f"Set default wallet: {name}")
        
    async def get_total_balance(self) -> Satoshi:
        """Get total balance across all wallets."""
        total = 0
        
        for wallet in self._wallets.values():
            balance = await wallet.get_balance()
            total += balance
            
        return Satoshi(total)
        
    def export_all(self) -> Dict[str, Any]:
        """Export all wallet data."""
        return {
            "wallets": {
                name: wallet.to_dict()
                for name, wallet in self._wallets.items()
            },
            "default_wallet": self._default_wallet,
        }
        
