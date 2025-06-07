"""Account module for Fractal Bitcoin."""

import logging
from typing import Optional, List, Union, Dict, Any

from ..constants import Network
from ..crypto import PrivateKey, PublicKey
from ..exceptions import InsufficientFundsError, TransactionError, WalletError
from ..providers.base import BaseProvider
from ..types.address import UTXO, AddressType
from ..types.common import Address, Satoshi, TxId, Amount
from ..types.transaction import TransactionBuilder, RawTransaction
from ..utils.validation import to_satoshi, validate_address

__all__ = ["Account", "AccountModule"]

logger = logging.getLogger(__name__)


class Account:
    """
    Individual account with private key.
    
    Represents a single Bitcoin account that can have multiple
    address types (P2PKH, P2WPKH, P2TR).
    """
    
    def __init__(
        self,
        private_key: PrivateKey,
        network: Network = Network.MAINNET,
        provider: Optional[BaseProvider] = None,
        label: Optional[str] = None,
        address_type: str = "p2wpkh",
    ) -> None:
        """
        Initialize account.
        
        Args:
            private_key: Account private key
            network: Target network
            provider: Optional provider for operations
            label: Account label
            address_type: Default address type
        """
        self._private_key = private_key
        self._public_key = private_key.public_key(compressed=True)
        self.network = network
        self._provider = provider
        self.label = label
        self._address_type = address_type
        
        # Generate addresses
        self._addresses = {
            "p2pkh": self._public_key.p2pkh_address(network),
            "p2wpkh": self._public_key.p2wpkh_address(network),
            "p2tr": self._public_key.p2tr_address(network),
        }
        
        self._logger = logging.getLogger(f"{__name__}.Account.{self.address[:8]}")
        
    @property
    def address(self) -> Address:
        """Get default address."""
        return self._addresses[self._address_type]
        
    @property
    def p2pkh_address(self) -> Address:
        """Get legacy P2PKH address."""
        return self._addresses["p2pkh"]
        
    @property
    def p2wpkh_address(self) -> Address:
        """Get SegWit P2WPKH address."""
        return self._addresses["p2wpkh"]
        
    @property
    def p2tr_address(self) -> Address:
        """Get Taproot P2TR address."""
        return self._addresses["p2tr"]
        
    @property
    def address_type(self) -> str:
        """Get default address type."""
        return self._address_type
        
    def set_address_type(self, address_type: str) -> None:
        """
        Set default address type.
        
        Args:
            address_type: One of 'p2pkh', 'p2wpkh', 'p2tr'
        """
        if address_type not in self._addresses:
            raise ValueError(f"Invalid address type: {address_type}")
        self._address_type = address_type
        
    @property
    def public_key(self) -> PublicKey:
        """Get public key."""
        return self._public_key
        
    async def get_balance(self) -> Satoshi:
        """
        Get total balance across all address types.
        
        Returns:
            Total balance in satoshis
        """
        if not self._provider:
            raise WalletError("Provider required for balance check")
            
        total = 0
        
        # Check all address types
        for address in self._addresses.values():
            try:
                from ..modules.address import AddressModule
                addr_module = AddressModule(self._provider)
                balance = await addr_module.get_balance(str(address))
                total += balance
            except Exception as e:
                self._logger.warning(f"Failed to get balance for {address}: {e}")
                
        return Satoshi(total)
        
    async def get_utxos(self, confirmed_only: bool = False) -> List[UTXO]:
        """
        Get all UTXOs for account.
        
        Args:
            confirmed_only: Only return confirmed UTXOs
            
        Returns:
            List of UTXOs
        """
        if not self._provider:
            raise WalletError("Provider required for UTXO retrieval")
            
        all_utxos = []
        
        # Get UTXOs for all address types
        for address in self._addresses.values():
            try:
                from ..modules.address import AddressModule
                addr_module = AddressModule(self._provider)
                utxos = await addr_module.get_utxos(str(address), confirmed_only)
                all_utxos.extend(utxos)
            except Exception as e:
                self._logger.warning(f"Failed to get UTXOs for {address}: {e}")
                
        return all_utxos
        
    async def send(
        self,
        to: str,
        amount: Amount,
        fee_rate: Optional[float] = None,
        data: Optional[bytes] = None,
        change_address: Optional[str] = None,
    ) -> TxId:
        """
        Send transaction.
        
        Args:
            to: Recipient address
            amount: Amount to send
            fee_rate: Fee rate in sats/vByte
            data: Optional OP_RETURN data
            change_address: Custom change address
            
        Returns:
            Transaction ID
        """
        if not self._provider:
            raise WalletError("Provider required for sending")
            
        # Validate inputs
        to = validate_address(to)
        amount_sats = to_satoshi(amount)
        
        # Get fee rate if not provided
        if fee_rate is None:
            from ..modules.fee import FeeModule
            fee_module = FeeModule(self._provider)
            fee_rate = await fee_module.get_priority_fee()
            
        # Get UTXOs
        utxos = await self.get_utxos(confirmed_only=True)
        if not utxos:
            raise InsufficientFundsError("No UTXOs available", required=amount_sats, available=0)
            
        # Build transaction
        builder = TransactionBuilder()
        
        # Add inputs
        total_input = 0
        selected_utxos = []
        
        for utxo in sorted(utxos, key=lambda x: x.value, reverse=True):
            builder.add_input(utxo.txid, utxo.vout)
            total_input += utxo.value
            selected_utxos.append(utxo)
            
            # Estimate size and check if we have enough
            estimated_size = builder.raw_tx.estimate_vsize()
            estimated_fee = int(estimated_size * fee_rate)
            
            if total_input >= amount_sats + estimated_fee:
                break
                
        if total_input < amount_sats + estimated_fee:
            raise InsufficientFundsError(
                required=amount_sats + estimated_fee,
                available=total_input
            )
            
        # Add outputs
        builder.add_output(to, amount_sats)
        
        # Add OP_RETURN if provided
        if data:
            builder.raw_tx.add_data_output(data)
            
        # Add change output
        change = total_input - amount_sats - estimated_fee
        if change > 546:  # Dust limit
            change_addr = change_address or str(self.address)
            builder.add_output(change_addr, change)
            
        # Sign transaction
        raw_tx = await self._sign_transaction(builder.raw_tx, selected_utxos)
        
        # Broadcast
        from ..modules.transaction import TransactionModule
        tx_module = TransactionModule(self._provider)
        txid = await tx_module.broadcast(raw_tx)
        
        self._logger.info(f"Sent {amount_sats} sats to {to}, txid: {txid}")
        return txid
        
    async def _sign_transaction(
        self,
        raw_tx: RawTransaction,
        utxos: list[UTXO]
    ) -> bytes:
        """Sign transaction."""
        from ..crypto.transaction_signing import sign_transaction
        
        private_keys = [self._private_key] * len(raw_tx.inputs)
        return sign_transaction(raw_tx, private_keys, utxos)
        
    def sign_message(self, message: str) -> bytes:
        """
        Sign message with private key.
        
        Args:
            message: Message to sign
            
        Returns:
            Signature bytes
        """
        from ..crypto.signature import sign_message
        return sign_message(self._private_key, message)
        
    def export_private_key(self) -> str:
        """
        Export private key as WIF.
        
        Returns:
            WIF-encoded private key
        """
        return self._private_key.wif(self.network)
        
    def to_dict(self) -> Dict[str, Any]:
        """Export account data (without private key)."""
        return {
            "address": str(self.address),
            "addresses": {k: str(v) for k, v in self._addresses.items()},
            "address_type": self._address_type,
            "label": self.label,
            "network": self.network.value,
        }
        
    def __repr__(self) -> str:
        """String representation."""
        return f"<Account address={self.address} label={self.label}>"


class AccountModule:
    """
    Account management module.
    
    Factory for creating and managing accounts.
    """
    
    def __init__(self, provider: BaseProvider) -> None:
        """
        Initialize account module.
        
        Args:
            provider: Provider instance
        """
        self._provider = provider
        self._logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
    def create_account(
        self,
        label: Optional[str] = None,
        address_type: str = "p2wpkh"
    ) -> Account:
        """
        Create new account with random key.
        
        Args:
            label: Account label
            address_type: Default address type
            
        Returns:
            New Account instance
        """
        private_key = PrivateKey.create()
        
        account = Account(
            private_key=private_key,
            network=self._provider.network,
            provider=self._provider,
            label=label,
            address_type=address_type,
        )
        
        self._logger.info(f"Created account: {account.address}")
        return account
        
    def from_private_key(
        self,
        private_key: Union[str, bytes, PrivateKey],
        label: Optional[str] = None,
        address_type: str = "p2wpkh"
    ) -> Account:
        """
        Create account from private key.
        
        Args:
            private_key: Private key
            label: Account label
            address_type: Default address type
            
        Returns:
            Account instance
        """
        if not isinstance(private_key, PrivateKey):
            private_key = PrivateKey(private_key)
            
        return Account(
            private_key=private_key,
            network=self._provider.network,
            provider=self._provider,
            label=label,
            address_type=address_type,
        )
        
    def from_wif(
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
            Account instance
        """
        private_key, compressed, network = PrivateKey.from_wif(wif)
        
        if network != self._provider.network:
            raise WalletError(
                f"WIF is for {network.value}, "
                f"but provider is on {self._provider.network.value}"
            )
            
        return Account(
            private_key=private_key,
            network=network,
            provider=self._provider,
            label=label,
        )