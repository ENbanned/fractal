"""Key management for Fractal Bitcoin."""

import hashlib
import secrets
import hmac
from typing import Optional, Tuple, Union

from coincurve import PrivateKey as SecpPrivateKey, PublicKey as SecpPublicKey

from ..constants import Network, ADDRESS_PREFIXES, BECH32_HRP, TAPROOT_LEAF_VERSION, TAPSCRIPT_VER
from ..exceptions import CryptoError, ValidationError
from ..types.common import PrivateKeyBytes, PublicKeyBytes, Address
from ..utils.encoding import (
    hash160,
    double_sha256,
    encode_base58_check,
    decode_base58_check,
    encode_bech32,
    encode_address,
    tagged_hash,
    lift_x
)
from ..utils.validation import validate_private_key, validate_public_key

__all__ = ["PrivateKey", "PublicKey", "generate_mnemonic", "derive_key"]


class PrivateKey:
    """
    Bitcoin private key wrapper.
    
    Handles private key operations including signing, public key derivation,
    and various export formats (WIF, hex).
    """
    
    def __init__(self, key: Union[bytes, str, "PrivateKey"]) -> None:
        """
        Initialize private key.
        
        Args:
            key: Private key as 32 bytes, hex string, or another PrivateKey
            
        Raises:
            ValidationError: If key format is invalid
        """
        if isinstance(key, PrivateKey):
            self._secret = key._secret
            return
            
        # Validate and normalize key
        self._secret = PrivateKeyBytes(validate_private_key(key))
        
        # Initialize crypto library
        self._key = SecpPrivateKey(self._secret)
            
    @classmethod
    def create(cls) -> "PrivateKey":
        """
        Create new random private key.
        
        Returns:
            New PrivateKey instance
        """
        # Generate cryptographically secure random bytes
        while True:
            key_bytes = secrets.token_bytes(32)
            try:
                # Validate key is within valid range
                return cls(key_bytes)
            except ValidationError:
                # Extremely rare, try again
                continue
                
    @classmethod
    def from_seed(cls, seed: bytes) -> "PrivateKey":
        """
        Create private key from seed bytes.
        
        Args:
            seed: Seed bytes (any length)
            
        Returns:
            New PrivateKey instance
        """
        # Use SHA256 to get 32 bytes from seed
        key_bytes = hashlib.sha256(seed).digest()
        return cls(key_bytes)
        
    @classmethod
    def from_wif(cls, wif: str) -> Tuple["PrivateKey", bool, Network]:
        """
        Import private key from WIF.
        
        Args:
            wif: Wallet Import Format string
            
        Returns:
            Tuple of (private_key, is_compressed, network)
            
        Raises:
            ValidationError: If WIF is invalid
        """
        try:
            data = decode_base58_check(wif)
        except Exception as e:
            raise ValidationError(f"Invalid WIF format: {e}") from e
            
        if len(data) not in (33, 34):
            raise ValidationError(f"Invalid WIF length: {len(data)}")
            
        # Parse network
        version = data[0]
        if version == 0x80:
            network = Network.MAINNET
        elif version == 0xef:
            network = Network.TESTNET
        else:
            raise ValidationError(f"Unknown WIF version: {version:#x}")
            
        # Parse key and compression flag
        if len(data) == 33:
            key_bytes = data[1:33]
            compressed = False
        else:  # 34 bytes
            key_bytes = data[1:33]
            compressed = data[33] == 0x01
            if not compressed:
                raise ValidationError(f"Invalid compression flag: {data[33]:#x}")
                
        return cls(key_bytes), compressed, network
        
    @property
    def secret(self) -> PrivateKeyBytes:
        """Get private key as bytes."""
        return self._secret
        
    def hex(self) -> str:
        """Get private key as hex string."""
        return self._secret.hex()
        
    def wif(self, network: Network = Network.MAINNET, compressed: bool = True) -> str:
        """
        Export private key in Wallet Import Format.
        
        Args:
            network: Target network
            compressed: Use compressed format
            
        Returns:
            WIF encoded private key
        """
        # Network version byte
        version = b"\x80" if network == Network.MAINNET else b"\xef"
        
        # Build data
        data = version + self._secret
        if compressed:
            data += b"\x01"
            
        return encode_base58_check(data)
        
    def public_key(self, compressed: bool = True) -> "PublicKey":
        """
        Get corresponding public key.
        
        Args:
            compressed: Return compressed format
            
        Returns:
            PublicKey instance
        """

        pubkey_obj = self._key.public_key
        serialized = pubkey_obj.format(compressed=compressed)
            
        return PublicKey(serialized, compressed=compressed)
    
    def taproot_internal_key(self) -> bytes:
        """
        Get internal public key for Taproot (x-only).
        
        Returns:
            32-byte x-only internal public key
        """
        pubkey = self.public_key(compressed=True)
        return pubkey.point[1:33]  # Remove prefix
        
    def taproot_output_key(self, merkle_root: Optional[bytes] = None) -> bytes:
        """
        Get Taproot output key.
        
        Args:
            merkle_root: Script tree merkle root (None for key-path only)
            
        Returns:
            32-byte x-only output public key
        """
        pubkey = self.public_key(compressed=True)
        internal_key = self.taproot_internal_key()
        return pubkey._taproot_tweak_public_key(internal_key, merkle_root)
        
    def taproot_address(self, network: Network = Network.MAINNET) -> Address:
        """
        Get Taproot address.
        
        Args:
            network: Target network
            
        Returns:
            P2TR address
        """
        output_key = self.taproot_output_key()
        return encode_address("p2tr", output_key, network)
        
    def sign(self, message_hash: bytes, deterministic: bool = True) -> bytes:
        """
        Sign 32-byte message hash.
        
        Args:
            message_hash: 32-byte hash to sign
            deterministic: Use RFC 6979 deterministic signing
            
        Returns:
            DER-encoded signature
            
        Raises:
            CryptoError: If signing fails
        """
        if len(message_hash) != 32:
            raise ValueError("Message hash must be 32 bytes")
            
        try:
            return self._key.sign(message_hash, hasher=None)
        except Exception as e:
            raise CryptoError(f"Signing failed: {e}") from e
            
    def sign_recoverable(self, message_hash: bytes) -> bytes:
        """
        Create recoverable signature.
        
        Args:
            message_hash: 32-byte hash to sign
            
        Returns:
            65-byte recoverable signature
            
        Raises:
            CryptoError: If signing fails
        """
        if len(message_hash) != 32:
            raise ValueError("Message hash must be 32 bytes")
            
        try:
            return self._key.sign_recoverable(message_hash, hasher=None)
        except Exception as e:
            raise CryptoError(f"Recoverable signing failed: {e}") from e
            
    def derive_child(self, index: int, hardened: bool = False) -> "PrivateKey":
        """
        Derive child private key (BIP32).
        
        Args:
            index: Child key index
            hardened: Use hardened derivation
            
        Returns:
            Child PrivateKey
            
        Raises:
            CryptoError: If derivation fails
        """
        if hardened:
            index |= 0x80000000
            
        # Get public key for non-hardened derivation
        if not hardened:
            pubkey = self.public_key(compressed=True).point
            data = pubkey + index.to_bytes(4, "big")
        else:
            data = b"\x00" + self._secret + index.to_bytes(4, "big")
            
        # Compute HMAC-SHA512
        hmac_key = b"Bitcoin seed"  # Would use chain code in full BIP32
        h = hmac.new(hmac_key, data, hashlib.sha512).digest()
        
        # Split result
        child_key = h[:32]
        child_chain_code = h[32:]  # Would be used for further derivation
        
        # Add to parent key (modulo curve order)
        n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        key_int = int.from_bytes(self._secret, "big")
        child_int = int.from_bytes(child_key, "big")
        result_int = (key_int + child_int) % n
        
        if result_int == 0:
            raise CryptoError("Invalid child key")
            
        result_bytes = result_int.to_bytes(32, "big")
        return PrivateKey(result_bytes)
        
    def __eq__(self, other: object) -> bool:
        """Check equality."""
        if not isinstance(other, PrivateKey):
            return False
        return self._secret == other._secret
        
    def __repr__(self) -> str:
        """String representation."""
        # Show first and last 4 chars of hex for security
        hex_str = self.hex()
        masked = f"{hex_str[:4]}...{hex_str[-4:]}"
        return f"PrivateKey({masked})"


class PublicKey:
    """
    Bitcoin public key wrapper.
    
    Handles public key operations including address generation,
    verification, and various encoding formats.
    """
    
    def __init__(
        self,
        key: Union[bytes, str, "PublicKey"],
        compressed: Optional[bool] = None
    ) -> None:
        """
        Initialize public key.
        
        Args:
            key: Public key as bytes, hex string, or another PublicKey
            compressed: Whether key is compressed (auto-detected if None)
            
        Raises:
            ValidationError: If key format is invalid
        """
        if isinstance(key, PublicKey):
            self._point = key._point
            self._compressed = key._compressed
            return
            
        # Validate and normalize key
        key_bytes = validate_public_key(key)
        self._point = PublicKeyBytes(key_bytes)
        
        # Detect compression
        if compressed is None:
            self._compressed = len(key_bytes) == 33
        else:
            self._compressed = compressed
            
        # Initialize crypto library
        self._key = SecpPublicKey(key_bytes)
            
    @property
    def point(self) -> PublicKeyBytes:
        """Get public key as bytes."""
        if self._compressed and len(self._point) == 65:
                return PublicKeyBytes(self._key.format(compressed=True))
        elif not self._compressed and len(self._point) == 33:
                return PublicKeyBytes(self._key.format(compressed=False))
        return self._point
        
    def hex(self) -> str:
        """Get public key as hex string."""
        return self.point.hex()
        
    def hash160(self) -> bytes:
        """Get HASH160 of public key."""
        return hash160(self.point)
        
    def p2pkh_address(self, network: Network = Network.MAINNET) -> Address:
        """
        Get Pay-to-PubKey-Hash address.
        
        Args:
            network: Target network
            
        Returns:
            P2PKH address
        """
        return encode_address("p2pkh", self.hash160(), network)
        
    def p2wpkh_address(self, network: Network = Network.MAINNET) -> Address:
        """
        Get Pay-to-Witness-PubKey-Hash (SegWit) address.
        
        Args:
            network: Target network
            
        Returns:
            P2WPKH address
            
        Raises:
            ValidationError: If public key is not compressed
        """
        if not self._compressed:
            raise ValidationError("SegWit requires compressed public keys")
            
        return encode_address("p2wpkh", self.hash160(), network)
        
    def p2tr_address(self, network: Network = Network.MAINNET) -> Address:
        """
        Get Pay-to-Taproot address.
        
        Args:
            network: Target network
            
        Returns:
            P2TR address
            
        Raises:
            ValidationError: If public key is not compressed
        """
        if not self._compressed:
            raise ValidationError("Taproot requires compressed public keys")
            
        x_only = self.point[1:33]
        
        internal_pubkey = x_only
        
        output_key = self._taproot_tweak_public_key(internal_pubkey, None)
        
        return encode_address("p2tr", output_key, network)
    
    def _taproot_tweak_public_key(self, internal_key: bytes, merkle_root: Optional[bytes]) -> bytes:
        """
        Tweak internal public key for Taproot.
        
        Args:
            internal_key: 32-byte x-only internal public key
            merkle_root: 32-byte merkle root of script tree (None for key-path only)
            
        Returns:
            32-byte x-only output public key
            
        Raises:
            CryptoError: If tweaking fails
        """
        if merkle_root is None:
            # Key-path spending only (no script tree)
            tweak_data = internal_key
        else:
            # Script-path spending available
            tweak_data = internal_key + merkle_root
            
        # Compute tweak
        tweak = tagged_hash("TapTweak", tweak_data)
        
        # Lift internal key to curve point
        internal_point = lift_x(internal_key)
        if internal_point is None:
            raise CryptoError("Invalid internal public key")
            
        # Parse the point
        if internal_point[0] == 0x02:
            # Even y
            internal_key_full = internal_point
        else:
            # This shouldn't happen with lift_x
            raise CryptoError("Unexpected point format")
            
        # Create coincurve point for arithmetic
        try:
            from coincurve import PublicKey as SecpPublicKey
            internal_secp = SecpPublicKey(internal_key_full)
            
            # Add tweak to point
            tweak_int = int.from_bytes(tweak, "big")
            tweaked_secp = internal_secp.add(tweak_int.to_bytes(32, "big"))
            
            # Get x-coordinate only
            tweaked_point = tweaked_secp.format(compressed=True)
            return tweaked_point[1:33]  # Remove prefix, return x-only
            
        except Exception as e:
            raise CryptoError(f"Taproot tweaking failed: {e}") from e
        
    def verify(self, signature: bytes, message_hash: bytes) -> bool:
        """
        Verify signature.
        
        Args:
            signature: DER-encoded signature
            message_hash: 32-byte message hash
            
        Returns:
            True if signature is valid
        """
        if len(message_hash) != 32:
            return False
            
        try:
            self._key.verify(signature, message_hash, hasher=None)
            return True
        except Exception:
            return False
            
    def __eq__(self, other: object) -> bool:
        """Check equality."""
        if not isinstance(other, PublicKey):
            return False
        return self.point == other.point
        
    def __repr__(self) -> str:
        """String representation."""
        addr = self.p2pkh_address()
        return f"PublicKey({addr})"


def generate_mnemonic(strength: int = 128) -> str:
    """Generate BIP39 mnemonic phrase."""
    from .bip39 import generate_mnemonic as _generate
    return _generate(strength)


def derive_key(
    mnemonic: str,
    passphrase: str = "",
    account: int = 0,
    change: int = 0,
    index: int = 0,
    network: Network = Network.MAINNET
) -> PrivateKey:
    """Derive private key from mnemonic (BIP39/BIP44)."""
    from .bip39 import mnemonic_to_seed
    from .hd import HDNode
    
    path = f"m/44'/0'/{account}'/{change}/{index}"
    seed = mnemonic_to_seed(mnemonic, passphrase)
    master = HDNode.from_seed(seed, network)
    derived = master.derive_path(path)
    
    return derived.get_private_key()