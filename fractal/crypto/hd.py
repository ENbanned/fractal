"""Hierarchical Deterministic key derivation for Fractal Bitcoin."""

import hmac
import hashlib
from typing import Optional

from ..constants import Network
from ..crypto.keys import PrivateKey, PublicKey
from ..exceptions import CryptoError
from ..utils.encoding import encode_base58_check, hash160

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

class HDNode:
    """HD wallet node (BIP32)."""
    
    def __init__(
        self,
        private_key: Optional[bytes],
        public_key: bytes,
        chain_code: bytes,
        depth: int = 0,
        parent_fingerprint: bytes = b'\x00\x00\x00\x00',
        index: int = 0,
        network: Network = Network.MAINNET
    ):
        self.private_key = private_key
        self.public_key = public_key
        self.chain_code = chain_code
        self.depth = depth
        self.parent_fingerprint = parent_fingerprint
        self.index = index
        self.network = network
        
    @classmethod
    def from_seed(cls, seed: bytes, network: Network = Network.MAINNET) -> "HDNode":
        """Create master node from seed."""
        if len(seed) < 16 or len(seed) > 64:
            raise ValueError("Seed must be between 16 and 64 bytes")
            
        h = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
        
        private_key_bytes = h[:32]
        chain_code = h[32:]
        
        key_int = int.from_bytes(private_key_bytes, 'big')
        if key_int == 0 or key_int >= N:
            raise CryptoError("Invalid master key")
        
        private_key = PrivateKey(private_key_bytes)
        public_key = private_key.public_key(compressed=True).point
        
        return cls(
            private_key=private_key_bytes,
            public_key=public_key,
            chain_code=chain_code,
            network=network
        )
        
    def derive(self, index: int) -> "HDNode":
        """Derive child node."""
        if index >= 0x80000000:
            if self.private_key is None:
                raise CryptoError("Cannot do hardened derivation without private key")
            data = b'\x00' + self.private_key + index.to_bytes(4, 'big')
        else:
            data = self.public_key + index.to_bytes(4, 'big')
            
        h = hmac.new(self.chain_code, data, hashlib.sha512).digest()
        
        child_chain_code = h[32:]
        
        if self.private_key:
            child_key_int = int.from_bytes(h[:32], 'big')
            parent_key_int = int.from_bytes(self.private_key, 'big')
            child_private_int = (parent_key_int + child_key_int) % N
            
            if child_private_int == 0:
                return self.derive(index + 1)
                
            child_private_key = child_private_int.to_bytes(32, 'big')
            child_public_key = PrivateKey(child_private_key).public_key(compressed=True).point
        else:
            raise NotImplementedError("Public key derivation not implemented")
            
        parent_fingerprint = hash160(self.public_key)[:4]
        
        return HDNode(
            private_key=child_private_key if self.private_key else None,
            public_key=child_public_key,
            chain_code=child_chain_code,
            depth=self.depth + 1,
            parent_fingerprint=parent_fingerprint,
            index=index,
            network=self.network
        )
        
    def derive_path(self, path: str) -> "HDNode":
        """Derive using BIP32 path like m/44'/0'/0'/0/0."""
        if not path or path in ('m', 'M'):
            return self
            
        if path.startswith('m/') or path.startswith('M/'):
            path = path[2:]
            
        node = self
        for component in path.split('/'):
            if not component:
                continue
                
            if component.endswith("'") or component.endswith("h"):
                index = int(component[:-1]) + 0x80000000
            else:
                index = int(component)
                
            node = node.derive(index)
            
        return node
        
    def get_private_key(self) -> PrivateKey:
        """Get private key object."""
        if self.private_key is None:
            raise ValueError("This is a public-only node")
        return PrivateKey(self.private_key)