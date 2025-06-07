"""BIP39 mnemonic implementation for Fractal Bitcoin."""

import hashlib
import secrets
from typing import Optional

from ..exceptions import CryptoError
from ..constants import BIP39_WORDLIST as WORDLIST


def generate_mnemonic(strength: int = 128, wordlist: list[str] | None = None) -> str:
    """Generate BIP39 mnemonic phrase."""
    if strength not in (128, 160, 192, 224, 256):
        raise ValueError("Strength must be 128, 160, 192, 224, or 256")
        
    if wordlist is None:
        wordlist = WORDLIST
        
    # Generate entropy
    entropy = secrets.token_bytes(strength // 8)
    
    # Add checksum
    checksum_length = strength // 32
    checksum = hashlib.sha256(entropy).digest()
    checksum_bits = bin(checksum[0])[2:].zfill(8)[:checksum_length]
    
    # Convert to binary string
    entropy_bits = ''.join(format(byte, '08b') for byte in entropy)
    all_bits = entropy_bits + checksum_bits
    
    # Split into 11-bit chunks and convert to words
    words = []
    for i in range(0, len(all_bits), 11):
        chunk = all_bits[i:i+11]
        index = int(chunk, 2)
        words.append(wordlist[index])
        
    return ' '.join(words)

def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    """Convert mnemonic to seed using PBKDF2."""
    mnemonic = ' '.join(mnemonic.split())
    mnemonic_bytes = mnemonic.encode('utf-8')
    passphrase_bytes = ("mnemonic" + passphrase).encode('utf-8')
    
    return hashlib.pbkdf2_hmac(
        'sha512',
        mnemonic_bytes,
        passphrase_bytes,
        2048,
        dklen=64
    )