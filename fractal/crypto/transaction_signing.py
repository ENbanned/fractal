"""Transaction signing implementation for Fractal Bitcoin."""

import struct
from ..crypto.keys import PrivateKey
from ..types.transaction import RawTransaction, SigHashType, TransactionInput
from ..types.address import UTXO
from ..utils.encoding import encode_varint, int_to_bytes, double_sha256, serialize_script

def sign_transaction(
    tx: RawTransaction,
    private_keys: list[PrivateKey],
    utxos: list[UTXO]
) -> bytes:
    """Sign transaction and return serialized bytes."""
    
    # Simplified P2PKH signing for demonstration
    for i, (private_key, utxo) in enumerate(zip(private_keys, utxos)):
        public_key = private_key.public_key(compressed=True)
        
        # Create signature hash
        sig_hash = _create_sighash(tx, i, public_key.hash160())
        
        # Sign
        signature = private_key.sign(double_sha256(sig_hash))
        signature_with_type = signature + bytes([SigHashType.ALL])
        
        # Create scriptSig
        script_sig = serialize_script([signature_with_type, public_key.point])
        
        # Update input
        tx.inputs[i] = TransactionInput(
            outpoint=tx.inputs[i].outpoint,
            sequence=tx.inputs[i].sequence,
            script_sig=script_sig.hex(),
            witness=None
        )
        
    return _serialize_transaction(tx)

def _create_sighash(tx: RawTransaction, input_index: int, pubkey_hash: bytes) -> bytes:
    """Create signature hash for P2PKH."""
    s = bytearray()
    
    # Version
    s.extend(int_to_bytes(tx.version, 4, 'little'))
    
    # Inputs
    s.extend(encode_varint(len(tx.inputs)))
    for i, inp in enumerate(tx.inputs):
        s.extend(bytes.fromhex(inp.outpoint.txid)[::-1])
        s.extend(int_to_bytes(inp.outpoint.vout, 4, 'little'))
        
        if i == input_index:
            # P2PKH script
            script = serialize_script([0x76, 0xa9, pubkey_hash, 0x88, 0xac])
            s.extend(encode_varint(len(script)))
            s.extend(script)
        else:
            s.append(0)
            
        s.extend(int_to_bytes(inp.sequence, 4, 'little'))
    
    # Outputs
    s.extend(encode_varint(len(tx.outputs)))
    for out in tx.outputs:
        s.extend(int_to_bytes(out.value, 8, 'little'))
        script = bytes.fromhex(out.script_pubkey)
        s.extend(encode_varint(len(script)))
        s.extend(script)
    
    # Locktime and sighash type
    s.extend(int_to_bytes(tx.locktime, 4, 'little'))
    s.extend(int_to_bytes(SigHashType.ALL, 4, 'little'))
    
    return bytes(s)

def _serialize_transaction(tx: RawTransaction) -> bytes:
    """Serialize signed transaction."""
    s = bytearray()
    
    s.extend(int_to_bytes(tx.version, 4, 'little'))
    s.extend(encode_varint(len(tx.inputs)))
    
    for inp in tx.inputs:
        s.extend(bytes.fromhex(inp.outpoint.txid)[::-1])
        s.extend(int_to_bytes(inp.outpoint.vout, 4, 'little'))
        script = bytes.fromhex(inp.script_sig)
        s.extend(encode_varint(len(script)))
        s.extend(script)
        s.extend(int_to_bytes(inp.sequence, 4, 'little'))
    
    s.extend(encode_varint(len(tx.outputs)))
    for out in tx.outputs:
        s.extend(int_to_bytes(out.value, 8, 'little'))
        script = bytes.fromhex(out.script_pubkey)
        s.extend(encode_varint(len(script)))
        s.extend(script)
    
    s.extend(int_to_bytes(tx.locktime, 4, 'little'))
    
    return bytes(s)