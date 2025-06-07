from fractal.crypto.keys import PrivateKey, PublicKey
from fractal.crypto.signature import sign_message, parse_der_signature, encode_der_signature
from fractal.constants import Network


def test_private_key_wif_roundtrip():
    key = PrivateKey.from_seed(b"seed")
    wif = key.wif(Network.TESTNET, compressed=True)
    imported, compressed, net = PrivateKey.from_wif(wif)
    assert compressed is True
    assert net == Network.TESTNET
    assert imported == key


def test_public_key_addresses():
    key = PrivateKey.from_seed(b"seed")
    pub = key.public_key(compressed=True)
    assert pub.p2pkh_address(Network.TESTNET).startswith("m") or pub.p2pkh_address(Network.TESTNET).startswith("n")
    assert pub.p2wpkh_address(Network.TESTNET).startswith("tb1q")
    assert pub.p2tr_address(Network.TESTNET).startswith("tb1p")


def test_der_signature_roundtrip():
    r = 1
    s = 2
    sig = encode_der_signature(r, s)
    parsed_r, parsed_s, sighash = parse_der_signature(sig)
    assert parsed_r == r
    assert parsed_s == s
    assert sighash is None

