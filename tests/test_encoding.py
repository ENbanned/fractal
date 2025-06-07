import pytest
from fractal.utils.encoding import (
    hex_to_bytes, bytes_to_hex, encode_varint, decode_varint,
    encode_base58, decode_base58, encode_base58_check, decode_base58_check,
    encode_bech32, decode_bech32, encode_bech32m, decode_bech32m,
    encode_address, decode_address
)
from fractal.constants import Network


def test_hex_bytes_roundtrip():
    data = b"\x00\x01deadbeef"
    hex_str = bytes_to_hex(data, prefix=True)
    assert hex_str.startswith("0x")
    assert hex_to_bytes(hex_str) == data
    with pytest.raises(Exception):
        hex_to_bytes("zzzz")


def test_varint_roundtrip():
    for value in [0, 1, 252, 253, 65535, 65536, 2**32 + 1]:
        encoded = encode_varint(value)
        decoded, offset = decode_varint(encoded)
        assert decoded == value
        assert offset == len(encoded)


def test_base58_roundtrip():
    payload = b"hello world"
    encoded = encode_base58(payload)
    assert decode_base58(encoded) == payload


def test_base58check_roundtrip():
    payload = b"test payload"
    enc = encode_base58_check(payload)
    dec = decode_base58_check(enc)
    assert dec == payload
    with pytest.raises(Exception):
        decode_base58_check(enc[:-1] + "1")


def test_bech32_and_bech32m_roundtrip():
    hrp = "bc"
    witprog = b"\x01" * 20
    addr = encode_bech32(hrp, 0, witprog)
    assert decode_bech32(addr) == (hrp, 0, witprog)

    hrp_m = "bc"
    prog_m = b"\x02" * 32
    addr_m = encode_bech32m(hrp_m, 1, prog_m)
    assert decode_bech32m(addr_m) == (hrp_m, 1, prog_m)


def test_encode_decode_address():
    hash20 = bytes.fromhex("11" * 20)
    hash32 = bytes.fromhex("22" * 32)

    addr_p2pkh = encode_address("p2pkh", hash20, Network.MAINNET)
    t, h = decode_address(addr_p2pkh, Network.MAINNET)
    assert t == "p2pkh" and h == hash20

    addr_p2sh = encode_address("p2sh", hash20, Network.MAINNET)
    t, h = decode_address(addr_p2sh, Network.MAINNET)
    assert t == "p2sh" and h == hash20

    addr_p2wpkh = encode_address("p2wpkh", hash20, Network.MAINNET)
    t, h = decode_address(addr_p2wpkh, Network.MAINNET)
    assert t == "p2wpkh" and h == hash20

    addr_p2wsh = encode_address("p2wsh", hash32, Network.MAINNET)
    t, h = decode_address(addr_p2wsh, Network.MAINNET)
    assert t == "p2wsh" and h == hash32

    addr_p2tr = encode_address("p2tr", hash32, Network.MAINNET)
    t, h = decode_address(addr_p2tr, Network.MAINNET)
    assert t == "p2tr" and h == hash32

