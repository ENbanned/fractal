import pytest
from decimal import Decimal

from fractal.utils import validation as v
from fractal.constants import Network
from fractal.utils.encoding import encode_address


def test_address_validation():
    h = bytes.fromhex("11" * 20)
    addr = encode_address("p2wpkh", h, Network.MAINNET)
    assert v.is_valid_address(addr, Network.MAINNET)
    assert v.validate_address(addr, Network.MAINNET) == addr
    with pytest.raises(v.ValidationError):
        v.validate_address("invalid")


def test_txid_validation():
    txid = "a" * 64
    assert v.is_valid_txid(txid)
    assert v.validate_txid(txid) == txid
    with pytest.raises(v.ValidationError):
        v.validate_txid("xyz")


def test_amount_conversion():
    assert v.to_satoshi(1) == 1
    assert v.to_satoshi(Decimal("1.0")) == 100000000
    assert v.to_btc(100000000) == Decimal("1")
    assert v.is_dust_amount(100) is True
    assert v.is_dust_amount(1000) is False

