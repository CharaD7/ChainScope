import pytest
from core import deploy_source


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("1", 1),
        ("eth", 1),
        ("mainnet", 1),
        ("etherscan.io", 1),
        ("8453", 8453),
        ("base", 8453),
        ("basescan.org", 8453),
        ("42161", 42161),
        ("arbitrum", 42161),
        ("arb", 42161),
        ("arbiscan.io", 42161),
        ("999", 999),
        ("hyperevm", 999),
        ("hyperevmscan.io", 999),
        ("https://arbiscan.io", 42161),
    ],
)
def test_chain_id_normalization(raw, expected):
    assert deploy_source.chain_id(raw) == expected


def test_chain_id_unknown_raises():
    with pytest.raises(ValueError):
        deploy_source.chain_id("not-a-chain")
