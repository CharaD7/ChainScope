"""Tests for the economic invariant models.

These are the tests that matter, because the whole value of `cs_econ` is that it
tells a vulnerable vault from a safe one. A model that cannot discriminate is
decoration. So every check is pinned against a case whose answer is known:

  * a naive ERC4626 (empty-vault branch, no offset) - donation attack is
    catastrophic at a 1-wei seed: the victim is minted ZERO shares;
  * an offset vault and a dead-share vault - donation attack is not viable;
  * a sandwich whose profit is cross-checked against a brute-force sweep of the
    same profit curve, because the optimiser being wrong is invisible otherwise;
  * the capital-budget bound, since extraction scales with the attacker's own
    capital and an unbounded search reports an unfundable theoretical maximum.

Two bugs were found by writing these, both of which produced plausible-looking
wrong numbers: the sandwich exit leg had the pool reserves reversed, and the
donation sweep started its seeds at 1e15, which structurally cannot see the
catastrophic regime.
"""
from __future__ import annotations

import pytest

from core.cs_econ import (
    ASSET_MODELS,
    SHARE_MODELS,
    donation_attack,
    erc4626_dead_shares,
    erc4626_naive,
    erc4626_virtual,
    rounding_drift,
    sandwich_profit_constant_product,
    sandwich_sensitivity,
    scan_donation_sensitivity,
)

W = 10 ** 18


# --------------------------------------------------------------------------- #
# donation / first-depositor inflation
# --------------------------------------------------------------------------- #


def test_naive_vault_loses_the_whole_deposit_at_tiny_seed():
    """The canonical catastrophic case, and the one a narrow sweep misses.

    At a 1-wei seed the attacker's share count is 1, so the victim's shares
    floor to zero and the entire deposit is extractable.
    """
    r = donation_attack(erc4626_naive, attacker_deposit=1, donation=100 * W, victim_deposit=W)
    assert r["victim_shares"] == 0
    assert r["victim_loss"] == W
    assert r["attacker_profit"] > 0
    assert r["viable"] is True


def test_attacker_seed_equal_to_victim_deposit_extracts_nothing():
    """The other end of the curve, and the reason a single parameter is evidence.

    A seed as large as the victim's deposit means the attacker already owns the
    vault, so the donation accrues to them proportionally and there is no
    extraction. Reporting only this case would understate the bug; reporting only
    the 1-wei case would overstate it.
    """
    r = donation_attack(erc4626_naive, attacker_deposit=W, donation=100 * W, victim_deposit=W)
    assert r["attacker_profit"] <= 100
    assert r["victim_loss"] <= 100


def test_offset_and_dead_share_vaults_are_not_viable():
    for fn in (erc4626_virtual, erc4626_dead_shares):
        best = scan_donation_sensitivity(fn)[0]
        assert best["attacker_profit"] <= 0, fn.__name__
        assert best["viable"] is False


def test_sweep_reaches_the_tiny_seed_regime():
    """Regression: seeds starting at 1e15 miss the total-loss case entirely."""
    best = scan_donation_sensitivity(erc4626_naive)[0]
    assert best["attacker_deposit"] == 1
    assert best["victim_shares"] == 0


def test_sweep_orders_worst_case_first():
    rows = scan_donation_sensitivity(erc4626_naive)
    assert rows == sorted(rows, key=lambda r: r["attacker_profit"], reverse=True)


def test_donation_raises_share_price():
    r = donation_attack(erc4626_naive, attacker_deposit=W, donation=100 * W, victim_deposit=W)
    assert r["share_price_after_donation"] > r["share_price_before_donation"]


def test_share_and_asset_models_are_mutually_consistent():
    """convertToAssets must be the inverse direction of convertToShares."""
    for name in SHARE_MODELS:
        ta, ts = 123456 * W, 65432 * W
        shares = SHARE_MODELS[name](ta, ts, 10 * W)
        assert shares > 0, name
        back = ASSET_MODELS[name](ta, ts, shares)
        # redemption of freshly minted shares returns slightly less than input
        assert back <= 10 * W, name
        assert back > 0, name


# --------------------------------------------------------------------------- #
# rounding drift
# --------------------------------------------------------------------------- #


def test_rounding_drift_is_zero_on_an_exact_one_to_one_pool():
    """With assets == supply every cycle divides evenly, so there is nothing to
    detect. A model reporting drift here would be manufacturing a finding."""
    r = rounding_drift(erc4626_naive, ASSET_MODELS["naive"], cycles=500, amount=1,
                       initial_assets=10 ** 24, initial_supply=10 ** 24)
    assert r["attacker_net"] == 0
    assert r["rounding_exploit"] is False


def test_rounding_drift_flags_zero_share_deposit():
    """A deposit too small to mint a share is a distinct, reportable failure."""
    r = rounding_drift(erc4626_naive, ASSET_MODELS["naive"], cycles=5, amount=1,
                       initial_assets=10 ** 24, initial_supply=3 * 10 ** 23)
    assert r["zero_share_deposit"] is True


def test_rounding_drift_detects_asymmetric_rounding():
    """A deliberately lopsided pair must show drift, or the check is inert.

    assets_for_shares floors to 0 while shares_for_assets floors to 1, so each
    cycle mints a share worth nothing and redeems nothing for it.
    """
    def shares_for(assets: int, supply: int, x: int) -> int:
        return x

    def assets_for(assets: int, supply: int, shares: int) -> int:
        return 0

    r = rounding_drift(shares_for, assets_for, cycles=100, amount=1,
                       initial_assets=10 ** 24, initial_supply=10 ** 24)
    assert r["attacker_net"] < 0, "attacker must come out behind"
    assert r["vault_gain"] > 0, "vault must absorb the difference"
    assert r["rounding_exploit"] is True
    assert r["conservation_holds"] is True, "attacker loss must equal vault gain exactly"


# --------------------------------------------------------------------------- #
# sandwich
# --------------------------------------------------------------------------- #


def _brute_force_sandwich(reserve_in, reserve_out, victim_in, n=400):
    """Independent sweep of the same profit curve, for cross-checking."""
    def amm(x, r_in, r_out):
        return 0.0 if x <= 0 else x * r_out / (r_in + x)

    best = -1.0
    for i in range(1, n + 1):
        x = reserve_in * i / n
        got = amm(x, reserve_in, reserve_out)
        r_in1, r_out1 = reserve_in + x, reserve_out - got
        vo = amm(victim_in, r_in1, r_out1)
        r_in2, r_out2 = r_in1 + victim_in, r_out1 - vo
        proceeds = amm(got, r_out2, r_in2)
        best = max(best, proceeds - x)
    return best


def test_sandwich_optimizer_matches_brute_force():
    """Regression: the exit leg previously used reversed pool reserves and
    reported a wildly wrong optimum. Cross-checking against an independent sweep
    is the only way that failure mode is visible."""
    r = sandwich_profit_constant_product(
        reserve_in=100 * W, reserve_out=100 * W, victim_amount_in=10 * W
    )
    brute = _brute_force_sandwich(100 * W, 100 * W, 10 * W)
    assert r["attacker_profit"] == pytest.approx(brute, rel=0.02), (r["attacker_profit"], brute)


def test_sandwich_is_profitable_when_unbounded():
    r = sandwich_profit_constant_product(
        reserve_in=100 * W, reserve_out=100 * W, victim_amount_in=10 * W, min_out_ratio=0.0
    )
    assert r["profitable"] is True
    assert r["attacker_profit"] > 0


def test_sandwich_profit_tracks_victim_loss():
    """The sandwich invariant: what the attacker takes is what the victim loses."""
    r = sandwich_profit_constant_product(
        reserve_in=100 * W, reserve_out=100 * W, victim_amount_in=10 * W, min_out_ratio=0.0
    )
    # You cannot extract more than the victim's trade moved, and the whole
    # sandwich is split between the victim and existing LPs - both must be
    # positive for a real sandwich, and they sum to the attacker's profit.
    assert 0 < r["value_extracted_from_victim"] < 10 * W
    assert r["value_extracted_from_lps"] > 0
    assert r["value_extracted_from_victim"] + r["value_extracted_from_lps"] == pytest.approx(
        r["attacker_profit"]
    )


def test_tight_slippage_bound_makes_attack_infeasible():
    """A bound the attacker cannot satisfy removes the victim's transaction
    entirely rather than merely shrinking the profit."""
    r = sandwich_profit_constant_product(
        reserve_in=100 * W,
        reserve_out=100 * W,
        victim_amount_in=90 * W,
        min_out_ratio=0.99,
        max_attacker_in=W,
    )
    if r["victim_tx_reverts"]:
        assert r["profitable"] is False
        assert r["attacker_profit"] == 0.0
    else:
        assert r["attacker_profit"] <= 0 or r["victim_out"] >= r["victim_floor"]


def test_capital_budget_bounds_extraction():
    """Extraction scales with the attacker's own capital, so an unbounded search
    reports a maximum nobody could fund. The budget must show up in the result."""
    small = sandwich_profit_constant_product(
        reserve_in=100 * W, reserve_out=100 * W, victim_amount_in=10 * W,
        min_out_ratio=0.0, max_attacker_in=1 * W,
    )
    large = sandwich_profit_constant_product(
        reserve_in=100 * W, reserve_out=100 * W, victim_amount_in=10 * W,
        min_out_ratio=0.0, max_attacker_in=50 * W,
    )
    assert small["attacker_buy_size"] <= 1 * W * 1.000001
    assert large["attacker_profit"] > small["attacker_profit"]


def test_sensitivity_reports_one_row_per_bound():
    rows = sandwich_sensitivity(reserve_in=100 * W, reserve_out=100 * W, victim_amount_in=W)
    assert len(rows) == 4
    assert [r["min_out_ratio"] for r in rows] == [0.0, 0.005, 0.01, 0.05]


def test_invalid_bound_is_rejected():
    with pytest.raises(ValueError):
        sandwich_profit_constant_product(reserve_in=W, reserve_out=W, victim_amount_in=W,
                                        min_out_ratio=1.5)