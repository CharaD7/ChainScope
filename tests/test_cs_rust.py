"""Tests for cli/cs_rust.py - the Rust-native Critical detectors.

The behaviour worth protecting is the R1 discrimination. Hydration's stableswap
contains three sites of the form

    let r: DispatchResult = (|| { ensure!(x >= y, Err); Ok(()) })();
    debug_assert!(r.is_ok(), "... invariant");
    r

which are correct - the `ensure!` is enforced and the Result is returned - and
three of the same file's `debug_assert_issuance_in_sync`, which returned `()` and
had no other check and was a real defect until commit 50a55673c4. A grep cannot
tell those apart. These tests make sure the scanner can.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from cli.cs_rust import (
    RUST,
    scan,
    scan_debug_assert,
    scan_donation_shape,
    summary,
)


def _write(tmp_path: Path, name: str, body: str) -> Path:
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body)
    return p


# ----------------------------------------------------------------- R1: true positives


def test_unit_fn_with_only_debug_assert_is_flagged(tmp_path):
    _write(tmp_path, "lib.rs", """
        fn ensure_issuance_in_sync(pool_id: T::AssetId) {
            let tracked = ShareIssuance::<T>::get(pool_id);
            let total = T::Currency::total_issuance(pool_id);
            debug_assert_eq!(tracked, total, "virtual share issuance out of sync");
        }
    """)
    hits = scan_debug_assert(tmp_path)
    assert len(hits) == 1
    assert hits[0]["fn"] == "ensure_issuance_in_sync"
    assert hits[0]["severity_hint"] == "high"


def test_debug_assert_false_marked_low(tmp_path):
    """Unreachable arms are usually documentation, not an invariant."""
    _write(tmp_path, "lib.rs", """
        fn take_revenue(asset: Asset) {
            match asset {
                Asset { fun: Fungibility::Fungible(a) } => { let _ = a; }
                _ => {
                    debug_assert!(false, "Can only accept concrete fungible tokens");
                }
            }
        }
    """)
    hits = scan_debug_assert(tmp_path)
    assert len(hits) == 1
    assert hits[0]["severity_hint"] == "low"


# ------------------------------------------------------------- R1: false positives


def test_result_returning_fn_with_ensure_is_not_flagged(tmp_path):
    """The exact Hydration shape: ensure! enforced, debug_assert diagnostic."""
    _write(tmp_path, "lib.rs", """
        fn ensure_add_liquidity_invariant(pool_id: T::AssetId) -> DispatchResult {
            let r: DispatchResult = (|| {
                let d = calculate_d(&reserves)?;
                ensure!(final_r >= initial_r, Error::<T>::InvariantError);
                Ok(())
            })();
            debug_assert!(r.is_ok(), "Stableswap add_liquidity invariant: {r:?}");
            r
        }
    """)
    assert scan_debug_assert(tmp_path) == []


def test_question_mark_body_is_not_flagged(tmp_path):
    _write(tmp_path, "lib.rs", """
        fn check(a: u64) {
            let v = compute(a)?;
            debug_assert_eq!(v, expected);
        }
    """)
    assert scan_debug_assert(tmp_path) == []


def test_result_returning_fn_is_not_flagged(tmp_path):
    _write(tmp_path, "lib.rs", """
        fn ensure_x(id: u32) -> Result<(), Error> {
            debug_assert!(total(id) > 0, "issuance must be positive");
            Ok(())
        }
    """)
    assert scan_debug_assert(tmp_path) == []


# ------------------------------------------------------------------- exclusions


def test_test_and_target_dirs_are_skipped(tmp_path):
    _write(tmp_path, "src/lib.rs", """
        fn f() {
            debug_assert_eq!(1, 2, "real");
        }
    """)
    _write(tmp_path, "tests/it.rs", """
        fn g() {
            debug_assert_eq!(1, 2, "test only");
        }
    """)
    _write(tmp_path, "target/debug/x.rs", """
        fn h() {
            debug_assert_eq!(1, 2, "build artifact");
        }
    """)
    hits = scan_debug_assert(tmp_path)
    assert [Path(h["file"]).name for h in hits] == ["lib.rs"]


# ------------------------------------------------------------------------ R2


def test_r2_flags_raw_balance_share_math(tmp_path):
    _write(tmp_path, "lib.rs", """
        fn shares_for_deposit() -> Balance {
            let supply = total_supply();
            let assets = pool.free_balance();
            assets.checked_div(supply).unwrap_or_default()
        }
    """)
    hits = scan_donation_shape(tmp_path)
    assert hits and all(h["class_id"] == "R2" for h in hits)


def test_r2_suppressed_by_virtual_offset_in_file(tmp_path):
    """Royco-style VIRTUAL_SHARES/VIRTUAL_VALUE files are exonerated."""
    _write(tmp_path, "lib.rs", """
        const VIRTUAL_SHARES: u128 = 1;
        const VIRTUAL_VALUE: u128 = 1;
        fn shares_for_deposit() -> Balance {
            let supply = total_supply() + VIRTUAL_SHARES;
            let assets = pool.free_balance() + VIRTUAL_VALUE;
            assets.checked_div(supply).unwrap_or_default()
        }
    """)
    assert scan_donation_shape(tmp_path) == []


def test_r2_suppressed_by_first_depositor_guard(tmp_path):
    _write(tmp_path, "lib.rs", """
        fn shares_for_deposit() -> Balance {
            let supply = total_supply();
            if supply == 0 { return amount; }
            let assets = pool.free_balance();
            assets.checked_div(supply).unwrap_or_default()
        }
    """)
    assert scan_donation_shape(tmp_path) == []


# ------------------------------------------------------------------- driver


def test_scan_and_summary(tmp_path):
    _write(tmp_path, "lib.rs", """
        fn ensure_sync() {
            debug_assert_eq!(1, 2, "x");
        }
        fn shares() -> Balance {
            let s = total_supply();
            let a = pool.free_balance();
            a.checked_div(s).unwrap_or_default()
        }
    """)
    assert summary(tmp_path) == {"R1": 1, "R2": 1}
    ids = {h["class_id"] for h in scan(tmp_path)}
    assert ids == {"R1", "R2"}


def test_scan_survives_empty_tree(tmp_path):
    assert scan(tmp_path) == []
    assert summary(tmp_path) == {}


def test_scan_does_not_crash_on_broken_input(tmp_path):
    """A malformed tree must not abort the sweep."""
    (tmp_path / "weird").mkdir()
    (tmp_path / "weird" / "x.rs").write_bytes(b"\xff\xfe\x00broken rust \xc3\x28")
    scan(tmp_path)  # must not raise


def test_rust_extension_set_is_rs_only():
    assert RUST == {".rs"}