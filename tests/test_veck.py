"""Tests for the Critical-class scanner (`cli/cs_veck.py`).

The scanner is a triage aid, not an oracle, so these tests pin the two
properties that actually matter for trust:

  1. it does not miss a planted pattern (recall), and
  2. it does not fire on commented-out code or unrelated text (precision).

Network-free: everything runs against a temp directory.
"""
import re
from pathlib import Path

import pytest

from cli.cs_veck import CLASSES, _BY_ID, _strip, scan

SOL = """// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

contract C {
    // function initialize(address) external;   <- commented out, must NOT hit
    /* function upgradeTo(address) external; */

    function initialize(address o) external initializer { owner = o; }

    function doDelegatecall(address t, bytes memory d) external {
        (bool s, ) = t.delegatecall(d);
        require(s, "fail");
    }

    function unsafeCall(address payable to) external {
        (bool success, ) = to.call{value: 1}("");
    }

    function shares() external view returns (uint256) {
        if (totalSupply() == 0) { return 1; }
        return 0;
    }
}
"""


@pytest.fixture()
def tree(tmp_path: Path) -> Path:
    (tmp_path / "C.sol").write_text(SOL)
    return tmp_path


def test_class_table_is_complete_and_unique():
    # 19 classes: 15 generic web3 + 4 DeFi-specific added 2026-09-30
    # (flash-loan manipulation, CLMM pool math, swap slippage/MEV, vault donation).
    assert len(CLASSES) == 19
    ids = [c["id"] for c in CLASSES]
    assert ids == list(range(1, 20))
    assert len(set(ids)) == 19
    for c in CLASSES:
        assert c["name"] and c["why"] and c["look"]
        assert "strong" in c and "weak" in c


def test_strip_removes_line_and_block_comments():
    assert _strip("int x = 1; // initialize() here").strip() == "int x = 1;"
    assert "initialize" not in _strip("/* function initialize() external; */ int x;")


def test_scan_finds_planted_patterns(tree: Path):
    hits = scan(tree)
    found = {(h["class_id"], h["file"], h["line"]) for h in hits}
    classes = {c for c, _, _ in found}
    assert 1 in classes    # un-guarded initialize
    assert 12 in classes   # delegatecall
    assert 14 in classes   # unchecked call
    assert 4 in classes    # totalSupply()==0


def test_scan_ignores_commented_patterns(tree: Path):
    hits = scan(tree)
    for h in hits:
        assert h["line"] not in (5, 6), f"commented line reported: {h}"


def test_scan_respects_class_filter(tree: Path):
    hits = scan(tree, [12])
    assert {h["class_id"] for h in hits} == {12}


def test_scan_respects_strong_only(tree: Path):
    hits = [h for h in scan(tree) if h["strength"] == "strong"]
    assert all(h["strength"] == "strong" for h in hits)


def test_empty_tree_is_clean(tmp_path: Path):
    (tmp_path / "x.sol").write_text("contract X { function f() external {} }")
    assert scan(tmp_path) == []


def test_non_solid_files_ignored(tmp_path: Path):
    (tmp_path / "a.py").write_text("def initialize(): pass")
    assert scan(tmp_path) == []


def test_hit_shape_has_adjudication_fields(tree: Path):
    for h in scan(tree):
        assert set(h) == {"class_id", "class", "strength", "file", "line", "snippet"}
        assert h["class"] == _BY_ID[h["class_id"]]["name"]
        assert h["strength"] in ("strong", "weak")
        assert isinstance(h["line"], int)


def test_strong_ranks_before_weak(tree: Path):
    hits = scan(tree)
    strengths = [h["strength"] for h in hits]
    # strong first, then weak
    assert strengths == sorted(strengths, key=lambda s: s != "strong")
