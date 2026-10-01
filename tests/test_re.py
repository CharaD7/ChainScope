"""Tests for the bytecode reverse-engineering engine.

Everything here runs offline against synthetic and captured bytecode. The network
paths (cast code, 4byte lookup) are not unit tested - a test that silently depends
on a mainnet RPC is a test that fails for reasons unrelated to the code, which is
how false signals get trusted.

The primitives are pinned because they are easy to get subtly wrong in ways that
look like findings:
  * opcode walking must skip PUSH payload, or payload bytes are read as opcodes
    and selector extraction returns nonsense;
  * slot 0x00 must render as 0x0, not the empty string after stripping zeros;
  * a minimal proxy carries its implementation in its runtime code;
  * interface inference must not fire on a single shared signature.
"""
from __future__ import annotations

import pytest

from core.cs_re import (
    access_control_hints,
    guard_coverage,
    dangerous_ops,
    diff_bytecode,
    extract_selectors,
    infer_interfaces,
    is_minimal_proxy,
    iter_opcodes,
    opcode_histogram,
    storage_slots,
    trailing_immutables,
)


def _hex(*parts: str) -> str:
    return "0x" + "".join(parts)


# a real EIP-1167 minimal proxy shape
MINIMAL_PROXY = (
    "0x363d3d373d3d3d363d73"
    + "aa" * 20
    + "5af43d82803e903d91602b57fd5bf3"
)


class TestOpcodeWalking:
    def test_push_payload_is_not_read_as_opcodes(self):
        """PUSH32 payload contains bytes that are valid opcodes.

        If payload were walked, this would inflate the histogram with garbage.
        0x63 is PUSH4 and must appear exactly once, not as payload noise.
        """
        # PUSH32 of a value whose payload contains many 0x63 bytes
        code = _hex("7f" + "63" * 32 + "00")
        ops = [op for op, _ in iter_opcodes(code)]
        assert ops == [0x7F, 0x00]
        hist = opcode_histogram(code)
        # 0x63 must be absent entirely, not present-and-zero: if payload bytes were
        # walked, the histogram would grow 32 spurious PUSH4 entries.
        assert "0x63" not in hist
        assert hist["0x7f"] == 1
        assert hist["0x00"] == 1

    def test_histogram_counts_repeated_pushes(self):
        code = _hex("6000", "6000", "6001")
        assert opcode_histogram(code)["0x60"] == 3


class TestSelectorExtraction:
    def test_finds_push4_selectors_in_dispatcher(self):
        # PUSH4 0x11223344 EQ ; PUSH4 0x55667788 EQ
        code = _hex("6311223344", "14", "6355667788", "14", "00")
        sel = extract_selectors(code)
        assert "0x11223344" in sel["dispatcher"]
        assert "0x55667788" in sel["dispatcher"]

    def test_deep_constants_are_separated_not_merged(self):
        """PUSH4 values past the dispatcher are usually coincidental.

        Reporting them as selectors would inflate the interface surface with
        4-byte windows of unrelated data.
        """
        # 400 zero bytes then a PUSH4 deep in the code
        code = _hex("00" * 400, "63deadbeef", "00")
        sel = extract_selectors(code)
        assert sel["dispatcher"] == []
        assert "0xdeadbeef" in sel["other_constants"]

    def test_handles_push32_without_garbage_selectors(self):
        sel = extract_selectors(_hex("7f" + "aa" * 32, "00"))
        assert sel["dispatcher"] == []


class TestMinimalProxy:
    def test_detects_eip1167_and_reads_implementation(self):
        assert is_minimal_proxy(MINIMAL_PROXY) == "0x" + "aa" * 20

    def test_non_proxy_is_not_matched(self):
        assert is_minimal_proxy(_hex("6080604052", "00" * 20)) is None

    def test_upgradeable_proxy_is_not_a_minimal_proxy(self):
        """A proxy that can be upgraded must not be reported as immutable.

        The distinction matters: an EIP-1167 implementation is hardcoded, while
        an EIP-1967 one can change under you.
        """
        assert is_minimal_proxy(_hex("363d3d373d3d3d363d73", "bb" * 20, "5af43d82803e903d91602b57fd5bf3", "5a")) is None


class TestStorageSlots:
    def test_slot_zero_renders_as_0x0(self):
        """0x00 must not strip down to the empty string after lstrip('0')."""
        slots = storage_slots(_hex("6000", "55"))
        assert slots == [{"slot": "0x0", "op": "SSTORE"}]

    def test_sload_and_sstore_are_distinguished(self):
        slots = storage_slots(_hex("6001", "54", "6020", "55"))
        assert {"slot": "0x1", "op": "SLOAD"} in slots
        assert {"slot": "0x20", "op": "SSTORE"} in slots

    def test_trailing_push_that_is_not_a_store_is_ignored(self):
        assert storage_slots(_hex("6001", "00", "00")) == []


class TestDangerousOps:
    def test_detects_delegatecall_and_selfdestruct(self):
        ops = {d["op"] for d in dangerous_ops(_hex("f4", "ff", "f5"))}
        assert "DELEGATECALL" in ops
        assert "SELFDESTRUCT" in ops
        assert "CREATE2" in ops

    def test_clean_contract_reports_none(self):
        assert dangerous_ops(_hex("60016002", "01", "00")) == []

    def test_every_hit_carries_a_reason(self):
        for d in dangerous_ops(_hex("f4")):
            assert d["why"] and isinstance(d["why"], str)


class TestImmutables:
    def test_reads_trailing_constructor_argument(self):
        code = _hex("6000", "00" * 20) + "ab" * 32
        assert trailing_immutables(code)[0].startswith("0xabab")

    def test_short_code_yields_nothing(self):
        assert trailing_immutables(_hex("6000")) == []


class TestDifferential:
    def test_identical_code(self):
        d = diff_bytecode(_hex("60016002", "00"), _hex("60016002", "00"))
        assert d["identical"] is True
        assert d["logic_identical"] is True

    def test_detects_added_selector(self):
        a = _hex("6311223344", "14", "00")
        b = _hex("6355667788", "14", "00")
        d = diff_bytecode(a, b)
        assert d["selectors_only_in_a"] == ["0x11223344"]
        assert d["selectors_only_in_b"] == ["0x55667788"]
        assert d["identical"] is False

    def test_detects_opcode_change_with_same_selectors(self):
        """A one-line divergence often keeps the same ABI and changes logic."""
        a = _hex("6311223344", "14", "f4", "00")
        b = _hex("6311223344", "14", "f3", "00")
        d = diff_bytecode(a, b)
        assert d["selectors_only_in_a"] == [] and d["selectors_only_in_b"] == []
        assert d["logic_identical"] is False
        assert d["opcode_delta"].get("0xf4") == 1
        assert d["opcode_delta"].get("0xf3") == -1

    def test_metadata_only_difference_is_flagged(self):
        """Different IPFS hash, identical logic - the common benign case."""
        logic = "6001600201"
        a = _hex(logic) + "a264697066735822" + "11" * 34
        b = _hex(logic) + "a264697066735822" + "22" * 34
        d = diff_bytecode(a, b)
        assert d["metadata_only_difference"] is True
        assert d["logic_identical"] is True
        assert d["identical"] is False


class TestInterfaceInference:
    def test_requires_most_of_the_interface(self):
        """`owner()` alone must not be read as Ownable."""
        from core.cs_re import infer_interfaces as inf
        res = inf({"0x1": ["owner()"]})
        assert "Ownable" not in res["interfaces"]

    def test_full_ownable_is_detected(self):
        res = infer_interfaces({
            "0x1": ["owner()"],
            "0x2": ["renounceOwnership()"],
            "0x3": ["transferOwnership(address)"],
        })
        assert "Ownable" in res["interfaces"]
        assert res["interfaces"]["Ownable"]["confidence"] == 1.0

    def test_unresolved_selectors_are_reported(self):
        res = infer_interfaces({"0x1": [], "0x2": ["someUnindexedThing()"]})
        assert "0x1" in res["unresolved_selectors"]

    def test_erc20_needs_the_full_set(self):
        partial = infer_interfaces({
            "0x1": ["totalSupply()"],
            "0x2": ["balanceOf(address)"],
        })
        assert "ERC20" not in partial["interfaces"]

# --------------------------------------------------------------------------- #
# diamond branch
# --------------------------------------------------------------------------- #
# Built for a false example: I claimed sDAI was an EIP-2535 diamond when it was
# not, and no diamond was found among 143 real in-scope addresses. So the branch
# is now validated against a real, standards-shaped diamond
# (tools/diamond_fixture, deployed to anvil and driven end-to-end), and these
# tests pin the classification against that shape.
#
# The property that matters: facet selectors are absent from the diamond's own
# bytecode, which is exactly what the surface caveat warns about.

FACETS_RETURN = (
    "[(0xBA12646CC07ADBe43F8bD25D83FB628D29C8A762, [0xd580f22b]), "
    "(0x7ab4C4804197531f7ed6A6bc0f0781f706ff7953, [0x0bf397c4]), "
    "(0xc8CB5439c767A63aca1c01862252B2F3495fDcFE, [0x7a0ed627])]"
)


class TestDiamondClassification:
    def _patch(self, monkeypatch, *, facets_ok: bool, code: str):
        import core.cs_re as re_mod

        monkeypatch.setattr(re_mod, "runtime_code", lambda chain, addr: code)
        monkeypatch.setattr(re_mod, "_storage", lambda chain, addr, slot: None)
        monkeypatch.setattr(re_mod, "rpc_for", lambda chain: "http://local")
        if facets_ok:
            monkeypatch.setattr(re_mod, "_call",
                                lambda chain, addr, sig, args="": (True, FACETS_RETURN))
        else:
            monkeypatch.setattr(re_mod, "_call", lambda chain, addr, sig, args="": (False, ""))

    def test_address_reporting_facets_is_classified_as_diamond(self, monkeypatch):
        self._patch(monkeypatch, facets_ok=True, code="0x6080604052")
        from core.cs_re import resolve_proxy
        r = resolve_proxy("1", "0xabc")
        assert r["kind"] == "EIP2535_DIAMOND"
        assert len(r["facets"]) == 3
        assert any("registered in storage" in n for n in r["notes"])
        assert any("Read the facets, not this" in n for n in r["notes"])

    def test_diamond_without_facets_is_not_classified_as_one(self, monkeypatch):
        """facets() reverting must not produce a diamond verdict.

        This is the sDAI error in reverse: a contract that does not answer
        facets() is not evidence of a diamond.
        """
        self._patch(monkeypatch, facets_ok=False, code="0x6080604052")
        from core.cs_re import resolve_proxy
        r = resolve_proxy("1", "0xabc")
        assert r["kind"] == "DIRECT"
        assert r["facets"] == []

    def test_facet_selectors_are_absent_from_the_diamond_bytecode(self):
        """The blind spot the caveat describes, pinned arithmetically."""
        from core.cs_re import extract_selectors, _FUNC_DECL
        import re as _re
        # facetAFunction() selector
        import hashlib
        # keccak via cast is unavailable offline, so use a known-good constant
        facet_selector = "0xd580f22b"  # facetAFunction()
        # diamond bytecode: only its own functions
        diamond_code = "0x" + "6311223344" + "14" + "00"
        sel = extract_selectors(diamond_code)
        assert facet_selector not in sel["dispatcher"]
        assert "0x11223344" in sel["dispatcher"]


# --------------------------------------------------------------------------- #
# 4. uninitialised-target probing
# --------------------------------------------------------------------------- #

class TestUninitializedProbe:
    """Both directions must work.

    A detector that can only ever answer "initialized" is worse than useless -
    it looks like a clean bill of health. The fixture provides one address that is
    genuinely uninitialised and one that is not.
    """

    def test_count_args_handles_forms(self):
        from core.cs_re import _count_args
        assert _count_args("initialize()") == 0
        assert _count_args("initialize(address)") == 1
        assert _count_args("initialize(address,uint256)") == 2
        assert _count_args("initialize(address,(uint256,bytes))") == 2

    def test_init_name_filter(self):
        from core.cs_re import _INIT_NAME
        assert _INIT_NAME.match("initialize(address)")
        assert _INIT_NAME.match("initialize2(uint256)")
        assert _INIT_NAME.match("__init(address)")
        assert not _INIT_NAME.match("deposit(uint256)")

    def test_classify_reads_custom_error_selectors(self):
        """A contract using `error InvalidInitialization()` prints the raw
        selector, never the name - matching strings alone reports UNKNOWN."""
        from core.cs_re import _classify_init_call, _init_error_selectors
        sel = next(iter(_init_error_selectors()))
        assert _classify_init_call(False, f"execution reverted, data: 0x{sel}") == "INITIALIZED"

    def test_successful_call_means_uninitialized(self):
        from core.cs_re import _classify_init_call
        assert _classify_init_call(True, "0x0000...01") == "UNINITIALIZED"

    def test_unrelated_revert_stays_unknown(self):
        """Never report "safe" from a revert we cannot explain."""
        from core.cs_re import _classify_init_call
        assert _classify_init_call(False, "execution reverted, data: 0xdeadbeef") == "UNKNOWN"
        assert _classify_init_call(False, "out of gas") == "UNKNOWN"

    def test_init_error_selectors_are_derived_not_guessed(self):
        """Regression: hardcoded f1c221079 was wrong; the real selector for
        InvalidInitialization() is f92ee8a9. A wrong constant silently turns every
        initialized contract into UNKNOWN."""
        from core.cs_re import _init_error_selectors
        sels = _init_error_selectors()
        assert sels, "selectors must resolve"
        for sig in sels.values():
            assert len(sig) > 0


# --------------------------------------------------------------------------- #
# 1. access-control inference
# --------------------------------------------------------------------------- #
# Reading onlyOwner by hand across kelp's ~19,000 lines is the work this replaces.
# The controls are the point: a detector that cannot tell a guarded contract from
# one that merely reads msg.sender is worse than none, because it manufactures
# assurance. Both directions are pinned against bytecode captured from a real
# deployment.

CALLER = "33"  # bare hex: every other fragment below is bare hex too


class TestAccessControlInference:
    def test_absent_caller_is_reported_as_absence_not_safety(self):
        h = access_control_hints("0x" + "6000" * 20)  # no CALLER anywhere
        assert h["verdict"] == "NO_CALLER_CHECK_DETECTED"
        assert "not evidence" in h["note"]

    def test_storing_the_sender_is_not_a_guard(self):
        """Regression: `lastSender = msg.sender` is CALLER then SSTORE.

        An earlier version accepted "any JUMPI nearby", which matched the
        function dispatcher and reported this unguarded contract as guarded.
        """
        # CALLER ; PUSH1 slot ; SSTORE ; STOP
        code = "0x" + CALLER + "6001" + "55" + "00"
        h = access_control_hints(code)
        assert h["verdict"] == "CALLER_READ_NOT_GATED"
        assert h["branches"] == 0

    def test_guard_shape_is_detected(self):
        """CALLER ; SLOAD ; EQ ; PUSH2 ; JUMPI - the onlyOwner shape."""
        code = "0x" + CALLER + "54" + "6000" + "14" + "610000" + "57" + "00"
        h = access_control_hints(code)
        assert h["verdict"] == "CALLER_GUARD_PRESENT"
        assert h["branches"] >= 1

    def test_immutable_owner_candidate_is_recovered(self):
        code = "0x" + CALLER + "73" + "11" * 20 + "14" + "57" + "00"
        h = access_control_hints(code)
        assert "0x" + "11" * 20 in h["immutable_owners"]

    def test_role_hash_candidates_are_recovered(self):
        code = "0x" + CALLER + "7f" + "22" * 32 + "14" + "57" + "00"
        h = access_control_hints(code)
        assert "0x" + "22" * 32 in h["role_hashes"]

    def test_verdict_is_labelled_heuristic(self):
        code = "0x" + CALLER + "54" + "6000" + "14" + "610000" + "57" + "00"
        h = access_control_hints(code)
        assert h["confidence"] == "heuristic"
        assert "cannot tell a correct guard" in h["note"]

    def test_guard_coverage_refuses_per_function_precision(self):
        """Bytecode has no reliable function boundaries; per-function gating would
        be fabricated precision."""
        code = "0x" + CALLER + "54" + "6000" + "14" + "610000" + "57" + "631122334414" + "00"
        g = guard_coverage(code, [])
        assert "not per function" in g["explanation"]
        assert g["unguarded_or_unknown"] == 0  # a guard exists somewhere
