// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "forge-std/Test.sol";

interface IERC20R {
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
}

interface IVaultR {
    function asset() external view returns (address);
    function totalAssets() external view returns (uint256);
    function totalSupply() external view returns (uint256);
    function convertToShares(uint256) external view returns (uint256);
    function convertToAssets(uint256) external view returns (uint256);
    function deposit(uint256, address) external returns (uint256);
    function redeem(uint256, address, address) external returns (uint256);
    function withdraw(uint256, address, address) external returns (uint256);
}

/// @notice Runs the rounding-drift attack against a REAL deployed vault:
///         repeatedly deposit and fully redeem, and total what the depositor
///         loses. Positive net loss for the depositor across many cycles is a
///         High-severity accounting bug - the pool quietly absorbs value that
///         belongs to whoever cycled.
///
/// Unlike the fixture binding this does not compare against a Python prediction.
/// A real vault's conversion functions cannot be reimplemented faithfully in
/// Python without reading its source, so the fork result IS the answer. The
/// fixture binding already proved the arithmetic; what this establishes is
/// whether any live vault is actually exposed.
///
/// Configure with TARGET_VAULT, TARGET_ASSET, CYCLES, FORK_BLOCK, RPC_URL.
contract RoundingDriftTest is Test {
    uint256 constant W = 1e18;
    address attacker = makeAddr("drifter");

    struct Drift {
        uint256 cycles;
        uint256 cyclesCompleted;
        uint256 paid;
        uint256 recovered;
        bool stopped;
        uint256 vaultAssetsBefore;
        uint256 vaultAssetsAfter;
    }

    /// Returns false when unconfigured so the suite stays green with no TARGET_VAULT
    /// set. A require() here would report as a failing test, which looks like a
    /// broken harness rather than a test that had nothing to probe.
    function _fork() internal returns (bool ok) {
        ok = vm.envOr("TARGET_VAULT", address(0)) != address(0);
        if (!ok) {
            emit log("TARGET_VAULT unset - skipping live-vault drift probes");
            return false;
        }
        require(vm.envOr("FORK_BLOCK", uint256(0)) > 0, "FORK_BLOCK must be a recent block");
        vm.createSelectFork(
            vm.envOr("RPC_URL", string("https://ethereum.publicnode.com")),
            vm.envOr("FORK_BLOCK", uint256(0))
        );
    }

    /// One cycle: deposit `amount`, redeem every share minted, and return how
    /// much came back. A vault with a minimum-deposit or withdrawal cap reverts
    /// mid-loop; that is a property of the target, so it is reported rather than
    /// allowed to abort the run.
    /// public, not internal: it is invoked via `this.` so a revert is catchable
    /// per-cycle instead of aborting the whole run. That makes it an EXTERNAL
    /// call, so `msg.sender` here is the test contract and any prank applied by
    /// the caller is already spent - every external call below is pranked
    /// individually. Without that, the approval belongs to the test contract and
    /// every cycle reverts with "ERC20: insufficient allowance", which is
    /// indistinguishable from a vault that refuses to be cycled.
    function cycle(address vault, address asset, uint256 amount) public returns (uint256 back) {
        uint256 balBefore = IERC20R(asset).balanceOf(attacker);
        vm.prank(attacker);
        uint256 minted = IVaultR(vault).deposit(amount, attacker);
        vm.prank(attacker);
        IVaultR(vault).redeem(minted, attacker, attacker);
        back = IERC20R(asset).balanceOf(attacker) - balBefore;
    }

    function _run(address vault, address asset, uint256 amount, uint256 cycles)
        internal
        returns (Drift memory d)
    {
        d.cycles = cycles;
        d.vaultAssetsBefore = IVaultR(vault).totalAssets();

        deal(asset, attacker, cycles * amount + 1000 * W);
        vm.prank(attacker);
        IERC20R(asset).approve(vault, type(uint256).max);

        for (uint256 i = 0; i < cycles; i++) {
            try this.cycle(vault, asset, amount) returns (uint256 back) {
                d.recovered += back;
                d.paid += amount;
                d.cyclesCompleted++;
            } catch {
                d.stopped = true;
                break;
            }
        }
        d.vaultAssetsAfter = IVaultR(vault).totalAssets();
    }

    function _emit(string memory tag, Drift memory d) internal {
        emit log_named_uint(string.concat("DRIFT_", tag, " cycles_done   "), d.cyclesCompleted);
        emit log_named_uint(string.concat("DRIFT_", tag, " paid          "), d.paid);
        emit log_named_uint(string.concat("DRIFT_", tag, " recovered     "), d.recovered);
        emit log_named_int(string.concat("DRIFT_", tag, " net           "), int256(d.recovered) - int256(d.paid));
        emit log_named_uint(string.concat("DRIFT_", tag, " vault_delta   "), d.vaultAssetsAfter - d.vaultAssetsBefore);
        emit log_named_uint(string.concat("DRIFT_", tag, " stopped       "), d.stopped ? 1 : 0);
    }

    /// A single large cycle, repeated. Large enough to clear any minimum-deposit
    /// rule that would otherwise stop the loop immediately.
    function test_drift_large() public {
        if (!_fork()) return;
        address vault = vm.envAddress("TARGET_VAULT");
        address asset = vm.envOr("TARGET_ASSET", address(0));
        if (asset == address(0)) asset = IVaultR(vault).asset();

        Drift memory d = _run(vault, asset, W, vm.envOr("CYCLES", uint256(20)));
        _emit("large", d);
    }

    /// Small repeated deposits: the regime where rounding asymmetry compounds.
    function test_drift_small() public {
        if (!_fork()) return;
        address vault = vm.envAddress("TARGET_VAULT");
        address asset = vm.envOr("TARGET_ASSET", address(0));
        if (asset == address(0)) asset = IVaultR(vault).asset();

        Drift memory d = _run(vault, asset, 1e6, vm.envOr("CYCLES", uint256(50)));
        _emit("small", d);
    }
}
