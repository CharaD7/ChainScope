// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

/// @notice Ground-truth vaults for binding `core/cs_econ.py` to real execution.
///
/// These are deliberately minimal and deliberately one of each: a vault that is
/// known vulnerable and one that is known safe. Their only purpose is to answer
/// the question the Python models cannot answer about themselves - do the numbers
/// Python predicts match what the EVM actually does? A model that disagrees with
/// the EVM on a fixture will disagree on a real vault too, and would report a
/// confident wrong number.

interface IERC20Like {
    function totalSupply() external view returns (uint256);
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
}

/// @notice Minimal ERC4626 with the empty-vault branch and no virtual offset.
///         This is the vulnerable shape: the first depositor's shares become the
///         denominator for everyone, so a plain transfer to the vault inflates the
///         share price immediately.
contract NaiveVault {
    string public constant name = "NaiveVault";
    address public immutable asset;
    uint256 public totalAssets;
    uint256 public totalSupply;

    constructor(address asset_) {
        asset = asset_;
    }

    function convertToShares(uint256 assets) public view returns (uint256) {
        if (totalSupply == 0) {
            return assets;
        }
        return assets * totalSupply / totalAssets;
    }

    function convertToAssets(uint256 shares) public view returns (uint256) {
        if (totalSupply == 0) {
            return shares;
        }
        return shares * totalAssets / totalSupply;
    }

    function deposit(uint256 assets) external returns (uint256 shares) {
        shares = convertToShares(assets);
        require(shares > 0, "zero shares");
        totalAssets += assets;
        totalSupply += shares;
        IERC20Like(asset).transferFrom(msg.sender, address(this), assets);
        return shares;
    }

    function withdraw(uint256 shares) external returns (uint256 assets) {
        assets = convertToAssets(shares);
        require(assets > 0, "zero assets");
        totalAssets -= assets;
        totalSupply -= shares;
        IERC20Like(asset).transfer(msg.sender, assets);
        return assets;
    }

    /// @notice A donation is a plain transfer with no vault logic at all. This is
    ///         what makes the attack permissionless: no special role, no hook.
    function donate(uint256 assets) external {
        IERC20Like(asset).transferFrom(msg.sender, address(this), assets);
        totalAssets += assets;
    }
}

/// @notice Same interface, protected by `decimalsOffset` virtual shares and
///         liquidity, matching `erc4626_virtual` in cs_econ.py.
contract OffsetVault {
    string public constant name = "OffsetVault";
    uint8 public constant decimalsOffset = 3;
    uint256 private constant OFFSET = 10 ** 3;

    address public immutable asset;
    uint256 public totalAssets;
    uint256 public totalSupply;

    constructor(address asset_) {
        asset = asset_;
    }

    function _offset() internal pure returns (uint256) {
        return OFFSET;
    }

    function convertToShares(uint256 assets) public view returns (uint256) {
        uint256 denom = totalAssets + _offset();
        if (denom == 0) {
            return assets;
        }
        return assets * (totalSupply + _offset()) / denom;
    }

    function convertToAssets(uint256 shares) public view returns (uint256) {
        uint256 denom = totalSupply + _offset();
        if (denom == 0) {
            return shares;
        }
        return shares * (totalAssets + _offset()) / denom;
    }

    function deposit(uint256 assets) external returns (uint256 shares) {
        shares = convertToShares(assets);
        require(shares > 0, "zero shares");
        totalAssets += assets;
        totalSupply += shares;
        IERC20Like(asset).transferFrom(msg.sender, address(this), assets);
        return shares;
    }

    function withdraw(uint256 shares) external returns (uint256 assets) {
        assets = convertToAssets(shares);
        require(assets > 0, "zero assets");
        totalAssets -= assets;
        totalSupply -= shares;
        IERC20Like(asset).transfer(msg.sender, assets);
        return assets;
    }

    function donate(uint256 assets) external {
        IERC20Like(asset).transferFrom(msg.sender, address(this), assets);
        totalAssets += assets;
    }
}

contract MockToken {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function approve(address, uint256) external pure returns (bool) {
        return true;
    }
}