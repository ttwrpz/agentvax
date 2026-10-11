// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {ISavingsVault} from "./interfaces/ISavingsVault.sol";
import {IPolicyWallet} from "./interfaces/IPolicyWallet.sol";

/// @title SavingsVault
/// @notice Holds swept funds with a separate balance for each depositing wallet. Only the owner of a wallet
///         can withdraw that wallet's balance, and only to themselves.
contract SavingsVault is ISavingsVault, ReentrancyGuard {
    using SafeERC20 for IERC20;

    /// @notice Contract version.
    string public constant VERSION = "1";

    /// @notice The token held by the vault.
    IERC20 public immutable token;

    /// @notice Balance held for each wallet.
    mapping(address wallet => uint256) public balanceOf;

    /// @notice A wallet deposited `amount`.
    event Deposited(address indexed wallet, uint256 amount);
    /// @notice The owner of `wallet` withdrew `amount` to themselves.
    event Withdrawn(address indexed wallet, address indexed owner, uint256 amount);

    error ZeroAddress();
    error ZeroAmount();
    error NotWalletOwner();
    error InsufficientBalance(uint256 available, uint256 requested);

    constructor(IERC20 asset_) {
        if (address(asset_) == address(0)) revert ZeroAddress();
        token = asset_;
    }

    /// @inheritdoc ISavingsVault
    function asset() external view returns (address) {
        return address(token);
    }

    /// @inheritdoc ISavingsVault
    /// @dev Credits `msg.sender`, so a deposit only ever adds to the caller's own balance.
    function deposit(uint256 amount) external nonReentrant {
        if (amount == 0) revert ZeroAmount();
        balanceOf[msg.sender] += amount;
        emit Deposited(msg.sender, amount);
        token.safeTransferFrom(msg.sender, address(this), amount);
    }

    /// @notice Withdraws `amount` of `wallet`'s balance to the caller, who must be the wallet's owner.
    /// @param wallet The PolicyWallet whose balance is debited.
    /// @param amount Token amount in base units.
    function withdraw(address wallet, uint256 amount) external nonReentrant {
        if (amount == 0) revert ZeroAmount();
        if (IPolicyWallet(wallet).owner() != msg.sender) revert NotWalletOwner();
        uint256 available = balanceOf[wallet];
        if (amount > available) revert InsufficientBalance(available, amount);
        balanceOf[wallet] = available - amount;
        emit Withdrawn(wallet, msg.sender, amount);
        token.safeTransfer(msg.sender, amount);
    }
}
