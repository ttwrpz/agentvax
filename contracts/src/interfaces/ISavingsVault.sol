// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Savings vault interface used by the PolicyWallet sweep
interface ISavingsVault {
    /// @notice The token the vault holds.
    function asset() external view returns (address);

    /// @notice Pulls `amount` of the asset from the caller and credits it to the caller's balance.
    function deposit(uint256 amount) external;

    /// @notice Balance held for `wallet`.
    function balanceOf(address wallet) external view returns (uint256);
}
