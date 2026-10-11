// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Minimal view of a PolicyWallet used by other AgentVax contracts
interface IPolicyWallet {
    /// @notice The owner key of the wallet.
    function owner() external view returns (address);
}
