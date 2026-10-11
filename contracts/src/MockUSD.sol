// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// @title MockUSD
/// @notice A valueless 6-decimal test token. Anyone may mint. Deployed only on test networks.
contract MockUSD is ERC20 {
    constructor() ERC20("AgentVax Mock USD", "mUSD") {}

    /// @notice Token amounts use 6 decimals, like common stablecoins.
    function decimals() public pure override returns (uint8) {
        return 6;
    }

    /// @notice Mints `amount` to `to`. Open to anyone because the token has no value.
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}
