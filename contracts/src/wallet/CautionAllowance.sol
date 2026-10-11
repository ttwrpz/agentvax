// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {WalletStorage} from "./WalletStorage.sol";

/// @title Caution allowance
/// @notice alpha(t) = min(A, alpha(t0) + A * (t - t0) / refillPeriod), kept in fixed point so that refill is
///         not lost to rounding. Halved once per newly synced applicable capsule, zeroed by `confirmAttack`.
/// @dev Rounding always goes down, which can only leave less allowance than the exact value.
abstract contract CautionAllowance is WalletStorage {
    /// @notice Fixed-point units per allowance point.
    uint256 public constant ALLOWANCE_UNIT = 1e6;

    /// @notice Remaining allowance now, in `ALLOWANCE_UNIT` per point.
    function allowance() public view returns (uint256) {
        if (!_auth.mandateSet) return 0;
        uint256 cap = uint256(_auth.mandate.allowanceMax) * ALLOWANCE_UNIT;
        uint256 refill = (cap * (block.timestamp - _allowanceT0)) / _auth.mandate.refillPeriod;
        uint256 value = _allowanceAtT0 + refill;
        return value < cap ? value : cap;
    }

    /// @notice Sets the allowance to zero. Owner only, immediate.
    function confirmAttack() external onlyOwner whenMandateSet {
        _setAllowance(0);
        emit AttackConfirmed();
    }

    /// @dev Records `value` as the allowance at the current time.
    function _setAllowance(uint256 value) internal {
        _allowanceAtT0 = value;
        _allowanceT0 = uint64(block.timestamp);
    }

    /// @dev Deducts `points` if the allowance covers them. Returns false, changing nothing, if it does not.
    function _trySpendAllowance(uint256 points) internal returns (bool) {
        uint256 cost = points * ALLOWANCE_UNIT;
        uint256 available = allowance();
        if (cost > available) return false;
        _setAllowance(available - cost);
        return true;
    }

    /// @dev Halves the allowance once for each of `times` newly seen applicable capsules.
    function _halveAllowance(uint256 times) internal {
        uint256 value = times >= 256 ? 0 : allowance() >> times;
        _setAllowance(value);
        emit AllowanceHalved(times, value);
    }
}
