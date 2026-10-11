// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ISavingsVault} from "../interfaces/ISavingsVault.sol";
import {IThreatBulletin} from "../interfaces/IThreatBulletin.sol";
import {IPolicyWalletEvents} from "../interfaces/IPolicyWalletEvents.sol";
import {IPolicyWalletErrors} from "../interfaces/IPolicyWalletErrors.sol";
import {AuthorityBook, CapsuleBook, ItemBook, LedgerBook} from "./WalletTypes.sol";

/// @title Shared state of the PolicyWallet
/// @notice Inherited by every module of the wallet. All owner-relevant state is readable through view
///         functions so that an owner can migrate to a later version.
abstract contract WalletStorage is IPolicyWalletEvents, IPolicyWalletErrors {
    // ------------------------------------------------------------------ fixed at deployment

    /// @notice Contract version. Part of the EIP-712 domain.
    string public constant VERSION = "1";

    /// @notice The owner key. Holds authority over the mandate.
    address public immutable owner;
    /// @notice The only token the wallet pays in.
    IERC20 public immutable token;
    /// @notice The only place a sweep can send funds.
    ISavingsVault public immutable vault;
    /// @notice The capsule registry the wallet listens to.
    IThreatBulletin public immutable bulletin;

    // ------------------------------------------------------------------ state

    AuthorityBook internal _auth;
    LedgerBook internal _ledger;
    CapsuleBook internal _capsules;

    ItemBook internal _itemBook;

    // ------------------------------------------------------------------ counters

    /// @notice Next intent nonce the wallet accepts.
    uint256 public nonce;
    /// @notice Whether an intent hash has been submitted. A submitted intent never executes twice.
    mapping(bytes32 intentHash => bool) public intentUsed;
    /// @notice Token spent autonomously (L1 and schedule runs) on each day index.
    mapping(uint256 day => uint256) public spentOnDay;
    /// @notice Native token sent by fee top-ups on each day index.
    mapping(uint256 day => uint256) public toppedUpOnDay;

    // ------------------------------------------------------------------ allowance

    uint256 internal _allowanceAtT0; // in ALLOWANCE_UNIT per point
    uint64 internal _allowanceT0;

    // ------------------------------------------------------------------ modifiers

    modifier onlyOwner() {
        _requireOwner();
        _;
    }

    modifier onlyAgent() {
        _requireAgent();
        _;
    }

    modifier whenMandateSet() {
        _requireMandateSet();
        _;
    }

    constructor(
        address owner_,
        address agent_,
        address guardian_,
        IERC20 token_,
        ISavingsVault vault_,
        IThreatBulletin bulletin_
    ) {
        if (
            owner_ == address(0) || agent_ == address(0) || guardian_ == address(0) || address(token_) == address(0)
                || address(vault_) == address(0) || address(bulletin_) == address(0)
        ) revert ZeroAddress();
        if (vault_.asset() != address(token_)) revert VaultAssetMismatch();
        _requireDistinctKeys(owner_, agent_, guardian_);
        owner = owner_;
        _auth.agent = agent_;
        _auth.guardian = guardian_;
        token = token_;
        vault = vault_;
        bulletin = bulletin_;
    }

    function _requireOwner() internal view {
        if (msg.sender != owner) revert NotOwner();
    }

    function _requireAgent() internal view {
        if (msg.sender != _auth.agent || msg.sender == address(0)) revert NotAgent();
    }

    /// @dev The owner, agent and guardian keys must be three different addresses so that no single key both
    ///      proposes and attests, or both acts and authorises. A revoked agent (zero) is allowed.
    function _requireDistinctKeys(address ownerKey, address agentKey, address guardianKey) internal pure {
        if (agentKey == guardianKey || agentKey == ownerKey || guardianKey == ownerKey) revert KeysNotDistinct();
    }

    function _requireMandateSet() internal view {
        if (!_auth.mandateSet) revert MandateNotSet();
    }

    /// @dev Day index used by the daily limits.
    function _today() internal view returns (uint256) {
        return block.timestamp / 1 days;
    }
}
