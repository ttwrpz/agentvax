// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Capsule, CapsuleAction, Channels, Flags, Tiers} from "./lib/AgentVaxTypes.sol";
import {IThreatBulletin} from "./interfaces/IThreatBulletin.sol";

/// @title ThreatBulletin
/// @notice Shared registry of immunity capsules and anchored detector models.
/// @dev A capsule is fixed fields only: no text, no call data. It can only make a wallet more cautious.
///      A capsule from one observer is capped at a delay (L2). Owner approval (L3) needs `QUORUM` distinct
///      registered wallets, counting the issuer. Every capsule expires within `MAX_LIFETIME`.
///      There is no code path from this contract to any wallet's mandate.
contract ThreatBulletin is IThreatBulletin {
    /// @notice Contract version.
    string public constant VERSION = "1";
    /// @notice Longest lifetime a capsule may have.
    uint64 public constant MAX_LIFETIME = 7 days;
    /// @notice Capsules a registered wallet may publish per day (UTC day index).
    uint256 public constant MAX_PUBLISH_PER_DAY = 3;
    /// @notice Distinct wallets, counting the issuer, needed before a capsule can impose owner approval.
    uint8 public constant QUORUM = 2;

    uint8 private constant MAX_FAMILY = 5;

    /// @notice The only address that may register wallets. Fixed at deployment.
    address public immutable registrar;
    /// @notice The only address that may anchor detector models. Fixed at deployment.
    address public immutable aggregator;

    /// @notice Wallets allowed to publish and attest.
    mapping(address wallet => bool) public isRegistered;
    /// @notice Whether `wallet` has attested capsule `id` (the issuer counts as attested).
    mapping(uint256 id => mapping(address wallet => bool)) public hasAttested;
    /// @notice Capsules published by `wallet` on day index `day`.
    mapping(address wallet => mapping(uint256 day => uint256)) public publishedOnDay;
    /// @notice Model hash anchored for each detector version.
    mapping(uint32 version => bytes32) public modelHash;
    /// @notice Highest anchored detector version.
    uint32 public latestModelVersion;

    Capsule[] private _capsules;
    /// @dev Publication time of each capsule, same index as `_capsules`. Non-decreasing.
    uint64[] private _publishedAt;

    /// @notice `wallet` was registered or deregistered.
    event WalletRegistration(address indexed wallet, bool registered);
    /// @notice A capsule was published.
    event CapsulePublished(
        uint256 indexed id,
        address indexed issuer,
        uint8 family,
        uint8 channel,
        uint16 features,
        uint8 action,
        uint8 restriction,
        uint64 expiry,
        uint32 guardVersion
    );
    /// @notice `attester` attested capsule `id`, which now has `attestations` attestations.
    event CapsuleAttested(uint256 indexed id, address indexed attester, uint8 attestations);
    /// @notice A detector model was anchored.
    event ModelAnchored(uint32 indexed version, bytes32 modelHash);

    error ZeroAddress();
    error NotRegistrar();
    error NotAggregator();
    error NotRegistered(address wallet);
    error InvalidCapsule();
    error InvalidLifetime(uint64 lifetime);
    error PublishLimitReached(uint256 day);
    error UnknownCapsule(uint256 id);
    error CapsuleExpired(uint256 id);
    error AlreadyAttested(uint256 id, address wallet);
    error StaleModelVersion(uint32 version, uint32 latest);
    error ZeroModelHash();

    constructor(address registrar_, address aggregator_) {
        if (registrar_ == address(0) || aggregator_ == address(0)) revert ZeroAddress();
        registrar = registrar_;
        aggregator = aggregator_;
    }

    /// @notice Registers or deregisters `wallet` as a participant. Registrar only.
    function setRegistered(address wallet, bool registered) external {
        if (msg.sender != registrar) revert NotRegistrar();
        if (wallet == address(0)) revert ZeroAddress();
        isRegistered[wallet] = registered;
        emit WalletRegistration(wallet, registered);
    }

    /// @inheritdoc IThreatBulletin
    /// @dev Fields are validated: family 1..5, channel 0..4, features a non-empty subset of the eight flags,
    ///      action 1..4, restriction 2 or 3, lifetime 1..MAX_LIFETIME seconds.
    function publish(
        uint8 family,
        uint8 channel,
        uint16 features,
        uint8 action,
        uint8 restriction,
        uint64 lifetime,
        uint32 guardVersion
    ) external returns (uint256 id) {
        if (!isRegistered[msg.sender]) revert NotRegistered(msg.sender);
        if (
            family == 0 || family > MAX_FAMILY || channel >= Channels.COUNT || features == 0
                || (features & ~Flags.ALL) != 0 || action == uint8(CapsuleAction.NONE)
                || action > uint8(CapsuleAction.PAYEE_OR_MANDATE_CHANGE) || restriction < Tiers.L2
                || restriction > Tiers.L3
        ) revert InvalidCapsule();
        if (lifetime == 0 || lifetime > MAX_LIFETIME) revert InvalidLifetime(lifetime);

        uint256 day = block.timestamp / 1 days;
        uint256 published = publishedOnDay[msg.sender][day];
        if (published >= MAX_PUBLISH_PER_DAY) revert PublishLimitReached(day);
        publishedOnDay[msg.sender][day] = published + 1;

        uint64 expiry = uint64(block.timestamp) + lifetime;
        _capsules.push(
            Capsule({
                family: family,
                channel: channel,
                features: features,
                action: action,
                restriction: restriction,
                expiry: expiry,
                guardVersion: guardVersion,
                issuer: msg.sender,
                attestations: 1
            })
        );
        _publishedAt.push(uint64(block.timestamp));
        id = _capsules.length;
        hasAttested[id][msg.sender] = true;
        emit CapsulePublished(id, msg.sender, family, channel, features, action, restriction, expiry, guardVersion);
    }

    /// @inheritdoc IThreatBulletin
    function attest(uint256 id) external {
        if (!isRegistered[msg.sender]) revert NotRegistered(msg.sender);
        Capsule storage c = _capsule(id);
        if (c.expiry <= block.timestamp) revert CapsuleExpired(id);
        if (hasAttested[id][msg.sender]) revert AlreadyAttested(id, msg.sender);
        hasAttested[id][msg.sender] = true;
        if (c.attestations < type(uint8).max) c.attestations += 1;
        emit CapsuleAttested(id, msg.sender, c.attestations);
    }

    /// @notice Anchors detector model `version` with `hash`. Versions strictly increase. Aggregator only.
    function anchorModel(uint32 version, bytes32 hash) external {
        if (msg.sender != aggregator) revert NotAggregator();
        if (hash == bytes32(0)) revert ZeroModelHash();
        if (version <= latestModelVersion) revert StaleModelVersion(version, latestModelVersion);
        latestModelVersion = version;
        modelHash[version] = hash;
        emit ModelAnchored(version, hash);
    }

    /// @inheritdoc IThreatBulletin
    function capsuleCount() external view returns (uint256) {
        return _capsules.length;
    }

    /// @inheritdoc IThreatBulletin
    function getCapsule(uint256 id) external view returns (Capsule memory) {
        return _capsule(id);
    }

    /// @notice Restriction capsule `id` imposes now: capped at a delay (L2) until `QUORUM` wallets attest.
    function effectiveRestriction(uint256 id) public view returns (uint8) {
        Capsule storage c = _capsule(id);
        if (c.attestations >= QUORUM || c.restriction < Tiers.L3) return c.restriction;
        return Tiers.L2;
    }

    /// @inheritdoc IThreatBulletin
    function matchFields(uint256 id)
        external
        view
        returns (uint8 channel, uint16 features, uint8 action, uint8 restriction, uint64 expiry)
    {
        Capsule storage c = _capsule(id);
        return (c.channel, c.features, c.action, effectiveRestriction(id), c.expiry);
    }

    /// @inheritdoc IThreatBulletin
    function strength(uint256 id)
        external
        view
        returns (uint8 effectiveRestriction_, uint8 attestations, uint64 expiry)
    {
        Capsule storage c = _capsule(id);
        return (effectiveRestriction(id), c.attestations, c.expiry);
    }

    /// @inheritdoc IThreatBulletin
    /// @dev Binary search over publication times, so the cost grows with the logarithm of the capsule count.
    function firstPossiblyLive() external view returns (uint256) {
        uint256 lo = 0;
        uint256 hi = _publishedAt.length;
        while (lo < hi) {
            uint256 mid = (lo + hi) / 2;
            if (uint256(_publishedAt[mid]) + MAX_LIFETIME > block.timestamp) hi = mid;
            else lo = mid + 1;
        }
        return lo + 1;
    }

    function _capsule(uint256 id) private view returns (Capsule storage) {
        if (id == 0 || id > _capsules.length) revert UnknownCapsule(id);
        return _capsules[id - 1];
    }
}
