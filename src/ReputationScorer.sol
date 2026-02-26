// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {IAgentBondManagerOutcomes} from "./interfaces/IAgentBondManagerOutcomes.sol";
import {IReputationScorer} from "./interfaces/IReputationScorer.sol";

/// @title ReputationScorer
/// @author Vaultum
/// @custom:security-contact dev@vaultum.app
/// @notice Minimal on-chain scorer derived from AgentBondManager outcome counters.
///         Score 0 = 100% bond, score 10000 = 5% bond.
///         Deployed behind an ERC-1967 proxy (UUPS pattern).
contract ReputationScorer is IReputationScorer, Initializable, UUPSUpgradeable {
    uint256 public constant MAX_SCORE = 10_000;
    uint256 public constant MAX_BOND_BPS = 10_000;
    uint256 public constant MIN_BOND_BPS = 500;
    uint256 public constant SLASH_MULTIPLIER_BPS_BASE = 10_000;
    uint256 public constant MAX_SLASH_MULTIPLIER_BPS = 100_000; // 10x

    IAgentBondManagerOutcomes public BOND_MANAGER;
    address public owner;
    address public pendingOwner;
    uint256 public priorValue;
    uint256 public slashMultiplierBps;

    event BondManagerConfigured(address indexed bondManager);
    event ScoringParamsInitialized(uint256 priorValue, uint256 slashMultiplierBps);
    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    error NotOwner();
    error NotPendingOwner();
    error ZeroAddress();
    error AddressWithoutCode();
    error InvalidParameter();
    error BondManagerAlreadyConfigured();
    error BondManagerNotConfigured();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(uint256 priorValue_, uint256 slashMultiplierBps_) external initializer {
        if (priorValue_ == 0) revert InvalidParameter();
        if (
            slashMultiplierBps_ < SLASH_MULTIPLIER_BPS_BASE || slashMultiplierBps_ > MAX_SLASH_MULTIPLIER_BPS
        ) revert InvalidParameter();

        priorValue = priorValue_;
        slashMultiplierBps = slashMultiplierBps_;
        owner = msg.sender;
        emit ScoringParamsInitialized(priorValue_, slashMultiplierBps_);
        emit OwnershipTransferred(address(0), msg.sender);
    }

    function setBondManager(address bondManager_) external onlyOwner {
        if (bondManager_ == address(0)) revert ZeroAddress();
        if (bondManager_.code.length == 0) revert AddressWithoutCode();
        if (address(BOND_MANAGER) != address(0)) revert BondManagerAlreadyConfigured();
        BOND_MANAGER = IAgentBondManagerOutcomes(bondManager_);
        emit BondManagerConfigured(bondManager_);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        pendingOwner = newOwner;
        emit OwnershipTransferStarted(owner, newOwner);
    }

    function acceptOwnership() external {
        if (msg.sender != pendingOwner) revert NotPendingOwner();
        emit OwnershipTransferred(owner, msg.sender);
        owner = msg.sender;
        pendingOwner = address(0);
    }

    /// @inheritdoc IReputationScorer
    function getScore(uint256 agentId) public view returns (uint256 score, uint64 evidenceCount) {
        IAgentBondManagerOutcomes bondManager = BOND_MANAGER;
        if (address(bondManager) == address(0)) revert BondManagerNotConfigured();

        (
            uint256 successValue,
            uint256 slashValue,
            uint64 successCount,
            uint64 slashCount,
            ,
            
        ) = bondManager.getAgentOutcomeTotals(agentId);

        evidenceCount = successCount + slashCount;
        if (evidenceCount == 0) return (0, 0);

        uint256 slashPenalty = (slashValue * slashMultiplierBps) / SLASH_MULTIPLIER_BPS_BASE;
        uint256 denominator = successValue + slashPenalty + priorValue;
        if (denominator == 0) return (0, evidenceCount);

        score = (successValue * MAX_SCORE) / denominator;
        if (score > MAX_SCORE) {
            score = MAX_SCORE;
        }
    }

    /// @inheritdoc IReputationScorer
    function getRequiredBond(uint256 agentId, uint256 taskValue) public view returns (uint256) {
        (uint256 score,) = getScore(agentId);
        uint256 bondBps = MAX_BOND_BPS - (score * (MAX_BOND_BPS - MIN_BOND_BPS) / MAX_SCORE);
        return (taskValue * bondBps) / MAX_BOND_BPS;
    }

    function _authorizeUpgrade(address) internal override onlyOwner {}

    uint256[45] private __gap;
}
