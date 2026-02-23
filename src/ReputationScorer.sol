// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {IERC8004Reputation} from "./interfaces/IERC8004Reputation.sol";
import {IERC8004Validation} from "./interfaces/IERC8004Validation.sol";
import {IReputationScorer} from "./interfaces/IReputationScorer.sol";

/// @title ReputationScorer
/// @author Vaultum
/// @custom:security-contact dev@vaultum.app
/// @notice Default IReputationScorer for ERC-8004 agents. Combines Reputation and
///         Validation registry data with configurable weights. Trusted reviewer
///         lists provide Sybil filtering. Score 0 = 100% bond, score 10000 = 5% bond.
///         Deployed behind an ERC-1967 proxy (UUPS pattern).
contract ReputationScorer is IReputationScorer, Initializable, UUPSUpgradeable {
    uint256 public constant MAX_SCORE = 10_000;
    uint256 public constant MAX_BOND_BPS = 10_000;
    uint256 public constant MIN_BOND_BPS = 500;
    uint256 public constant MAX_TRUSTED_LIST_SIZE = 200;

    IERC8004Reputation public REPUTATION_REGISTRY;
    IERC8004Validation public VALIDATION_REGISTRY;

    address public owner;
    address public pendingOwner;
    string public reputationTag;
    uint256 public maxExpectedValue;
    uint256 public reputationWeight;
    uint256 public validationWeight;

    address[] private _trustedReviewers;
    mapping(address => bool) public isTrustedReviewer;

    address[] private _trustedValidators;
    mapping(address => bool) public isTrustedValidator;

    event TrustedReviewerAdded(address indexed reviewer);
    event TrustedReviewerRemoved(address indexed reviewer);
    event TrustedValidatorAdded(address indexed validator);
    event TrustedValidatorRemoved(address indexed validator);
    event WeightsUpdated(uint256 reputationWeight, uint256 validationWeight);
    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    error NotOwner();
    error NotPendingOwner();
    error ZeroAddress();
    error AlreadyTrusted();
    error NotTrusted();
    error ListFull();
    error InvalidWeights();
    error InvalidMaxValue();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(
        address reputationRegistry_,
        address validationRegistry_,
        string memory reputationTag_,
        uint256 maxExpectedValue_
    ) external initializer {
        if (reputationRegistry_ == address(0)) revert ZeroAddress();
        if (validationRegistry_ == address(0)) revert ZeroAddress();
        if (maxExpectedValue_ == 0) revert InvalidMaxValue();

        REPUTATION_REGISTRY = IERC8004Reputation(reputationRegistry_);
        VALIDATION_REGISTRY = IERC8004Validation(validationRegistry_);
        reputationTag = reputationTag_;
        maxExpectedValue = maxExpectedValue_;
        reputationWeight = 70;
        validationWeight = 30;
        owner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
    }

    function addTrustedReviewer(address reviewer) external onlyOwner {
        if (reviewer == address(0)) revert ZeroAddress();
        if (isTrustedReviewer[reviewer]) revert AlreadyTrusted();
        if (_trustedReviewers.length >= MAX_TRUSTED_LIST_SIZE) revert ListFull();
        _trustedReviewers.push(reviewer);
        isTrustedReviewer[reviewer] = true;
        emit TrustedReviewerAdded(reviewer);
    }

    function removeTrustedReviewer(address reviewer) external onlyOwner {
        if (!isTrustedReviewer[reviewer]) revert NotTrusted();
        isTrustedReviewer[reviewer] = false;
        _removeFromArray(_trustedReviewers, reviewer);
        emit TrustedReviewerRemoved(reviewer);
    }

    function addTrustedValidator(address validator) external onlyOwner {
        if (validator == address(0)) revert ZeroAddress();
        if (isTrustedValidator[validator]) revert AlreadyTrusted();
        if (_trustedValidators.length >= MAX_TRUSTED_LIST_SIZE) revert ListFull();
        _trustedValidators.push(validator);
        isTrustedValidator[validator] = true;
        emit TrustedValidatorAdded(validator);
    }

    function removeTrustedValidator(address validator) external onlyOwner {
        if (!isTrustedValidator[validator]) revert NotTrusted();
        isTrustedValidator[validator] = false;
        _removeFromArray(_trustedValidators, validator);
        emit TrustedValidatorRemoved(validator);
    }

    function setWeights(uint256 repWeight, uint256 valWeight) external onlyOwner {
        if (repWeight + valWeight == 0) revert InvalidWeights();
        if (repWeight > MAX_SCORE || valWeight > MAX_SCORE) revert InvalidWeights();
        reputationWeight = repWeight;
        validationWeight = valWeight;
        emit WeightsUpdated(repWeight, valWeight);
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

    // --- Views ---

    function trustedReviewers() external view returns (address[] memory) {
        return _trustedReviewers;
    }

    function trustedValidators() external view returns (address[] memory) {
        return _trustedValidators;
    }

    /// @inheritdoc IReputationScorer
    function getScore(uint256 agentId) public view returns (uint256 score, uint64 feedbackCount) {
        (uint256 repScore, uint64 repCount) = _reputationScore(agentId);
        (uint256 valScore, uint64 valCount) = _validationScore(agentId);

        feedbackCount = repCount + valCount;
        if (feedbackCount == 0) return (0, 0);

        if (repCount > 0 && valCount > 0) {
            score = (repScore * reputationWeight + valScore * validationWeight) / (reputationWeight + validationWeight);
        } else if (repCount > 0) {
            score = repScore;
        } else {
            score = valScore;
        }
    }

    /// @inheritdoc IReputationScorer
    function getRequiredBond(uint256 agentId, uint256 taskValue) public view returns (uint256) {
        (uint256 score,) = getScore(agentId);
        uint256 bondBps = MAX_BOND_BPS - (score * (MAX_BOND_BPS - MIN_BOND_BPS) / MAX_SCORE);
        return (taskValue * bondBps) / MAX_BOND_BPS;
    }

    // --- Internal ---

    function _authorizeUpgrade(address) internal override onlyOwner {}

    function _removeFromArray(address[] storage arr, address target) internal {
        for (uint256 i; i < arr.length; i++) {
            if (arr[i] == target) {
                arr[i] = arr[arr.length - 1];
                arr.pop();
                return;
            }
        }
    }

    function _reputationScore(uint256 agentId) internal view returns (uint256 score, uint64 count) {
        address[] memory reviewers = _reviewerList(agentId);
        if (reviewers.length == 0) return (0, 0);

        try REPUTATION_REGISTRY.getSummary(agentId, reviewers, reputationTag, "") returns (
            uint64 n, int128 avg, uint8 decimals
        ) {
            count = n;
            if (n == 0 || avg <= 0) return (0, n);

            uint256 raw = uint256(uint128(avg));
            if (decimals > 18) return (0, n);
            uint256 scale = 10 ** uint256(decimals);
            if (maxExpectedValue > type(uint256).max / scale) return (0, n);
            uint256 denom = maxExpectedValue * scale;
            score = (raw * MAX_SCORE) / denom;
            if (score > MAX_SCORE) score = MAX_SCORE;
        } catch {
            return (0, 0);
        }
    }

    function _validationScore(uint256 agentId) internal view returns (uint256 score, uint64 count) {
        if (_trustedValidators.length == 0) return (0, 0);
        try VALIDATION_REGISTRY.getSummary(agentId, _trustedValidators, "") returns (uint64 n, uint8 avg) {
            count = n;
            if (n == 0) return (0, 0);
            score = uint256(avg) * 100;
            if (score > MAX_SCORE) score = MAX_SCORE;
        } catch {
            return (0, 0);
        }
    }

    function _reviewerList(uint256) internal view returns (address[] memory) {
        return _trustedReviewers;
    }

    uint256[50] private __gap;
}
