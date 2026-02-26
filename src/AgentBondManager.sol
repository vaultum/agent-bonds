// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IERC8004Identity} from "./interfaces/IERC8004Identity.sol";
import {IERC8004Validation} from "./interfaces/IERC8004Validation.sol";
import {IReputationScorer} from "./interfaces/IReputationScorer.sol";

interface IPermit2 {
    struct PermitDetails {
        address token;
        uint160 amount;
        uint48 expiration;
        uint48 nonce;
    }

    struct PermitSingle {
        PermitDetails details;
        address spender;
        uint256 sigDeadline;
    }

    function permit(address owner, PermitSingle calldata permitSingle, bytes calldata signature) external;

    function transferFrom(address from, address to, uint160 amount, address token) external;
}

interface IEIP3009 {
    function transferWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external;
}

/// @title AgentBondManager
/// @author Vaultum
/// @custom:security-contact dev@vaultum.app
/// @notice Reputation-collateralized bonding for ERC-8004 agents (UUPS).
contract AgentBondManager is Initializable, UUPSUpgradeable {
    using SafeERC20 for IERC20;

    enum TaskStatus {
        None,
        Active,
        Completed,
        Disputed,
        Resolved,
        Slashed,
        Expired,
        Refunded
    }

    enum ValidationFinalityPolicy {
        ResponseHashRequired,
        AnyStatusRecord
    }

    enum StatusLookupFailurePolicy {
        CanonicalUnknownAsMissing,
        AlwaysMissing,
        AlwaysUnavailable
    }

    enum ValidatorSelectionPolicy {
        DesignatedOnly,
        DesignatedAndAllowlisted
    }

    enum AgentOutcomeKind {
        Success,
        Slashed,
        Neutral
    }

    struct Bond {
        uint256 amount;
        uint256 locked;
    }

    struct Task {
        uint256 agentId;
        address client;
        uint8 snapshotMinPassingScore;
        TaskStatus status;
        uint256 payment;
        bytes32 taskHash;
        uint256 bondLocked;
        uint48 deadline;
        uint48 disputedAt;
        uint16 snapshotSlashBps;
        uint40 snapshotDisputePeriod;
        uint40 snapshotRegistryGracePeriod;
        address agentRecipient;
        address clientRecipient;
        uint8 snapshotValidationFinalityPolicy;
        uint8 snapshotStatusLookupFailurePolicy;
        address committedValidator;
    }

    struct AgentOutcomes {
        uint256 successValue;
        uint256 slashValue;
        uint256 slashAmount;
        uint64 successCount;
        uint64 slashCount;
        uint64 neutralCount;
    }

    struct CreateTaskInput {
        uint256 agentId;
        bytes32 taskHash;
        uint256 deadline;
        uint256 paymentAmount;
        address signer;
        address agentRecipient;
        address clientRecipient;
        address committedValidator;
        uint256 validatorFeeAmount;
    }

    uint256 public constant MIN_DISPUTE_PERIOD = 1 hours;
    uint256 public constant MAX_DISPUTE_PERIOD = 90 days;
    address public constant PERMIT2_DEFAULT = 0x000000000022D473030F116dDEE9F6B43aC78BA3;

    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant NAME_HASH = keccak256("AgentBondManager");
    bytes32 private constant VERSION_HASH = keccak256("1");
    uint256 private constant MAX_KNOWNNESS_SCAN = 512;
    uint256 private constant DEFAULT_MAX_AGENT_TASK_HISTORY = 4096;
    uint256 private constant MAX_MIN_VALIDATOR_FEE_TOKENS = 1_000_000;
    uint8 private constant REQUEST_KNOWN_STATE_UNSET = 0;
    uint8 private constant REQUEST_KNOWN_STATE_MISSING = 1;
    uint8 private constant REQUEST_KNOWN_STATE_KNOWN = 2;
    uint8 private constant REQUEST_KNOWN_STATE_UNSUPPORTED = 3;
    bytes32 private constant TASK_PERMIT_TYPEHASH = keccak256(
        "TaskPermit(uint256 agentId,address client,address agentRecipient,address clientRecipient,address committedValidator,uint256 validatorFeeAmount,uint256 paymentAmount,uint256 deadline,bytes32 taskHash,uint256 nonce)"
    );
    bytes32 private constant VALIDATOR_COMMITMENT_TYPEHASH = keccak256(
        "ValidatorCommitment(uint256 agentId,address client,bytes32 taskHash,uint256 feeAmount,uint256 deadline,uint256 nonce)"
    );

    IERC8004Identity public IDENTITY_REGISTRY;
    IERC8004Validation public VALIDATION_REGISTRY;
    IReputationScorer public SCORER;
    IERC20 public settlementToken;
    address public permit2;

    address public owner;
    address public pendingOwner;
    uint256 public disputePeriod;
    uint8 public minPassingScore;
    uint256 public slashBps;
    uint256 public minValidatorFee;
    uint256 public nextTaskId;

    mapping(uint256 agentId => Bond) public bonds;
    mapping(uint256 taskId => Task) public tasks;
    mapping(uint256 agentId => uint256) public agentNonces;
    mapping(address validator => uint256) public validatorNonces;
    mapping(address account => uint256) public claimable;
    mapping(uint256 taskId => uint256) public validatorFeeCommitment;
    mapping(uint256 taskId => uint256) public validatorFeeEscrow;
    mapping(uint256 taskId => uint256) public registryFailureSince;
    mapping(uint256 agentId => AgentOutcomes) private _agentOutcomes;
    uint256 public registryFailureGracePeriod;
    ValidationFinalityPolicy public validationFinalityPolicy;
    StatusLookupFailurePolicy public statusLookupFailurePolicy;
    // Dispute request knownness cache:
    // 0=unset, 1=request missing, 2=request known, 3=knownness lookup unsupported.
    mapping(uint256 taskId => uint8) private _disputeRequestKnownState;
    ValidatorSelectionPolicy public validatorSelectionPolicy;
    mapping(address validator => bool) public trustedValidators;
    uint256 public maxAgentTaskHistory;
    mapping(uint256 agentId => mapping(uint256 index => uint256 taskId)) private _agentTaskHistory;
    mapping(uint256 agentId => uint256) private _agentTaskHistoryStart;
    mapping(uint256 agentId => uint256) private _agentTaskHistoryCount;

    event BondDeposited(uint256 indexed agentId, address indexed depositor, uint256 amount);
    event BondWithdrawn(uint256 indexed agentId, address indexed recipient, uint256 amount);
    event TaskCreated(
        uint256 indexed taskId,
        uint256 indexed agentId,
        address indexed client,
        uint256 payment,
        bytes32 taskHash,
        bytes32 requestHash,
        uint256 bondLocked
    );
    event TaskCompleted(uint256 indexed taskId, uint256 indexed agentId);
    event TaskDisputed(uint256 indexed taskId, uint256 indexed agentId);
    event DisputeResolved(uint256 indexed taskId, uint256 indexed agentId, bool agentWon, uint8 validationScore);
    event BondSlashed(uint256 indexed agentId, uint256 indexed taskId, uint256 amount);
    event TaskExpiredClaimed(uint256 indexed taskId, uint256 indexed agentId);
    event DisputeExpiredClaimed(uint256 indexed taskId, address indexed beneficiary);
    event ValidatorFeeEscrowed(uint256 indexed taskId, address indexed payer, uint256 amount, uint256 requiredAmount);
    event ValidatorFeePaid(uint256 indexed taskId, address indexed validator, uint256 amount);
    event ValidatorFeeRefunded(uint256 indexed taskId, address indexed beneficiary, uint256 amount);
    event RegistryFailureRecorded(uint256 indexed taskId, uint256 retryAfter);
    event DisputeRefundedNoRegistry(uint256 indexed taskId, address indexed beneficiary);
    event RegistryFailureGracePeriodUpdated(uint256 oldPeriod, uint256 newPeriod);
    event ValidationFinalityPolicyUpdated(uint8 oldPolicy, uint8 newPolicy);
    event StatusLookupFailurePolicyUpdated(uint8 oldPolicy, uint8 newPolicy);
    event ValidatorSelectionPolicyUpdated(uint8 oldPolicy, uint8 newPolicy);
    event MinValidatorFeeUpdated(uint256 oldMinFee, uint256 newMinFee);
    event Permit2Updated(address oldPermit2, address newPermit2);
    event TrustedValidatorAdded(address indexed validator);
    event TrustedValidatorRemoved(address indexed validator);
    event MaxAgentTaskHistoryUpdated(uint256 oldLimit, uint256 newLimit);
    event Credited(address indexed account, uint256 amount);
    event Claimed(address indexed account, uint256 amount);
    event AgentOutcomeRecorded(
        uint256 indexed agentId,
        uint256 indexed taskId,
        uint8 indexed outcomeKind,
        uint256 payment,
        uint256 slashAmount
    );
    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event DisputePeriodUpdated(uint256 oldPeriod, uint256 newPeriod);
    event MinPassingScoreUpdated(uint8 oldScore, uint8 newScore);
    event SlashBpsUpdated(uint256 oldBps, uint256 newBps);

    error NotOwner();
    error NotPendingOwner();
    error NotAgentOwner();
    error NotClient();
    error ZeroAddress();
    error ZeroValue();
    error InvalidStatus();
    error InsufficientBond();
    error DeadlineInPast();
    error EmptyTaskHash();
    error NotExpired();
    error DisputePeriodActive();
    error DeadlinePassed();
    error AgentMismatch();
    error NoValidationResponse();
    error ValidationExists();
    error TransferFailed();
    error Reentrancy();
    error InvalidParameter();
    error InvalidSignature();
    error ValidatorMismatch();
    error ValidatorNotTrusted();
    error ValidatorFeeBelowMinimum();
    error InsufficientValidatorFee();
    error RegistryUnavailable();
    error TokenTransferMismatch();
    error PermitAmountTooLow();
    error AddressWithoutCode();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    modifier nonReentrant() {
        uint256 locked;
        assembly ("memory-safe") {
            locked := tload(0)
        }
        if (locked != 0) revert Reentrancy();
        assembly ("memory-safe") {
            tstore(0, 1)
        }
        _;
        assembly ("memory-safe") {
            tstore(0, 0)
        }
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(
        address identityRegistry_,
        address validationRegistry_,
        address scorer_,
        address settlementToken_,
        uint256 disputePeriod_,
        uint8 minPassingScore_,
        uint256 slashBps_
    ) external initializer {
        if (identityRegistry_ == address(0)) revert ZeroAddress();
        if (validationRegistry_ == address(0)) revert ZeroAddress();
        if (scorer_ == address(0)) revert ZeroAddress();
        if (settlementToken_ == address(0)) revert ZeroAddress();
        _requireHasCode(identityRegistry_);
        _requireHasCode(validationRegistry_);
        _requireHasCode(scorer_);
        _requireHasCode(settlementToken_);
        if (minPassingScore_ == 0 || minPassingScore_ > 100) revert InvalidParameter();
        if (slashBps_ > 10_000) revert InvalidParameter();
        if (disputePeriod_ < MIN_DISPUTE_PERIOD || disputePeriod_ > MAX_DISPUTE_PERIOD) revert InvalidParameter();

        IDENTITY_REGISTRY = IERC8004Identity(identityRegistry_);
        VALIDATION_REGISTRY = IERC8004Validation(validationRegistry_);
        SCORER = IReputationScorer(scorer_);
        settlementToken = IERC20(settlementToken_);
        permit2 = PERMIT2_DEFAULT;
        disputePeriod = disputePeriod_;
        minPassingScore = minPassingScore_;
        slashBps = slashBps_;
        registryFailureGracePeriod = 3 days;
        validationFinalityPolicy = ValidationFinalityPolicy.ResponseHashRequired;
        statusLookupFailurePolicy = StatusLookupFailurePolicy.CanonicalUnknownAsMissing;
        validatorSelectionPolicy = ValidatorSelectionPolicy.DesignatedOnly;
        maxAgentTaskHistory = DEFAULT_MAX_AGENT_TASK_HISTORY;
        owner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
    }

    // --- Core ---

    /// @notice Bond principal is agent-owned; only the current identity owner can deposit.
    function depositBond(uint256 agentId, uint256 amount) external nonReentrant {
        _validateDeposit(msg.sender, agentId, amount);
        _pullPayment(msg.sender, amount);
        _recordDeposit(agentId, msg.sender, amount);
    }

    function depositBondWithPermit2(
        uint256 agentId,
        uint256 amount,
        uint256 permitAmount,
        uint256 permitExpiration,
        uint256 permitNonce,
        uint256 permitSigDeadline,
        bytes calldata permitSig
    ) external nonReentrant {
        _validateDeposit(msg.sender, agentId, amount);
        _pullPaymentWithPermit2(msg.sender, amount, permitAmount, permitExpiration, permitNonce, permitSigDeadline, permitSig);
        _recordDeposit(agentId, msg.sender, amount);
    }

    function depositBondWithEip3009(
        uint256 agentId,
        uint256 amount,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external nonReentrant {
        _validateDeposit(msg.sender, agentId, amount);
        _pullPaymentWithEip3009(msg.sender, amount, validAfter, validBefore, nonce, v, r, s);
        _recordDeposit(agentId, msg.sender, amount);
    }

    function withdrawBond(uint256 agentId, uint256 amount) external nonReentrant {
        if (amount == 0) revert ZeroValue();
        if (!IDENTITY_REGISTRY.isAuthorizedOrOwner(msg.sender, agentId)) revert NotAgentOwner();

        Bond storage bond = bonds[agentId];
        uint256 available = bond.amount - bond.locked;
        if (amount > available) revert InsufficientBond();

        bond.amount -= amount;

        address recipient = _agentRecipient(agentId);
        _pushPayment(recipient, amount);
        emit BondWithdrawn(agentId, recipient, amount);
    }

    /// @notice Requires EIP-712 signature from the agent (or authorized operator/smart wallet).
    function createTask(
        uint256 agentId,
        bytes32 taskHash,
        uint256 deadline,
        uint256 paymentAmount,
        address signer,
        address agentRecipient_,
        address clientRecipient_,
        address committedValidator_,
        uint256 validatorFeeAmount,
        bytes calldata validatorSig,
        bytes calldata agentSig
    ) external nonReentrant returns (uint256 taskId) {
        CreateTaskInput memory input = _buildCreateTaskInput(
            agentId,
            taskHash,
            deadline,
            paymentAmount,
            signer,
            agentRecipient_,
            clientRecipient_,
            committedValidator_,
            validatorFeeAmount
        );
        _validateCreateTask(input);
        _verifyCreateTaskSignatures(input, msg.sender, validatorSig, agentSig);
        _pullPayment(msg.sender, input.paymentAmount);
        return _recordTask(msg.sender, input);
    }

    function createTaskWithPermit2(
        uint256 agentId,
        bytes32 taskHash,
        uint256 deadline,
        uint256 paymentAmount,
        address signer,
        address agentRecipient_,
        address clientRecipient_,
        address committedValidator_,
        uint256 validatorFeeAmount,
        bytes calldata validatorSig,
        bytes calldata agentSig,
        uint256 permitAmount,
        uint256 permitExpiration,
        uint256 permitNonce,
        uint256 permitSigDeadline,
        bytes calldata permitSig
    ) external nonReentrant returns (uint256 taskId) {
        CreateTaskInput memory input = _buildCreateTaskInput(
            agentId,
            taskHash,
            deadline,
            paymentAmount,
            signer,
            agentRecipient_,
            clientRecipient_,
            committedValidator_,
            validatorFeeAmount
        );
        _validateCreateTask(input);
        _verifyCreateTaskSignatures(input, msg.sender, validatorSig, agentSig);
        _pullPaymentWithPermit2(
            msg.sender,
            input.paymentAmount,
            permitAmount,
            permitExpiration,
            permitNonce,
            permitSigDeadline,
            permitSig
        );
        return _recordTask(msg.sender, input);
    }

    function createTaskWithEip3009(
        uint256 agentId,
        bytes32 taskHash,
        uint256 deadline,
        uint256 paymentAmount,
        address signer,
        address agentRecipient_,
        address clientRecipient_,
        address committedValidator_,
        uint256 validatorFeeAmount,
        bytes calldata validatorSig,
        bytes calldata agentSig,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external nonReentrant returns (uint256 taskId) {
        CreateTaskInput memory input = _buildCreateTaskInput(
            agentId,
            taskHash,
            deadline,
            paymentAmount,
            signer,
            agentRecipient_,
            clientRecipient_,
            committedValidator_,
            validatorFeeAmount
        );
        _validateCreateTask(input);
        _verifyCreateTaskSignatures(input, msg.sender, validatorSig, agentSig);
        _pullPaymentWithEip3009(msg.sender, input.paymentAmount, validAfter, validBefore, nonce, v, r, s);
        return _recordTask(msg.sender, input);
    }

    function completeTask(uint256 taskId) external nonReentrant {
        Task storage task = tasks[taskId];
        if (task.status != TaskStatus.Active) revert InvalidStatus();
        if (msg.sender != task.client) revert NotClient();
        if (block.timestamp > task.deadline) revert DeadlinePassed();

        task.status = TaskStatus.Completed;
        _unlockBond(task.agentId, task.bondLocked);
        _credit(task.agentRecipient, task.payment);
        _recordSuccessOutcome(task.agentId, taskId, task.payment);
        emit TaskCompleted(taskId, task.agentId);
    }

    function disputeTask(uint256 taskId, uint256 validatorFeeAmount) external nonReentrant {
        (Task storage task, uint256 requiredFee) = _validateDispute(taskId, validatorFeeAmount);
        _pullPayment(msg.sender, validatorFeeAmount);
        _recordDispute(task, taskId, validatorFeeAmount, requiredFee);
    }

    function disputeTaskWithPermit2(
        uint256 taskId,
        uint256 validatorFeeAmount,
        uint256 permitAmount,
        uint256 permitExpiration,
        uint256 permitNonce,
        uint256 permitSigDeadline,
        bytes calldata permitSig
    ) external nonReentrant {
        (Task storage task, uint256 requiredFee) = _validateDispute(taskId, validatorFeeAmount);
        _pullPaymentWithPermit2(
            msg.sender,
            validatorFeeAmount,
            permitAmount,
            permitExpiration,
            permitNonce,
            permitSigDeadline,
            permitSig
        );
        _recordDispute(task, taskId, validatorFeeAmount, requiredFee);
    }

    function disputeTaskWithEip3009(
        uint256 taskId,
        uint256 validatorFeeAmount,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external nonReentrant {
        (Task storage task, uint256 requiredFee) = _validateDispute(taskId, validatorFeeAmount);
        _pullPaymentWithEip3009(msg.sender, validatorFeeAmount, validAfter, validBefore, nonce, v, r, s);
        _recordDispute(task, taskId, validatorFeeAmount, requiredFee);
    }

    /// @notice Validation finality behavior is controlled by validationFinalityPolicy.
    function resolveDispute(uint256 taskId) external nonReentrant {
        Task storage task = tasks[taskId];
        if (task.status != TaskStatus.Disputed) revert InvalidStatus();

        bytes32 reqHash = _requestHashForTask(taskId, task);
        uint8 finalityPolicy = _taskValidationFinalityPolicy(task);

        uint8 response;
        try VALIDATION_REGISTRY.getValidationStatus(reqHash) returns (
            address validatorAddr, uint256 validationAgentId, uint8 resp, bytes32 respHash, string memory, uint256
        ) {
            if (_isMissingValidationRecord(validatorAddr, validationAgentId)) revert NoValidationResponse();
            if (!_isFinalValidationRecord(respHash, finalityPolicy)) revert NoValidationResponse();
            if (validationAgentId != task.agentId) revert AgentMismatch();
            if (validatorAddr != task.committedValidator) revert ValidatorMismatch();
            response = resp;
        } catch {
            revert NoValidationResponse();
        }

        _payValidatorFee(taskId, task.committedValidator);

        if (response >= task.snapshotMinPassingScore) {
            task.status = TaskStatus.Resolved;
            _unlockBond(task.agentId, task.bondLocked);
            _credit(task.agentRecipient, task.payment);
            _recordSuccessOutcome(task.agentId, taskId, task.payment);
            emit DisputeResolved(taskId, task.agentId, true, response);
        } else {
            task.status = TaskStatus.Slashed;
            uint256 slashAmount = _slashAndRefund(task, taskId);
            _recordSlashedOutcome(task.agentId, taskId, task.payment, slashAmount);
            emit DisputeResolved(taskId, task.agentId, false, response);
        }
    }

    /// @notice Permissionless expiry claim; anyone can execute this keeper-friendly path after deadline.
    function claimExpiredTask(uint256 taskId) external nonReentrant {
        Task storage task = tasks[taskId];
        if (task.status != TaskStatus.Active) revert InvalidStatus();
        if (block.timestamp <= task.deadline) revert NotExpired();

        task.status = TaskStatus.Expired;
        _unlockBond(task.agentId, task.bondLocked);
        _credit(task.agentRecipient, task.payment);
        _recordSuccessOutcome(task.agentId, taskId, task.payment);
        emit TaskExpiredClaimed(taskId, task.agentId);
    }

    /// @notice Slashes when no final validation exists; refund-only after grace if registry is unavailable.
    function reclaimDisputedTask(uint256 taskId) external nonReentrant {
        Task storage task = tasks[taskId];
        if (task.status != TaskStatus.Disputed) revert InvalidStatus();
        if (block.timestamp <= task.disputedAt + task.snapshotDisputePeriod) revert DisputePeriodActive();

        bytes32 reqHash = _requestHashForTask(taskId, task);
        uint8 finalityPolicy = _taskValidationFinalityPolicy(task);
        uint8 failurePolicy = _taskStatusLookupFailurePolicy(task);
        bool registryFailed;
        bool validationExists;
        try VALIDATION_REGISTRY.getValidationStatus(reqHash) returns (
            address validatorAddr, uint256 validationAgentId, uint8, bytes32 responseHash, string memory, uint256
        ) {
            if (
                validationAgentId == task.agentId && validatorAddr == task.committedValidator
                    && _isFinalValidationRecord(responseHash, finalityPolicy)
            ) {
                validationExists = true;
            }
        } catch {
            registryFailed = _statusLookupFailureMeansUnavailable(taskId, task.agentId, reqHash, failurePolicy);
        }

        if (validationExists) revert ValidationExists();

        if (registryFailed) {
            uint256 failedAt = registryFailureSince[taskId];
            if (failedAt == 0) {
                registryFailureSince[taskId] = block.timestamp;
                emit RegistryFailureRecorded(taskId, block.timestamp + task.snapshotRegistryGracePeriod);
                return;
            }
            if (block.timestamp < failedAt + task.snapshotRegistryGracePeriod) revert RegistryUnavailable();
            task.status = TaskStatus.Refunded;
            _unlockBond(task.agentId, task.bondLocked);
            address beneficiary = task.clientRecipient;
            _credit(beneficiary, task.payment);
            _refundValidatorFee(taskId, beneficiary);
            _recordNeutralOutcome(task.agentId, taskId);
            emit DisputeRefundedNoRegistry(taskId, beneficiary);
        } else {
            task.status = TaskStatus.Slashed;
            uint256 slashAmount = _slashAndRefund(task, taskId);
            _refundValidatorFee(taskId, task.clientRecipient);
            _recordSlashedOutcome(task.agentId, taskId, task.payment, slashAmount);
            emit DisputeExpiredClaimed(taskId, task.clientRecipient);
        }
    }

    /// @notice Pull-payment: withdraw credited funds.
    function claim() external nonReentrant {
        uint256 amount = claimable[msg.sender];
        if (amount == 0) revert ZeroValue();
        claimable[msg.sender] = 0;
        _pushPayment(msg.sender, amount);
        emit Claimed(msg.sender, amount);
    }

    // --- Admin ---

    function setDisputePeriod(uint256 newPeriod) external onlyOwner {
        if (newPeriod < MIN_DISPUTE_PERIOD || newPeriod > MAX_DISPUTE_PERIOD) revert InvalidParameter();
        emit DisputePeriodUpdated(disputePeriod, newPeriod);
        disputePeriod = newPeriod;
    }

    function setMinPassingScore(uint8 newScore) external onlyOwner {
        if (newScore == 0 || newScore > 100) revert InvalidParameter();
        emit MinPassingScoreUpdated(minPassingScore, newScore);
        minPassingScore = newScore;
    }

    function setSlashBps(uint256 newBps) external onlyOwner {
        if (newBps > 10_000) revert InvalidParameter();
        emit SlashBpsUpdated(slashBps, newBps);
        slashBps = newBps;
    }

    function setRegistryFailureGracePeriod(uint256 newPeriod) external onlyOwner {
        if (newPeriod > MAX_DISPUTE_PERIOD) revert InvalidParameter();
        emit RegistryFailureGracePeriodUpdated(registryFailureGracePeriod, newPeriod);
        registryFailureGracePeriod = newPeriod;
    }

    function setValidationFinalityPolicy(uint8 newPolicy) external onlyOwner {
        if (newPolicy > uint8(ValidationFinalityPolicy.AnyStatusRecord)) revert InvalidParameter();
        uint8 oldPolicy = uint8(validationFinalityPolicy);
        validationFinalityPolicy = ValidationFinalityPolicy(newPolicy);
        emit ValidationFinalityPolicyUpdated(oldPolicy, newPolicy);
    }

    function setStatusLookupFailurePolicy(uint8 newPolicy) external onlyOwner {
        if (newPolicy > uint8(StatusLookupFailurePolicy.AlwaysUnavailable)) revert InvalidParameter();
        uint8 oldPolicy = uint8(statusLookupFailurePolicy);
        statusLookupFailurePolicy = StatusLookupFailurePolicy(newPolicy);
        emit StatusLookupFailurePolicyUpdated(oldPolicy, newPolicy);
    }

    function setValidatorSelectionPolicy(uint8 newPolicy) external onlyOwner {
        if (newPolicy > uint8(ValidatorSelectionPolicy.DesignatedAndAllowlisted)) revert InvalidParameter();
        uint8 oldPolicy = uint8(validatorSelectionPolicy);
        validatorSelectionPolicy = ValidatorSelectionPolicy(newPolicy);
        emit ValidatorSelectionPolicyUpdated(oldPolicy, newPolicy);
    }

    function addTrustedValidator(address validator) external onlyOwner {
        if (validator == address(0)) revert ZeroAddress();
        if (trustedValidators[validator]) revert InvalidParameter();
        trustedValidators[validator] = true;
        emit TrustedValidatorAdded(validator);
    }

    function removeTrustedValidator(address validator) external onlyOwner {
        if (!trustedValidators[validator]) revert InvalidParameter();
        trustedValidators[validator] = false;
        emit TrustedValidatorRemoved(validator);
    }

    function setMinValidatorFee(uint256 newMinFee) external onlyOwner {
        if (newMinFee > _maxMinValidatorFee()) revert InvalidParameter();
        emit MinValidatorFeeUpdated(minValidatorFee, newMinFee);
        minValidatorFee = newMinFee;
    }

    function setPermit2(address newPermit2) external onlyOwner {
        if (newPermit2 == address(0)) revert ZeroAddress();
        _requireHasCode(newPermit2);
        emit Permit2Updated(permit2, newPermit2);
        permit2 = newPermit2;
    }

    function setMaxAgentTaskHistory(uint256 newLimit) external onlyOwner {
        if (newLimit == 0) revert InvalidParameter();
        emit MaxAgentTaskHistoryUpdated(maxAgentTaskHistory, newLimit);
        maxAgentTaskHistory = newLimit;
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

    function availableBond(uint256 agentId) external view returns (uint256) {
        return bonds[agentId].amount - bonds[agentId].locked;
    }

    function getTask(uint256 taskId) external view returns (Task memory) {
        return tasks[taskId];
    }

    function getBond(uint256 agentId) external view returns (uint256 amount, uint256 locked) {
        return (bonds[agentId].amount, bonds[agentId].locked);
    }

    function agentTaskIds(uint256 agentId) external view returns (uint256[] memory) {
        (uint256 historyStart, uint256 historyLen) = _taskHistoryWindow(agentId);
        uint256[] memory ids = new uint256[](historyLen);
        for (uint256 i; i < historyLen; i++) {
            ids[i] = _agentTaskHistory[agentId][historyStart + i];
        }

        return ids;
    }

    function agentTaskIdsSlice(uint256 agentId, uint256 offset, uint256 limit)
        external
        view
        returns (uint256[] memory)
    {
        if (limit == 0) {
            return new uint256[](0);
        }

        (uint256 historyStart, uint256 historyLen) = _taskHistoryWindow(agentId);
        if (offset >= historyLen) {
            return new uint256[](0);
        }

        uint256 end = offset + limit;
        if (end > historyLen) {
            end = historyLen;
        }

        uint256 size = end - offset;
        uint256[] memory slice = new uint256[](size);
        for (uint256 i; i < size; i++) {
            uint256 historyIndex = historyStart + offset + i;
            slice[i] = _agentTaskHistory[agentId][historyIndex];
        }

        return slice;
    }

    function requestHash(uint256 taskId) external view returns (bytes32) {
        Task storage task = tasks[taskId];
        return _requestHash(
            taskId, task.agentId, task.client, task.agentRecipient, task.clientRecipient, task.payment, task.taskHash
        );
    }

    function getAgentOutcomeTotals(uint256 agentId)
        external
        view
        returns (
            uint256 successValue,
            uint256 slashValue,
            uint64 successCount,
            uint64 slashCount,
            uint256 slashAmount,
            uint64 neutralCount
        )
    {
        AgentOutcomes storage outcomes = _agentOutcomes[agentId];
        return (
            outcomes.successValue,
            outcomes.slashValue,
            outcomes.successCount,
            outcomes.slashCount,
            outcomes.slashAmount,
            outcomes.neutralCount
        );
    }

    function domainSeparator() external view returns (bytes32) {
        return _domainSeparator();
    }

    // --- Internal ---

    function _authorizeUpgrade(address) internal override onlyOwner {}

    function _requireHasCode(address target) internal view {
        if (target.code.length == 0) revert AddressWithoutCode();
    }

    function _maxMinValidatorFee() internal view returns (uint256) {
        return MAX_MIN_VALIDATOR_FEE_TOKENS * (10 ** uint256(_settlementTokenDecimals()));
    }

    function _settlementTokenDecimals() internal view returns (uint8) {
        (bool ok, bytes memory data) = address(settlementToken).staticcall(abi.encodeWithSelector(0x313ce567));
        if (!ok || data.length < 32) return 18;

        uint256 decoded = abi.decode(data, (uint256));
        if (decoded > 77) return 18;
        return uint8(decoded);
    }

    function _verifyTaskPermit(
        uint256 agentId,
        address signer,
        address client_,
        address agentRecipient_,
        address clientRecipient_,
        address committedValidator_,
        uint256 validatorFeeAmount_,
        uint256 paymentAmount,
        uint256 deadline,
        bytes32 taskHash_,
        bytes calldata sig
    ) internal {
        if (!IDENTITY_REGISTRY.isAuthorizedOrOwner(signer, agentId)) revert InvalidSignature();
        uint256 nonce = agentNonces[agentId];
        bytes32 structHash = keccak256(
            abi.encode(
                TASK_PERMIT_TYPEHASH,
                agentId,
                client_,
                agentRecipient_,
                clientRecipient_,
                committedValidator_,
                validatorFeeAmount_,
                paymentAmount,
                deadline,
                taskHash_,
                nonce
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));
        if (!SignatureChecker.isValidSignatureNow(signer, digest, sig)) revert InvalidSignature();
        agentNonces[agentId] = nonce + 1;
    }

    function _verifyValidatorCommitment(
        address committedValidator_,
        uint256 agentId,
        address client_,
        bytes32 taskHash_,
        uint256 validatorFeeAmount_,
        uint256 deadline,
        bytes calldata validatorSig
    ) internal {
        uint256 nonce = validatorNonces[committedValidator_];
        bytes32 structHash = keccak256(
            abi.encode(
                VALIDATOR_COMMITMENT_TYPEHASH,
                agentId,
                client_,
                taskHash_,
                validatorFeeAmount_,
                deadline,
                nonce
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));
        if (!SignatureChecker.isValidSignatureNow(committedValidator_, digest, validatorSig)) revert InvalidSignature();
        validatorNonces[committedValidator_] = nonce + 1;
    }

    function _domainSeparator() internal view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, block.chainid, address(this)));
    }

    function _unlockBond(uint256 agentId, uint256 amount) internal {
        bonds[agentId].locked -= amount;
    }

    function _validateDeposit(address depositor, uint256 agentId, uint256 amount) internal view {
        if (amount == 0) revert ZeroValue();
        if (IDENTITY_REGISTRY.ownerOf(agentId) != depositor) revert NotAgentOwner();
    }

    function _recordDeposit(uint256 agentId, address depositor, uint256 amount) internal {
        bonds[agentId].amount += amount;
        emit BondDeposited(agentId, depositor, amount);
    }

    function _validateCreateTask(CreateTaskInput memory input) internal view {
        if (input.paymentAmount == 0) revert ZeroValue();
        if (input.deadline <= block.timestamp) revert DeadlineInPast();
        if (input.deadline > type(uint48).max) revert InvalidParameter();
        if (input.taskHash == bytes32(0)) revert EmptyTaskHash();
        if (input.agentRecipient == address(0)) revert ZeroAddress();
        if (input.clientRecipient == address(0)) revert ZeroAddress();
        if (input.committedValidator == address(0)) revert ZeroAddress();
        _requireTrustedCommittedValidator(input.committedValidator);
        if (input.validatorFeeAmount < minValidatorFee) revert ValidatorFeeBelowMinimum();
    }

    function _verifyCreateTaskSignatures(
        CreateTaskInput memory input,
        address client_,
        bytes calldata validatorSig,
        bytes calldata agentSig
    ) internal {
        _verifyTaskPermit(
            input.agentId,
            input.signer,
            client_,
            input.agentRecipient,
            input.clientRecipient,
            input.committedValidator,
            input.validatorFeeAmount,
            input.paymentAmount,
            input.deadline,
            input.taskHash,
            agentSig
        );
        _verifyValidatorCommitment(
            input.committedValidator,
            input.agentId,
            client_,
            input.taskHash,
            input.validatorFeeAmount,
            input.deadline,
            validatorSig
        );
    }

    function _buildCreateTaskInput(
        uint256 agentId,
        bytes32 taskHash,
        uint256 deadline,
        uint256 paymentAmount,
        address signer,
        address agentRecipient_,
        address clientRecipient_,
        address committedValidator_,
        uint256 validatorFeeAmount
    ) internal pure returns (CreateTaskInput memory) {
        return CreateTaskInput({
            agentId: agentId,
            taskHash: taskHash,
            deadline: deadline,
            paymentAmount: paymentAmount,
            signer: signer,
            agentRecipient: agentRecipient_,
            clientRecipient: clientRecipient_,
            committedValidator: committedValidator_,
            validatorFeeAmount: validatorFeeAmount
        });
    }

    function _recordTask(address client_, CreateTaskInput memory input) internal returns (uint256 taskId) {
        uint256 requiredBond = SCORER.getRequiredBond(input.agentId, input.paymentAmount);
        Bond storage bond = bonds[input.agentId];
        uint256 available = bond.amount - bond.locked;
        if (available < requiredBond) revert InsufficientBond();
        bond.locked += requiredBond;

        taskId = nextTaskId++;
        tasks[taskId] = Task({
            agentId: input.agentId,
            client: client_,
            agentRecipient: input.agentRecipient,
            clientRecipient: input.clientRecipient,
            snapshotMinPassingScore: minPassingScore,
            snapshotValidationFinalityPolicy: 0,
            snapshotStatusLookupFailurePolicy: 0,
            status: TaskStatus.Active,
            payment: input.paymentAmount,
            taskHash: input.taskHash,
            bondLocked: requiredBond,
            deadline: uint48(input.deadline),
            disputedAt: 0,
            snapshotSlashBps: uint16(slashBps),
            snapshotDisputePeriod: uint40(disputePeriod),
            snapshotRegistryGracePeriod: 0,
            committedValidator: input.committedValidator
        });
        validatorFeeCommitment[taskId] = input.validatorFeeAmount;
        _appendAgentTaskId(input.agentId, taskId);

        bytes32 reqHash = _requestHash(
            taskId,
            input.agentId,
            client_,
            input.agentRecipient,
            input.clientRecipient,
            input.paymentAmount,
            input.taskHash
        );
        emit TaskCreated(taskId, input.agentId, client_, input.paymentAmount, input.taskHash, reqHash, requiredBond);
    }

    function _appendAgentTaskId(uint256 agentId, uint256 taskId) internal {
        uint256 historyIndex = _agentTaskHistoryCount[agentId];
        _agentTaskHistory[agentId][historyIndex] = taskId;

        uint256 newCount = historyIndex + 1;
        _agentTaskHistoryCount[agentId] = newCount;

        uint256 historyStart = _agentTaskHistoryStart[agentId];
        if (newCount > maxAgentTaskHistory) {
            uint256 minStart = newCount - maxAgentTaskHistory;
            if (historyStart < minStart) {
                _agentTaskHistoryStart[agentId] = minStart;
            }
        }
    }

    function _validateDispute(uint256 taskId, uint256 validatorFeeAmount)
        internal
        view
        returns (Task storage task, uint256 requiredFee)
    {
        task = tasks[taskId];
        if (task.status != TaskStatus.Active) revert InvalidStatus();
        if (msg.sender != task.client) revert NotClient();
        if (block.timestamp > task.deadline) revert DeadlinePassed();
        requiredFee = validatorFeeCommitment[taskId];
        if (validatorFeeAmount < requiredFee) revert InsufficientValidatorFee();
    }

    function _recordDispute(Task storage task, uint256 taskId, uint256 validatorFeeAmount, uint256 requiredFee) internal {
        task.status = TaskStatus.Disputed;
        task.disputedAt = uint48(block.timestamp);
        task.snapshotRegistryGracePeriod = uint40(registryFailureGracePeriod);
        task.snapshotValidationFinalityPolicy = uint8(validationFinalityPolicy);
        task.snapshotStatusLookupFailurePolicy = uint8(statusLookupFailurePolicy);
        validatorFeeEscrow[taskId] = validatorFeeAmount;
        _disputeRequestKnownState[taskId] = REQUEST_KNOWN_STATE_UNSET;
        if (task.snapshotStatusLookupFailurePolicy == uint8(StatusLookupFailurePolicy.CanonicalUnknownAsMissing)) {
            _cacheDisputeRequestKnownness(taskId, task.agentId, _requestHashForTask(taskId, task));
        }
        emit ValidatorFeeEscrowed(taskId, msg.sender, validatorFeeAmount, requiredFee);
        emit TaskDisputed(taskId, task.agentId);
    }

    function _slashAndRefund(Task storage task, uint256 taskId) internal returns (uint256 slashAmount) {
        slashAmount = (task.payment * task.snapshotSlashBps) / 10_000;
        if (slashAmount > task.bondLocked) slashAmount = task.bondLocked;

        Bond storage bond = bonds[task.agentId];
        bond.amount -= slashAmount;
        bond.locked -= task.bondLocked;

        _credit(task.clientRecipient, task.payment + slashAmount);
        emit BondSlashed(task.agentId, taskId, slashAmount);
        return slashAmount;
    }

    function _credit(address to, uint256 amount) internal {
        claimable[to] += amount;
        emit Credited(to, amount);
    }

    function _pullPayment(address from, uint256 amount) internal {
        uint256 beforeBal = settlementToken.balanceOf(address(this));
        settlementToken.safeTransferFrom(from, address(this), amount);
        uint256 afterBal = settlementToken.balanceOf(address(this));
        if (afterBal - beforeBal != amount) revert TokenTransferMismatch();
    }

    function _pullPaymentWithPermit2(
        address from,
        uint256 amount,
        uint256 permitAmount,
        uint256 permitExpiration,
        uint256 permitNonce,
        uint256 permitSigDeadline,
        bytes calldata permitSig
    ) internal {
        if (permitAmount < amount) revert PermitAmountTooLow();
        if (amount > type(uint160).max) revert InvalidParameter();
        if (permitAmount > type(uint160).max) revert InvalidParameter();
        if (permitExpiration > type(uint48).max) revert InvalidParameter();
        if (permitNonce > type(uint48).max) revert InvalidParameter();

        IPermit2.PermitSingle memory permitSingle = IPermit2.PermitSingle({
            details: IPermit2.PermitDetails({
                token: address(settlementToken),
                amount: uint160(permitAmount),
                expiration: uint48(permitExpiration),
                nonce: uint48(permitNonce)
            }),
            spender: address(this),
            sigDeadline: permitSigDeadline
        });

        uint256 beforeBal = settlementToken.balanceOf(address(this));
        IPermit2(permit2).permit(from, permitSingle, permitSig);
        IPermit2(permit2).transferFrom(from, address(this), uint160(amount), address(settlementToken));
        uint256 afterBal = settlementToken.balanceOf(address(this));
        if (afterBal - beforeBal != amount) revert TokenTransferMismatch();
    }

    function _pullPaymentWithEip3009(
        address from,
        uint256 amount,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal {
        uint256 beforeBal = settlementToken.balanceOf(address(this));
        IEIP3009(address(settlementToken)).transferWithAuthorization(
            from, address(this), amount, validAfter, validBefore, nonce, v, r, s
        );
        uint256 afterBal = settlementToken.balanceOf(address(this));
        if (afterBal - beforeBal != amount) revert TokenTransferMismatch();
    }

    function _payValidatorFee(uint256 taskId, address validatorAddr) internal {
        uint256 fee = validatorFeeEscrow[taskId];
        if (fee == 0) return;
        validatorFeeEscrow[taskId] = 0;
        _credit(validatorAddr, fee);
        emit ValidatorFeePaid(taskId, validatorAddr, fee);
    }

    function _refundValidatorFee(uint256 taskId, address beneficiary) internal {
        uint256 fee = validatorFeeEscrow[taskId];
        if (fee == 0) return;
        validatorFeeEscrow[taskId] = 0;
        _credit(beneficiary, fee);
        emit ValidatorFeeRefunded(taskId, beneficiary, fee);
    }

    function _pushPayment(address to, uint256 amount) internal {
        settlementToken.safeTransfer(to, amount);
    }

    function _recordSuccessOutcome(uint256 agentId, uint256 taskId, uint256 payment) internal {
        AgentOutcomes storage outcomes = _agentOutcomes[agentId];
        outcomes.successValue += payment;
        outcomes.successCount += 1;
        emit AgentOutcomeRecorded(agentId, taskId, uint8(AgentOutcomeKind.Success), payment, 0);
    }

    function _recordSlashedOutcome(uint256 agentId, uint256 taskId, uint256 payment, uint256 slashAmount) internal {
        AgentOutcomes storage outcomes = _agentOutcomes[agentId];
        outcomes.slashValue += payment + slashAmount;
        outcomes.slashAmount += slashAmount;
        outcomes.slashCount += 1;
        emit AgentOutcomeRecorded(agentId, taskId, uint8(AgentOutcomeKind.Slashed), payment, slashAmount);
    }

    function _recordNeutralOutcome(uint256 agentId, uint256 taskId) internal {
        AgentOutcomes storage outcomes = _agentOutcomes[agentId];
        outcomes.neutralCount += 1;
        emit AgentOutcomeRecorded(agentId, taskId, uint8(AgentOutcomeKind.Neutral), 0, 0);
    }

    function _agentRecipient(uint256 agentId) internal view returns (address) {
        address wallet = IDENTITY_REGISTRY.getAgentWallet(agentId);
        return wallet == address(0) ? IDENTITY_REGISTRY.ownerOf(agentId) : wallet;
    }

    function _requestHash(
        uint256 taskId,
        uint256 agentId_,
        address client_,
        address agentRecipient_,
        address clientRecipient_,
        uint256 payment_,
        bytes32 taskHash_
    ) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                address(this),
                block.chainid,
                taskId,
                agentId_,
                client_,
                agentRecipient_,
                clientRecipient_,
                payment_,
                taskHash_
            )
        );
    }

    function _requestHashForTask(uint256 taskId, Task storage task) internal view returns (bytes32) {
        return _requestHash(
            taskId, task.agentId, task.client, task.agentRecipient, task.clientRecipient, task.payment, task.taskHash
        );
    }

    function _isFinalValidationRecord(bytes32 responseHash, uint8 finalityPolicy) internal pure returns (bool) {
        if (finalityPolicy == uint8(ValidationFinalityPolicy.AnyStatusRecord)) {
            return true;
        }
        return responseHash != bytes32(0);
    }

    function _isMissingValidationRecord(address validatorAddr, uint256 validationAgentId) internal pure returns (bool) {
        return validatorAddr == address(0) && validationAgentId == 0;
    }

    function _statusLookupFailureMeansUnavailable(uint256 taskId, uint256 agentId, bytes32 reqHash, uint8 failurePolicy)
        internal
        returns (bool)
    {
        if (failurePolicy == uint8(StatusLookupFailurePolicy.AlwaysMissing)) {
            return false;
        }
        if (failurePolicy == uint8(StatusLookupFailurePolicy.AlwaysUnavailable)) {
            return true;
        }

        uint8 knownState = _disputeRequestKnownState[taskId];
        if (knownState == REQUEST_KNOWN_STATE_MISSING) {
            return false;
        }
        if (knownState == REQUEST_KNOWN_STATE_KNOWN) {
            return true;
        }
        if (knownState == REQUEST_KNOWN_STATE_UNSUPPORTED) {
            return true;
        }

        (bool supported, bool known) = _isRequestKnownForAgent(agentId, reqHash);
        if (!supported) {
            _disputeRequestKnownState[taskId] = REQUEST_KNOWN_STATE_UNSUPPORTED;
            return true;
        }
        _disputeRequestKnownState[taskId] = known ? REQUEST_KNOWN_STATE_KNOWN : REQUEST_KNOWN_STATE_MISSING;
        // unknown request => missing (slash path), known request with failed status read => unavailable.
        return known;
    }

    function _taskValidationFinalityPolicy(Task storage task) internal view returns (uint8) {
        return task.snapshotValidationFinalityPolicy;
    }

    function _taskStatusLookupFailurePolicy(Task storage task) internal view returns (uint8) {
        return task.snapshotStatusLookupFailurePolicy;
    }

    function _effectiveTaskHistoryStart(uint256 historyStart, uint256 historyCount) internal view returns (uint256) {
        if (historyCount <= maxAgentTaskHistory) {
            return historyStart;
        }

        uint256 minStart = historyCount - maxAgentTaskHistory;
        return historyStart > minStart ? historyStart : minStart;
    }

    function _taskHistoryWindow(uint256 agentId) internal view returns (uint256 historyStart, uint256 historyLen) {
        uint256 historyCount = _agentTaskHistoryCount[agentId];
        historyStart = _effectiveTaskHistoryStart(_agentTaskHistoryStart[agentId], historyCount);
        historyLen = historyCount > historyStart ? historyCount - historyStart : 0;
    }

    function _requireTrustedCommittedValidator(address committedValidator_) internal view {
        if (validatorSelectionPolicy == ValidatorSelectionPolicy.DesignatedAndAllowlisted) {
            if (!trustedValidators[committedValidator_]) revert ValidatorNotTrusted();
        }
    }

    function _cacheDisputeRequestKnownness(uint256 taskId, uint256 agentId, bytes32 reqHash) internal {
        (bool supported, bool known) = _isRequestKnownForAgent(agentId, reqHash);
        if (!supported) {
            _disputeRequestKnownState[taskId] = REQUEST_KNOWN_STATE_UNSUPPORTED;
            return;
        }
        _disputeRequestKnownState[taskId] = known ? REQUEST_KNOWN_STATE_KNOWN : REQUEST_KNOWN_STATE_MISSING;
    }

    function _isRequestKnownForAgent(uint256 agentId, bytes32 reqHash)
        internal
        view
        returns (bool supported, bool known)
    {
        (bool supportedLen, uint256 len) = _agentValidationsLength(agentId);
        if (!supportedLen || len > MAX_KNOWNNESS_SCAN) {
            return (false, false);
        }

        try VALIDATION_REGISTRY.getAgentValidations(agentId) returns (bytes32[] memory requestHashes) {
            uint256 actualLen = requestHashes.length;
            if (actualLen > MAX_KNOWNNESS_SCAN) {
                return (false, false);
            }
            supported = true;
            len = actualLen;
            for (uint256 i; i < len; i++) {
                if (requestHashes[i] == reqHash) {
                    return (true, true);
                }
            }
            return (true, false);
        } catch {
            return (false, false);
        }
    }

    function _agentValidationsLength(uint256 agentId) internal view returns (bool supported, uint256 len) {
        bytes memory callData = abi.encodeWithSelector(IERC8004Validation.getAgentValidations.selector, agentId);
        address registry = address(VALIDATION_REGISTRY);

        assembly ("memory-safe") {
            let ptr := mload(0x40)
            let success := staticcall(gas(), registry, add(callData, 0x20), mload(callData), ptr, 0x40)
            if success {
                if gt(returndatasize(), 0x3f) {
                    if eq(mload(ptr), 0x20) {
                        supported := 1
                        len := mload(add(ptr, 0x20))
                    }
                }
            }
            mstore(0x40, add(ptr, 0x40))
        }
    }

    uint256[36] private __gap;
}
