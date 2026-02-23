// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {IERC8004Identity} from "./interfaces/IERC8004Identity.sol";
import {IERC8004Validation} from "./interfaces/IERC8004Validation.sol";
import {IReputationScorer} from "./interfaces/IReputationScorer.sol";

/// @title AgentBondManager
/// @author Vaultum
/// @custom:security-contact dev@vaultum.app
/// @notice Reputation-collateralized bonding for ERC-8004 agents (UUPS).
contract AgentBondManager is Initializable, UUPSUpgradeable {
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
        uint256 deadline;
        uint256 disputedAt;
        uint256 snapshotSlashBps;
        uint256 snapshotDisputePeriod;
        uint256 snapshotRegistryGracePeriod;
        address agentRecipient;
        address clientRecipient;
        uint8 snapshotValidationFinalityPolicy;
        uint8 snapshotStatusLookupFailurePolicy;
        address committedValidator;
    }

    uint256 public constant MAX_DISPUTE_PERIOD = 90 days;

    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant NAME_HASH = keccak256("AgentBondManager");
    bytes32 private constant VERSION_HASH = keccak256("1");
    uint256 private constant MAX_KNOWNNESS_SCAN = 512;
    uint8 private constant REQUEST_KNOWN_STATE_UNSET = 0;
    uint8 private constant REQUEST_KNOWN_STATE_MISSING = 1;
    uint8 private constant REQUEST_KNOWN_STATE_KNOWN = 2;
    uint8 private constant REQUEST_KNOWN_STATE_UNSUPPORTED = 3;
    bytes32 private constant TASK_PERMIT_TYPEHASH = keccak256(
        "TaskPermit(uint256 agentId,address client,address agentRecipient,address clientRecipient,address committedValidator,uint256 payment,uint256 deadline,bytes32 taskHash,uint256 nonce)"
    );

    IERC8004Identity public IDENTITY_REGISTRY;
    IERC8004Validation public VALIDATION_REGISTRY;
    IReputationScorer public SCORER;

    address public owner;
    address public pendingOwner;
    uint256 public disputePeriod;
    uint8 public minPassingScore;
    uint256 public slashBps;
    uint256 public nextTaskId;

    mapping(uint256 agentId => Bond) public bonds;
    mapping(uint256 taskId => Task) public tasks;
    mapping(uint256 agentId => uint256[] taskIds) private _agentTasks;
    mapping(uint256 agentId => uint256) public agentNonces;
    mapping(address account => uint256) public claimable;
    mapping(uint256 taskId => uint256) public registryFailureSince;
    uint256 public registryFailureGracePeriod;
    ValidationFinalityPolicy public validationFinalityPolicy;
    StatusLookupFailurePolicy public statusLookupFailurePolicy;
    // Dispute request knownness cache:
    // 0=unset, 1=request missing, 2=request known, 3=knownness lookup unsupported.
    mapping(uint256 taskId => uint8) private _disputeRequestKnownState;

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
    event RegistryFailureRecorded(uint256 indexed taskId, uint256 retryAfter);
    event DisputeRefundedNoRegistry(uint256 indexed taskId, address indexed beneficiary);
    event RegistryFailureGracePeriodUpdated(uint256 oldPeriod, uint256 newPeriod);
    event ValidationFinalityPolicyUpdated(uint8 oldPolicy, uint8 newPolicy);
    event StatusLookupFailurePolicyUpdated(uint8 oldPolicy, uint8 newPolicy);
    event Credited(address indexed account, uint256 amount);
    event Claimed(address indexed account, uint256 amount);
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
    error RegistryUnavailable();

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
        uint256 disputePeriod_,
        uint8 minPassingScore_,
        uint256 slashBps_
    ) external initializer {
        if (identityRegistry_ == address(0)) revert ZeroAddress();
        if (validationRegistry_ == address(0)) revert ZeroAddress();
        if (scorer_ == address(0)) revert ZeroAddress();
        if (minPassingScore_ == 0 || minPassingScore_ > 100) revert InvalidParameter();
        if (slashBps_ > 10_000) revert InvalidParameter();
        if (disputePeriod_ > MAX_DISPUTE_PERIOD) revert InvalidParameter();

        IDENTITY_REGISTRY = IERC8004Identity(identityRegistry_);
        VALIDATION_REGISTRY = IERC8004Validation(validationRegistry_);
        SCORER = IReputationScorer(scorer_);
        disputePeriod = disputePeriod_;
        minPassingScore = minPassingScore_;
        slashBps = slashBps_;
        registryFailureGracePeriod = 3 days;
        validationFinalityPolicy = ValidationFinalityPolicy.ResponseHashRequired;
        statusLookupFailurePolicy = StatusLookupFailurePolicy.CanonicalUnknownAsMissing;
        owner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
    }

    // --- Core ---

    function depositBond(uint256 agentId) external payable {
        if (msg.value == 0) revert ZeroValue();
        if (!IDENTITY_REGISTRY.isAuthorizedOrOwner(msg.sender, agentId)) revert NotAgentOwner();

        bonds[agentId].amount += msg.value;
        emit BondDeposited(agentId, msg.sender, msg.value);
    }

    function withdrawBond(uint256 agentId, uint256 amount) external nonReentrant {
        if (amount == 0) revert ZeroValue();
        if (!IDENTITY_REGISTRY.isAuthorizedOrOwner(msg.sender, agentId)) revert NotAgentOwner();

        Bond storage bond = bonds[agentId];
        uint256 available = bond.amount - bond.locked;
        if (amount > available) revert InsufficientBond();

        bond.amount -= amount;

        address recipient = _agentRecipient(agentId);
        _transferETH(recipient, amount);
        emit BondWithdrawn(agentId, recipient, amount);
    }

    /// @notice Requires EIP-712 signature from the agent (or authorized operator/smart wallet).
    function createTask(
        uint256 agentId,
        bytes32 taskHash,
        uint256 deadline,
        address signer,
        address agentRecipient_,
        address clientRecipient_,
        address committedValidator_,
        bytes calldata agentSig
    ) external payable nonReentrant returns (uint256 taskId) {
        if (msg.value == 0) revert ZeroValue();
        if (deadline <= block.timestamp) revert DeadlineInPast();
        if (taskHash == bytes32(0)) revert EmptyTaskHash();
        if (agentRecipient_ == address(0)) revert ZeroAddress();
        if (clientRecipient_ == address(0)) revert ZeroAddress();
        if (committedValidator_ == address(0)) revert ZeroAddress();

        _verifyTaskPermit(
            agentId,
            signer,
            msg.sender,
            agentRecipient_,
            clientRecipient_,
            committedValidator_,
            msg.value,
            deadline,
            taskHash,
            agentSig
        );

        uint256 requiredBond = SCORER.getRequiredBond(agentId, msg.value);

        Bond storage bond = bonds[agentId];
        uint256 available = bond.amount - bond.locked;
        if (available < requiredBond) revert InsufficientBond();

        bond.locked += requiredBond;

        taskId = nextTaskId++;
        tasks[taskId] = Task({
            agentId: agentId,
            client: msg.sender,
            agentRecipient: agentRecipient_,
            clientRecipient: clientRecipient_,
            snapshotMinPassingScore: minPassingScore,
            snapshotValidationFinalityPolicy: 0,
            snapshotStatusLookupFailurePolicy: 0,
            status: TaskStatus.Active,
            payment: msg.value,
            taskHash: taskHash,
            bondLocked: requiredBond,
            deadline: deadline,
            disputedAt: 0,
            snapshotSlashBps: slashBps,
            snapshotDisputePeriod: disputePeriod,
            snapshotRegistryGracePeriod: 0,
            committedValidator: committedValidator_
        });

        _agentTasks[agentId].push(taskId);

        bytes32 reqHash =
            _requestHash(taskId, agentId, msg.sender, agentRecipient_, clientRecipient_, msg.value, taskHash);
        emit TaskCreated(taskId, agentId, msg.sender, msg.value, taskHash, reqHash, requiredBond);
    }

    function completeTask(uint256 taskId) external nonReentrant {
        Task storage task = tasks[taskId];
        if (task.status != TaskStatus.Active) revert InvalidStatus();
        if (msg.sender != task.client) revert NotClient();

        task.status = TaskStatus.Completed;
        _unlockBond(task.agentId, task.bondLocked);
        _credit(task.agentRecipient, task.payment);
        emit TaskCompleted(taskId, task.agentId);
    }

    function disputeTask(uint256 taskId) external {
        Task storage task = tasks[taskId];
        if (task.status != TaskStatus.Active) revert InvalidStatus();
        if (msg.sender != task.client) revert NotClient();
        if (block.timestamp > task.deadline) revert DeadlinePassed();

        task.status = TaskStatus.Disputed;
        task.disputedAt = block.timestamp;
        task.snapshotRegistryGracePeriod = registryFailureGracePeriod;
        task.snapshotValidationFinalityPolicy = uint8(validationFinalityPolicy);
        task.snapshotStatusLookupFailurePolicy = uint8(statusLookupFailurePolicy);
        _disputeRequestKnownState[taskId] = REQUEST_KNOWN_STATE_UNSET;
        if (task.snapshotStatusLookupFailurePolicy == uint8(StatusLookupFailurePolicy.CanonicalUnknownAsMissing)) {
            _cacheDisputeRequestKnownness(taskId, task.agentId, _requestHashForTask(taskId, task));
        }
        emit TaskDisputed(taskId, task.agentId);
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
            if (!_isFinalValidationRecord(respHash, finalityPolicy)) revert NoValidationResponse();
            if (validationAgentId != task.agentId) revert AgentMismatch();
            if (validatorAddr != task.committedValidator) revert ValidatorMismatch();
            response = resp;
        } catch {
            revert NoValidationResponse();
        }

        if (response >= task.snapshotMinPassingScore) {
            task.status = TaskStatus.Resolved;
            _unlockBond(task.agentId, task.bondLocked);
            _credit(task.agentRecipient, task.payment);
            emit DisputeResolved(taskId, task.agentId, true, response);
        } else {
            task.status = TaskStatus.Slashed;
            _slashAndRefund(task, taskId);
            emit DisputeResolved(taskId, task.agentId, false, response);
        }
    }

    function claimExpiredTask(uint256 taskId) external nonReentrant {
        Task storage task = tasks[taskId];
        if (task.status != TaskStatus.Active) revert InvalidStatus();
        if (block.timestamp <= task.deadline) revert NotExpired();

        task.status = TaskStatus.Expired;
        _unlockBond(task.agentId, task.bondLocked);
        _credit(task.agentRecipient, task.payment);
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
            emit DisputeRefundedNoRegistry(taskId, beneficiary);
        } else {
            task.status = TaskStatus.Slashed;
            _slashAndRefund(task, taskId);
            emit DisputeExpiredClaimed(taskId, task.clientRecipient);
        }
    }

    /// @notice Pull-payment: withdraw credited funds.
    function claim() external nonReentrant {
        uint256 amount = claimable[msg.sender];
        if (amount == 0) revert ZeroValue();
        claimable[msg.sender] = 0;
        _transferETH(msg.sender, amount);
        emit Claimed(msg.sender, amount);
    }

    // --- Admin ---

    function setDisputePeriod(uint256 newPeriod) external onlyOwner {
        if (newPeriod > MAX_DISPUTE_PERIOD) revert InvalidParameter();
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
        return _agentTasks[agentId];
    }

    function requestHash(uint256 taskId) external view returns (bytes32) {
        Task storage task = tasks[taskId];
        return _requestHash(
            taskId, task.agentId, task.client, task.agentRecipient, task.clientRecipient, task.payment, task.taskHash
        );
    }

    function domainSeparator() external view returns (bytes32) {
        return _domainSeparator();
    }

    // --- Internal ---

    function _authorizeUpgrade(address) internal override onlyOwner {}

    function _verifyTaskPermit(
        uint256 agentId,
        address signer,
        address client_,
        address agentRecipient_,
        address clientRecipient_,
        address committedValidator_,
        uint256 payment,
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
                payment,
                deadline,
                taskHash_,
                nonce
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));
        if (!SignatureChecker.isValidSignatureNow(signer, digest, sig)) revert InvalidSignature();
        agentNonces[agentId] = nonce + 1;
    }

    function _domainSeparator() internal view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, block.chainid, address(this)));
    }

    function _unlockBond(uint256 agentId, uint256 amount) internal {
        bonds[agentId].locked -= amount;
    }

    function _slashAndRefund(Task storage task, uint256 taskId) internal {
        uint256 slashAmount = (task.payment * task.snapshotSlashBps) / 10_000;
        if (slashAmount > task.bondLocked) slashAmount = task.bondLocked;

        Bond storage bond = bonds[task.agentId];
        bond.amount -= slashAmount;
        bond.locked -= task.bondLocked;

        _credit(task.clientRecipient, task.payment + slashAmount);
        emit BondSlashed(task.agentId, taskId, slashAmount);
    }

    function _credit(address to, uint256 amount) internal {
        claimable[to] += amount;
        emit Credited(to, amount);
    }

    function _transferETH(address to, uint256 amount) internal {
        (bool success,) = payable(to).call{value: amount}("");
        if (!success) revert TransferFailed();
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
        uint8 p = task.snapshotValidationFinalityPolicy;
        if (p <= uint8(ValidationFinalityPolicy.AnyStatusRecord)) {
            return p;
        }
        return uint8(validationFinalityPolicy);
    }

    function _taskStatusLookupFailurePolicy(Task storage task) internal view returns (uint8) {
        uint8 p = task.snapshotStatusLookupFailurePolicy;
        if (p <= uint8(StatusLookupFailurePolicy.AlwaysUnavailable)) {
            return p;
        }
        return uint8(statusLookupFailurePolicy);
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

    uint256[47] private __gap;
}
