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

    struct Bond {
        uint256 amount;
        uint256 locked;
    }

    /// @dev Packed: client + snapshotMinPassingScore + status fit in one slot.
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
    }

    uint256 public constant MAX_DISPUTE_PERIOD = 90 days;

    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant NAME_HASH = keccak256("AgentBondManager");
    bytes32 private constant VERSION_HASH = keccak256("1");
    bytes32 private constant TASK_PERMIT_TYPEHASH = keccak256(
        "TaskPermit(uint256 agentId,address client,uint256 payment,uint256 deadline,bytes32 taskHash,uint256 nonce)"
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
    event DisputeExpiredClaimed(uint256 indexed taskId, address indexed client);
    event RegistryFailureRecorded(uint256 indexed taskId, uint256 retryAfter);
    event DisputeRefundedNoRegistry(uint256 indexed taskId, address indexed client);
    event RegistryFailureGracePeriodUpdated(uint256 oldPeriod, uint256 newPeriod);
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
    error RegistryUnavailable();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    modifier nonReentrant() {
        uint256 locked;
        assembly {
            locked := tload(0)
        }
        if (locked != 0) revert Reentrancy();
        assembly {
            tstore(0, 1)
        }
        _;
        assembly {
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
    function createTask(uint256 agentId, bytes32 taskHash, uint256 deadline, address signer, bytes calldata agentSig)
        external
        payable
        nonReentrant
        returns (uint256 taskId)
    {
        if (msg.value == 0) revert ZeroValue();
        if (deadline <= block.timestamp) revert DeadlineInPast();
        if (taskHash == bytes32(0)) revert EmptyTaskHash();

        _verifyTaskPermit(agentId, signer, msg.sender, msg.value, deadline, taskHash, agentSig);

        uint256 requiredBond = SCORER.getRequiredBond(agentId, msg.value);

        Bond storage bond = bonds[agentId];
        uint256 available = bond.amount - bond.locked;
        if (available < requiredBond) revert InsufficientBond();

        bond.locked += requiredBond;

        taskId = nextTaskId++;
        tasks[taskId] = Task({
            agentId: agentId,
            client: msg.sender,
            snapshotMinPassingScore: minPassingScore,
            status: TaskStatus.Active,
            payment: msg.value,
            taskHash: taskHash,
            bondLocked: requiredBond,
            deadline: deadline,
            disputedAt: 0,
            snapshotSlashBps: slashBps,
            snapshotDisputePeriod: disputePeriod,
            snapshotRegistryGracePeriod: 0
        });

        _agentTasks[agentId].push(taskId);

        bytes32 reqHash = _requestHash(taskId, agentId, msg.sender, msg.value, taskHash);
        emit TaskCreated(taskId, agentId, msg.sender, msg.value, taskHash, reqHash, requiredBond);
    }

    function completeTask(uint256 taskId) external nonReentrant {
        Task storage task = tasks[taskId];
        if (task.status != TaskStatus.Active) revert InvalidStatus();
        if (msg.sender != task.client) revert NotClient();

        task.status = TaskStatus.Completed;
        _unlockBond(task.agentId, task.bondLocked);
        _credit(_agentRecipient(task.agentId), task.payment);
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
        emit TaskDisputed(taskId, task.agentId);
    }

    /// @notice Registry revert = no response. response == 0 is a valid "fail" per ERC-8004.
    function resolveDispute(uint256 taskId) external nonReentrant {
        Task storage task = tasks[taskId];
        if (task.status != TaskStatus.Disputed) revert InvalidStatus();

        bytes32 reqHash = _requestHash(taskId, task.agentId, task.client, task.payment, task.taskHash);

        uint8 response;
        try VALIDATION_REGISTRY.getValidationStatus(reqHash) returns (
            address, uint256 validationAgentId, uint8 resp, bytes32, string memory, uint256
        ) {
            if (validationAgentId != task.agentId) revert AgentMismatch();
            response = resp;
        } catch {
            revert NoValidationResponse();
        }

        if (response >= task.snapshotMinPassingScore) {
            task.status = TaskStatus.Resolved;
            _unlockBond(task.agentId, task.bondLocked);
            _credit(_agentRecipient(task.agentId), task.payment);
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
        _credit(_agentRecipient(task.agentId), task.payment);
        emit TaskExpiredClaimed(taskId, task.agentId);
    }

    /// @notice Slashes if registry confirms no validation; refund-only after grace if registry is unavailable.
    function reclaimDisputedTask(uint256 taskId) external nonReentrant {
        Task storage task = tasks[taskId];
        if (task.status != TaskStatus.Disputed) revert InvalidStatus();
        if (block.timestamp <= task.disputedAt + task.snapshotDisputePeriod) revert DisputePeriodActive();

        bytes32 reqHash = _requestHash(taskId, task.agentId, task.client, task.payment, task.taskHash);
        bool registryFailed;
        try VALIDATION_REGISTRY.getValidationStatus(reqHash) returns (
            address, uint256 validationAgentId, uint8, bytes32, string memory, uint256
        ) {
            if (validationAgentId == task.agentId) revert ValidationExists();
        } catch {
            registryFailed = true;
        }

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
            _credit(task.client, task.payment);
            emit DisputeRefundedNoRegistry(taskId, task.client);
        } else {
            task.status = TaskStatus.Slashed;
            _slashAndRefund(task, taskId);
            emit DisputeExpiredClaimed(taskId, task.client);
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
        return _requestHash(taskId, task.agentId, task.client, task.payment, task.taskHash);
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
        uint256 payment,
        uint256 deadline,
        bytes32 taskHash_,
        bytes calldata sig
    ) internal {
        if (!IDENTITY_REGISTRY.isAuthorizedOrOwner(signer, agentId)) revert InvalidSignature();
        uint256 nonce = agentNonces[agentId]++;
        bytes32 structHash =
            keccak256(abi.encode(TASK_PERMIT_TYPEHASH, agentId, client_, payment, deadline, taskHash_, nonce));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));
        if (!SignatureChecker.isValidSignatureNow(signer, digest, sig)) revert InvalidSignature();
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

        _credit(task.client, task.payment + slashAmount);
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

    function _requestHash(uint256 taskId, uint256 agentId_, address client_, uint256 payment_, bytes32 taskHash_)
        internal
        view
        returns (bytes32)
    {
        return keccak256(abi.encode(address(this), block.chainid, taskId, agentId_, client_, payment_, taskHash_));
    }

    uint256[50] private __gap;
}
