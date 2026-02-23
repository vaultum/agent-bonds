// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {AgentBondManager} from "../src/AgentBondManager.sol";
import {ReputationScorer} from "../src/ReputationScorer.sol";
import {MockIdentityRegistry, MockReputationRegistry, MockValidationRegistry} from "./mocks/MockERC8004.sol";

contract AgentBondManagerTest is Test {
    MockIdentityRegistry identity;
    MockReputationRegistry reputation;
    MockValidationRegistry validation;
    ReputationScorer scorer;
    AgentBondManager manager;

    uint256 internal constant AGENT_OWNER_PK = 0xA11CE;
    address internal agentOwner;
    address client = makeAddr("client");
    address validator = makeAddr("validator");
    uint256 agentId;

    uint256 constant DISPUTE_PERIOD = 7 days;
    uint8 constant MIN_PASSING_SCORE = 50;
    uint256 constant SLASH_BPS = 5000;
    uint8 constant FINALITY_POLICY_RESPONSE_HASH_REQUIRED = 0;
    uint8 constant FINALITY_POLICY_ANY_STATUS_RECORD = 1;
    uint8 constant STATUS_LOOKUP_POLICY_CANONICAL_UNKNOWN_AS_MISSING = 0;
    uint8 constant STATUS_LOOKUP_POLICY_ALWAYS_MISSING = 1;
    uint8 constant STATUS_LOOKUP_POLICY_ALWAYS_UNAVAILABLE = 2;

    bytes32 private constant TASK_PERMIT_TYPEHASH = keccak256(
        "TaskPermit(uint256 agentId,address client,address agentRecipient,address clientRecipient,address committedValidator,uint256 payment,uint256 deadline,bytes32 taskHash,uint256 nonce)"
    );

    event DisputeExpiredClaimed(uint256 indexed taskId, address indexed beneficiary);
    event DisputeRefundedNoRegistry(uint256 indexed taskId, address indexed beneficiary);

    function setUp() public {
        agentOwner = vm.addr(AGENT_OWNER_PK);

        identity = new MockIdentityRegistry();
        reputation = new MockReputationRegistry();
        validation = new MockValidationRegistry();

        vm.prank(agentOwner);
        agentId = identity.register(agentOwner);

        ReputationScorer scorerImpl = new ReputationScorer();
        ERC1967Proxy scorerProxy = new ERC1967Proxy(
            address(scorerImpl),
            abi.encodeCall(ReputationScorer.initialize, (address(reputation), address(validation), "starred", 100))
        );
        scorer = ReputationScorer(address(scorerProxy));

        AgentBondManager managerImpl = new AgentBondManager();
        ERC1967Proxy managerProxy = new ERC1967Proxy(
            address(managerImpl),
            abi.encodeCall(
                AgentBondManager.initialize,
                (address(identity), address(validation), address(scorer), DISPUTE_PERIOD, MIN_PASSING_SCORE, SLASH_BPS)
            )
        );
        manager = AgentBondManager(payable(address(managerProxy)));

        vm.deal(agentOwner, 100 ether);
        vm.deal(client, 100 ether);
    }

    // --- Helpers ---

    function _signPermit(
        uint256 agentId_,
        address client_,
        address agentRecipient_,
        address clientRecipient_,
        address committedValidator_,
        uint256 payment,
        uint256 deadline,
        bytes32 taskHash_,
        uint256 nonce
    ) internal view returns (bytes memory) {
        bytes32 structHash = keccak256(
            abi.encode(
                TASK_PERMIT_TYPEHASH,
                agentId_,
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
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", manager.domainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(AGENT_OWNER_PK, digest);
        return abi.encodePacked(r, s, v);
    }

    function _createTask(bytes32 taskHash, uint256 deadline, uint256 payment) internal returns (uint256) {
        return _createTaskWithRecipients(taskHash, deadline, payment, agentOwner, client);
    }

    function _createTaskWithRecipients(
        bytes32 taskHash,
        uint256 deadline,
        uint256 payment,
        address agentRecipient_,
        address clientRecipient_
    ) internal returns (uint256) {
        return _createTaskWithRecipientsAndValidator(
            taskHash, deadline, payment, agentRecipient_, clientRecipient_, validator
        );
    }

    function _createTaskWithRecipientsAndValidator(
        bytes32 taskHash,
        uint256 deadline,
        uint256 payment,
        address agentRecipient_,
        address clientRecipient_,
        address committedValidator_
    ) internal returns (uint256) {
        uint256 nonce = manager.agentNonces(agentId);
        bytes memory sig = _signPermit(
            agentId, client, agentRecipient_, clientRecipient_, committedValidator_, payment, deadline, taskHash, nonce
        );
        vm.prank(client);
        return manager.createTask{value: payment}(
            agentId, taskHash, deadline, agentOwner, agentRecipient_, clientRecipient_, committedValidator_, sig
        );
    }

    // --- Bond Tests ---

    function test_depositBond() public {
        vm.prank(agentOwner);
        manager.depositBond{value: 10 ether}(agentId);

        (uint256 amount, uint256 locked) = manager.getBond(agentId);
        assertEq(amount, 10 ether);
        assertEq(locked, 0);
    }

    function test_depositBond_revertsForNonOwner() public {
        vm.prank(client);
        vm.expectRevert(AgentBondManager.NotAgentOwner.selector);
        manager.depositBond{value: 10 ether}(agentId);
    }

    function test_depositBond_revertsForZeroValue() public {
        vm.prank(agentOwner);
        vm.expectRevert(AgentBondManager.ZeroValue.selector);
        manager.depositBond{value: 0}(agentId);
    }

    function test_withdrawBond() public {
        vm.prank(agentOwner);
        manager.depositBond{value: 10 ether}(agentId);

        uint256 balanceBefore = agentOwner.balance;

        vm.prank(agentOwner);
        manager.withdrawBond(agentId, 5 ether);

        (uint256 amount,) = manager.getBond(agentId);
        assertEq(amount, 5 ether);
        assertEq(agentOwner.balance, balanceBefore + 5 ether);
    }

    function test_withdrawBond_revertsIfLocked() public {
        vm.prank(agentOwner);
        manager.depositBond{value: 10 ether}(agentId);

        _createTask(keccak256("task"), block.timestamp + 1 days, 5 ether);

        vm.prank(agentOwner);
        vm.expectRevert(AgentBondManager.InsufficientBond.selector);
        manager.withdrawBond(agentId, 10 ether);
    }

    // --- Task Creation Tests ---

    function test_createTask() public {
        vm.prank(agentOwner);
        manager.depositBond{value: 10 ether}(agentId);

        uint256 taskId = _createTask(keccak256("task-spec"), block.timestamp + 1 days, 1 ether);

        AgentBondManager.Task memory task = manager.getTask(taskId);
        assertEq(task.agentId, agentId);
        assertEq(task.client, client);
        assertEq(task.payment, 1 ether);
        assertEq(task.taskHash, keccak256("task-spec"));
        assertEq(task.bondLocked, 1 ether);
        assertEq(task.snapshotMinPassingScore, MIN_PASSING_SCORE);
        assertEq(task.snapshotSlashBps, SLASH_BPS);
        assertEq(task.snapshotDisputePeriod, DISPUTE_PERIOD);
        assertEq(task.committedValidator, validator);
        assertTrue(task.status == AgentBondManager.TaskStatus.Active);
    }

    function test_createTask_storesCustomRecipients() public {
        vm.prank(agentOwner);
        manager.depositBond{value: 10 ether}(agentId);

        address agentRecipient_ = makeAddr("agent-recipient");
        address clientRecipient_ = makeAddr("client-recipient");
        uint256 taskId = _createTaskWithRecipients(
            keccak256("task-custom-recipient"), block.timestamp + 1 days, 1 ether, agentRecipient_, clientRecipient_
        );

        AgentBondManager.Task memory task = manager.getTask(taskId);
        assertEq(task.agentRecipient, agentRecipient_);
        assertEq(task.clientRecipient, clientRecipient_);
    }

    function test_createTask_revertsWhenPermitRecipientsDoNotMatchCall() public {
        vm.prank(agentOwner);
        manager.depositBond{value: 10 ether}(agentId);

        address permittedAgentRecipient = makeAddr("permitted-agent-recipient");
        address permittedClientRecipient = makeAddr("permitted-client-recipient");

        bytes32 taskHash = keccak256("recipient-mismatch");
        uint256 deadline = block.timestamp + 1 days;
        uint256 nonce = manager.agentNonces(agentId);
        bytes memory sig = _signPermit(
            agentId,
            client,
            permittedAgentRecipient,
            permittedClientRecipient,
            validator,
            1 ether,
            deadline,
            taskHash,
            nonce
        );

        vm.prank(client);
        vm.expectRevert(AgentBondManager.InvalidSignature.selector);
        manager.createTask{value: 1 ether}(
            agentId,
            taskHash,
            deadline,
            agentOwner,
            permittedAgentRecipient,
            makeAddr("different-client-recipient"),
            validator,
            sig
        );
    }

    function test_createTask_revertsForInvalidSignature() public {
        vm.prank(agentOwner);
        manager.depositBond{value: 10 ether}(agentId);

        // Sign with wrong private key
        bytes32 taskHash = keccak256("task");
        uint256 deadline = block.timestamp + 1 days;
        uint256 nonce = manager.agentNonces(agentId);
        bytes32 structHash = keccak256(
            abi.encode(
                TASK_PERMIT_TYPEHASH, agentId, client, agentOwner, client, validator, 1 ether, deadline, taskHash, nonce
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", manager.domainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(0xDEAD, digest);
        bytes memory badSig = abi.encodePacked(r, s, v);

        vm.prank(client);
        vm.expectRevert(AgentBondManager.InvalidSignature.selector);
        manager.createTask{value: 1 ether}(
            agentId, taskHash, deadline, agentOwner, agentOwner, client, validator, badSig
        );

        assertEq(manager.agentNonces(agentId), nonce);
    }

    function test_createTask_revertsForZeroRecipient() public {
        vm.prank(agentOwner);
        manager.depositBond{value: 10 ether}(agentId);

        vm.prank(client);
        vm.expectRevert(AgentBondManager.ZeroAddress.selector);
        manager.createTask{value: 1 ether}(
            agentId,
            keccak256("zero-recipient"),
            block.timestamp + 1 days,
            agentOwner,
            address(0),
            client,
            validator,
            hex""
        );
    }

    function test_createTask_revertsForZeroCommittedValidator() public {
        vm.prank(agentOwner);
        manager.depositBond{value: 10 ether}(agentId);

        uint256 nonce = manager.agentNonces(agentId);
        bytes memory sig = _signPermit(
            agentId,
            client,
            agentOwner,
            client,
            address(0),
            1 ether,
            block.timestamp + 1 days,
            keccak256("zero-validator"),
            nonce
        );

        vm.prank(client);
        vm.expectRevert(AgentBondManager.ZeroAddress.selector);
        manager.createTask{value: 1 ether}(
            agentId,
            keccak256("zero-validator"),
            block.timestamp + 1 days,
            agentOwner,
            agentOwner,
            client,
            address(0),
            sig
        );
    }

    function test_createTask_nonceIncrementsPerTask() public {
        vm.prank(agentOwner);
        manager.depositBond{value: 10 ether}(agentId);

        assertEq(manager.agentNonces(agentId), 0);
        _createTask(keccak256("t1"), block.timestamp + 1 days, 1 ether);
        assertEq(manager.agentNonces(agentId), 1);
        _createTask(keccak256("t2"), block.timestamp + 1 days, 1 ether);
        assertEq(manager.agentNonces(agentId), 2);
    }

    function test_createTask_revertsIfInsufficientBond() public {
        uint256 nonce = manager.agentNonces(agentId);
        bytes memory sig = _signPermit(
            agentId, client, agentOwner, client, validator, 1 ether, block.timestamp + 1 days, keccak256("task"), nonce
        );

        vm.prank(client);
        vm.expectRevert(AgentBondManager.InsufficientBond.selector);
        manager.createTask{value: 1 ether}(
            agentId, keccak256("task"), block.timestamp + 1 days, agentOwner, agentOwner, client, validator, sig
        );
    }

    function test_createTask_revertsForPastDeadline() public {
        vm.prank(agentOwner);
        manager.depositBond{value: 10 ether}(agentId);

        uint256 nonce = manager.agentNonces(agentId);
        bytes memory sig = _signPermit(
            agentId, client, agentOwner, client, validator, 1 ether, block.timestamp - 1, keccak256("task"), nonce
        );

        vm.prank(client);
        vm.expectRevert(AgentBondManager.DeadlineInPast.selector);
        manager.createTask{value: 1 ether}(
            agentId, keccak256("task"), block.timestamp - 1, agentOwner, agentOwner, client, validator, sig
        );
    }

    // --- Complete Task Tests ---

    function test_completeTask() public {
        vm.prank(agentOwner);
        manager.depositBond{value: 10 ether}(agentId);

        uint256 taskId = _createTask(keccak256("task"), block.timestamp + 1 days, 1 ether);

        vm.prank(client);
        manager.completeTask(taskId);

        AgentBondManager.Task memory task = manager.getTask(taskId);
        assertTrue(task.status == AgentBondManager.TaskStatus.Completed);
        assertEq(manager.claimable(agentOwner), 1 ether);

        (, uint256 locked) = manager.getBond(agentId);
        assertEq(locked, 0);
    }

    function test_completeTask_creditsCustomAgentRecipient() public {
        vm.prank(agentOwner);
        manager.depositBond{value: 10 ether}(agentId);

        address agentRecipient_ = makeAddr("agent-complete-recipient");
        uint256 taskId = _createTaskWithRecipients(
            keccak256("task-agent-recipient"), block.timestamp + 1 days, 1 ether, agentRecipient_, client
        );

        vm.prank(client);
        manager.completeTask(taskId);

        assertEq(manager.claimable(agentRecipient_), 1 ether);
        assertEq(manager.claimable(agentOwner), 0);
    }

    function test_completeTask_revertsForNonClient() public {
        vm.prank(agentOwner);
        manager.depositBond{value: 10 ether}(agentId);

        uint256 taskId = _createTask(keccak256("task"), block.timestamp + 1 days, 1 ether);

        vm.prank(agentOwner);
        vm.expectRevert(AgentBondManager.NotClient.selector);
        manager.completeTask(taskId);
    }

    // --- Dispute & Resolution Tests ---

    function test_disputeAndResolve_agentWins() public {
        vm.prank(agentOwner);
        manager.depositBond{value: 10 ether}(agentId);

        uint256 taskId = _createTask(keccak256("task-deliver"), block.timestamp + 1 days, 1 ether);

        vm.prank(client);
        manager.disputeTask(taskId);

        bytes32 reqHash = manager.requestHash(taskId);
        validation.setValidation(reqHash, validator, agentId, 80, true);

        manager.resolveDispute(taskId);

        AgentBondManager.Task memory task = manager.getTask(taskId);
        assertTrue(task.status == AgentBondManager.TaskStatus.Resolved);
        assertEq(manager.claimable(agentOwner), 1 ether);

        (uint256 bondAmt, uint256 bondLocked) = manager.getBond(agentId);
        assertEq(bondAmt, 10 ether);
        assertEq(bondLocked, 0);
    }

    function test_disputeAndResolve_clientWins() public {
        vm.prank(agentOwner);
        manager.depositBond{value: 10 ether}(agentId);

        uint256 taskId = _createTask(keccak256("task-bad"), block.timestamp + 1 days, 1 ether);

        vm.prank(client);
        manager.disputeTask(taskId);

        bytes32 reqHash = manager.requestHash(taskId);
        validation.setValidation(reqHash, validator, agentId, 30, true);

        manager.resolveDispute(taskId);

        AgentBondManager.Task memory task = manager.getTask(taskId);
        assertTrue(task.status == AgentBondManager.TaskStatus.Slashed);

        uint256 expectedSlash = (1 ether * SLASH_BPS) / 10_000;
        assertEq(manager.claimable(client), 1 ether + expectedSlash);

        (uint256 bondAmt, uint256 bondLocked) = manager.getBond(agentId);
        assertEq(bondAmt, 10 ether - expectedSlash);
        assertEq(bondLocked, 0);
    }

    function test_disputeAndResolve_clientWins_creditsCustomClientRecipient() public {
        vm.prank(agentOwner);
        manager.depositBond{value: 10 ether}(agentId);

        address clientRecipient_ = makeAddr("client-slash-recipient");
        uint256 taskId = _createTaskWithRecipients(
            keccak256("task-bad-custom-recipient"), block.timestamp + 1 days, 1 ether, agentOwner, clientRecipient_
        );

        vm.prank(client);
        manager.disputeTask(taskId);

        bytes32 reqHash = manager.requestHash(taskId);
        validation.setValidation(reqHash, validator, agentId, 30, true);

        manager.resolveDispute(taskId);

        uint256 expectedSlash = (1 ether * SLASH_BPS) / 10_000;
        assertEq(manager.claimable(clientRecipient_), 1 ether + expectedSlash);
        assertEq(manager.claimable(client), 0);
    }

    function test_resolveDispute_revertsWithoutValidation() public {
        vm.prank(agentOwner);
        manager.depositBond{value: 10 ether}(agentId);

        uint256 taskId = _createTask(keccak256("unvalidated"), block.timestamp + 1 days, 1 ether);

        vm.prank(client);
        manager.disputeTask(taskId);

        vm.expectRevert(AgentBondManager.NoValidationResponse.selector);
        manager.resolveDispute(taskId);
    }

    /// @dev response == 0 is a valid "fail" → slashes (M1 fix).
    function test_resolveDispute_zeroResponseSlashes() public {
        vm.prank(agentOwner);
        manager.depositBond{value: 10 ether}(agentId);

        uint256 taskId = _createTask(keccak256("zero-response"), block.timestamp + 1 days, 1 ether);

        vm.prank(client);
        manager.disputeTask(taskId);

        bytes32 reqHash = manager.requestHash(taskId);
        validation.setValidation(reqHash, validator, agentId, 0, true);

        manager.resolveDispute(taskId);

        AgentBondManager.Task memory task = manager.getTask(taskId);
        assertTrue(task.status == AgentBondManager.TaskStatus.Slashed);
    }

    function test_resolveDispute_revertsWhenValidationPending() public {
        vm.prank(agentOwner);
        manager.depositBond{value: 10 ether}(agentId);

        uint256 taskId = _createTask(keccak256("pending-response"), block.timestamp + 1 days, 1 ether);

        vm.prank(client);
        manager.disputeTask(taskId);

        bytes32 reqHash = manager.requestHash(taskId);
        validation.setValidation(reqHash, validator, agentId, 0, false);

        vm.expectRevert(AgentBondManager.NoValidationResponse.selector);
        manager.resolveDispute(taskId);
    }

    function test_resolveDispute_pendingCanSettleWhenAnyStatusPolicy() public {
        vm.prank(agentOwner);
        manager.depositBond{value: 10 ether}(agentId);

        manager.setValidationFinalityPolicy(FINALITY_POLICY_ANY_STATUS_RECORD);

        uint256 taskId = _createTask(keccak256("pending-policy"), block.timestamp + 1 days, 1 ether);

        vm.prank(client);
        manager.disputeTask(taskId);

        bytes32 reqHash = manager.requestHash(taskId);
        validation.setValidation(reqHash, validator, agentId, 0, false);

        manager.resolveDispute(taskId);

        AgentBondManager.Task memory task = manager.getTask(taskId);
        assertTrue(task.status == AgentBondManager.TaskStatus.Slashed);
    }

    function test_resolveDispute_validationPolicySnapshottedAtDispute() public {
        vm.prank(agentOwner);
        manager.depositBond{value: 10 ether}(agentId);

        uint256 taskId = _createTask(keccak256("pending-policy-snapshot"), block.timestamp + 1 days, 1 ether);

        vm.prank(client);
        manager.disputeTask(taskId);

        manager.setValidationFinalityPolicy(FINALITY_POLICY_ANY_STATUS_RECORD);

        bytes32 reqHash = manager.requestHash(taskId);
        validation.setValidation(reqHash, validator, agentId, 0, false);

        vm.expectRevert(AgentBondManager.NoValidationResponse.selector);
        manager.resolveDispute(taskId);
    }

    function test_resolveDispute_revertsWithoutValidation_whenUnknownReverts() public {
        vm.prank(agentOwner);
        manager.depositBond{value: 10 ether}(agentId);

        uint256 taskId = _createTask(keccak256("unknown-no-validation"), block.timestamp + 1 days, 1 ether);

        vm.prank(client);
        manager.disputeTask(taskId);

        validation.setUnknownReverts(true);

        vm.expectRevert(AgentBondManager.NoValidationResponse.selector);
        manager.resolveDispute(taskId);
    }

    // --- Reclaim & Expiry Tests ---

    function test_reclaimDisputedTask() public {
        vm.prank(agentOwner);
        manager.depositBond{value: 10 ether}(agentId);

        uint256 taskId = _createTask(keccak256("abandoned"), block.timestamp + 1 days, 1 ether);

        vm.prank(client);
        manager.disputeTask(taskId);

        vm.warp(block.timestamp + DISPUTE_PERIOD + 1);
        manager.reclaimDisputedTask(taskId);

        uint256 expectedSlash = (1 ether * SLASH_BPS) / 10_000;
        assertEq(manager.claimable(client), 1 ether + expectedSlash);

        AgentBondManager.Task memory task = manager.getTask(taskId);
        assertTrue(task.status == AgentBondManager.TaskStatus.Slashed);
    }

    function test_reclaimDisputedTask_slashesWhenValidationPending() public {
        vm.prank(agentOwner);
        manager.depositBond{value: 10 ether}(agentId);

        uint256 taskId = _createTask(keccak256("pending-reclaim"), block.timestamp + 1 days, 1 ether);

        vm.prank(client);
        manager.disputeTask(taskId);

        bytes32 reqHash = manager.requestHash(taskId);
        validation.setValidation(reqHash, validator, agentId, 0, false);

        vm.warp(block.timestamp + DISPUTE_PERIOD + 1);
        manager.reclaimDisputedTask(taskId);

        AgentBondManager.Task memory task = manager.getTask(taskId);
        assertTrue(task.status == AgentBondManager.TaskStatus.Slashed);
    }

    function test_reclaimDisputedTask_unknownRevertSlashes() public {
        vm.prank(agentOwner);
        manager.depositBond{value: 10 ether}(agentId);

        address clientRecipient_ = makeAddr("client-reclaim-slash-recipient");
        uint256 taskId = _createTaskWithRecipients(
            keccak256("unknown-reclaim"), block.timestamp + 1 days, 1 ether, agentOwner, clientRecipient_
        );

        vm.prank(client);
        manager.disputeTask(taskId);

        validation.setUnknownReverts(true);
        vm.warp(block.timestamp + DISPUTE_PERIOD + 1);

        vm.expectEmit(true, true, false, false, address(manager));
        emit DisputeExpiredClaimed(taskId, clientRecipient_);
        manager.reclaimDisputedTask(taskId);

        AgentBondManager.Task memory task = manager.getTask(taskId);
        assertTrue(task.status == AgentBondManager.TaskStatus.Slashed);
        assertEq(manager.registryFailureSince(taskId), 0);
        assertEq(manager.claimable(clientRecipient_), 1.5 ether);
        assertEq(manager.claimable(client), 0);
    }

    function test_reclaimDisputedTask_statusRevertUnknownRequestSlashesByDefault() public {
        vm.prank(agentOwner);
        manager.depositBond{value: 10 ether}(agentId);

        uint256 taskId = _createTask(keccak256("status-revert-reclaim"), block.timestamp + 1 days, 1 ether);

        vm.prank(client);
        manager.disputeTask(taskId);

        validation.setForceStatusRevert(true, "custom status error");
        vm.warp(block.timestamp + DISPUTE_PERIOD + 1);

        manager.reclaimDisputedTask(taskId);

        AgentBondManager.Task memory task = manager.getTask(taskId);
        assertTrue(task.status == AgentBondManager.TaskStatus.Slashed);
        assertEq(manager.registryFailureSince(taskId), 0);
    }

    function test_reclaimDisputedTask_canonicalFailureUsesCachedRequestKnownness_knownRequest() public {
        vm.prank(agentOwner);
        manager.depositBond{value: 10 ether}(agentId);

        uint256 taskId = _createTask(keccak256("cached-known-request"), block.timestamp + 1 days, 1 ether);
        bytes32 reqHash = manager.requestHash(taskId);
        validation.setValidation(reqHash, validator, agentId, 0, false);

        vm.prank(client);
        manager.disputeTask(taskId);

        // If reclaim re-scans request knownness instead of using the dispute snapshot cache,
        // this override would flip classification to "missing" and slash.
        bytes32[] memory emptySet = new bytes32[](0);
        validation.setAgentValidationsOverride(agentId, emptySet);
        validation.setForceStatusRevert(true, "status read failed");
        vm.warp(block.timestamp + DISPUTE_PERIOD + 1);

        manager.reclaimDisputedTask(taskId);
        assertGt(manager.registryFailureSince(taskId), 0);
        assertTrue(manager.getTask(taskId).status == AgentBondManager.TaskStatus.Disputed);

        vm.warp(block.timestamp + 3 days + 1);
        manager.reclaimDisputedTask(taskId);

        AgentBondManager.Task memory task = manager.getTask(taskId);
        assertTrue(task.status == AgentBondManager.TaskStatus.Refunded);
        assertEq(manager.claimable(client), 1 ether);
    }

    function test_reclaimDisputedTask_canonicalFailureUsesCachedRequestKnownness_unknownRequest() public {
        vm.prank(agentOwner);
        manager.depositBond{value: 10 ether}(agentId);

        uint256 taskId = _createTask(keccak256("cached-unknown-request"), block.timestamp + 1 days, 1 ether);
        bytes32 reqHash = manager.requestHash(taskId);

        vm.prank(client);
        manager.disputeTask(taskId);

        // If reclaim re-scans knownness, this late override would force "known" and route to unavailable.
        bytes32[] memory knownSet = new bytes32[](1);
        knownSet[0] = reqHash;
        validation.setAgentValidationsOverride(agentId, knownSet);
        validation.setForceStatusRevert(true, "status read failed");
        vm.warp(block.timestamp + DISPUTE_PERIOD + 1);

        manager.reclaimDisputedTask(taskId);

        AgentBondManager.Task memory task = manager.getTask(taskId);
        assertTrue(task.status == AgentBondManager.TaskStatus.Slashed);
        assertEq(manager.registryFailureSince(taskId), 0);
        assertEq(manager.claimable(client), 1.5 ether);
    }

    function test_reclaimDisputedTask_statusRevertKnownRequestUnavailableByDefault() public {
        vm.prank(agentOwner);
        manager.depositBond{value: 10 ether}(agentId);

        uint256 taskId = _createTask(keccak256("status-revert-known-request"), block.timestamp + 1 days, 1 ether);
        bytes32 reqHash = manager.requestHash(taskId);
        validation.setValidation(reqHash, validator, agentId, 0, false);

        vm.prank(client);
        manager.disputeTask(taskId);

        validation.setForceStatusRevert(true, "custom status error");
        vm.warp(block.timestamp + DISPUTE_PERIOD + 1);

        manager.reclaimDisputedTask(taskId);

        assertGt(manager.registryFailureSince(taskId), 0);
        assertTrue(manager.getTask(taskId).status == AgentBondManager.TaskStatus.Disputed);
    }

    function test_reclaimDisputedTask_statusRevertSlashesWhenPolicyAlwaysMissing() public {
        vm.prank(agentOwner);
        manager.depositBond{value: 10 ether}(agentId);

        uint256 taskId = _createTask(keccak256("status-revert-missing"), block.timestamp + 1 days, 1 ether);

        vm.prank(client);
        manager.disputeTask(taskId);

        manager.setStatusLookupFailurePolicy(STATUS_LOOKUP_POLICY_ALWAYS_MISSING);
        validation.setForceStatusRevert(true, "custom status error");
        vm.warp(block.timestamp + DISPUTE_PERIOD + 1);

        manager.reclaimDisputedTask(taskId);

        AgentBondManager.Task memory task = manager.getTask(taskId);
        assertTrue(task.status == AgentBondManager.TaskStatus.Slashed);
        assertEq(manager.registryFailureSince(taskId), 0);
    }

    function test_reclaimDisputedTask_nonCanonicalPolicy_skipsKnownnessScan() public {
        vm.prank(agentOwner);
        manager.depositBond{value: 20 ether}(agentId);

        manager.setStatusLookupFailurePolicy(STATUS_LOOKUP_POLICY_ALWAYS_MISSING);
        uint256 slashTaskId = _createTask(keccak256("non-canonical-missing"), block.timestamp + 1 days, 1 ether);
        vm.prank(client);
        manager.disputeTask(slashTaskId);

        manager.setStatusLookupFailurePolicy(STATUS_LOOKUP_POLICY_ALWAYS_UNAVAILABLE);
        uint256 unavailableTaskId =
            _createTask(keccak256("non-canonical-unavailable"), block.timestamp + 1 days, 1 ether);
        vm.prank(client);
        manager.disputeTask(unavailableTaskId);

        // Both status and knownness lookup paths fail under forceRevert.
        // Non-canonical policies must still route deterministically without knownness scanning.
        validation.setForceRevert(true);
        vm.warp(block.timestamp + DISPUTE_PERIOD + 1);

        manager.reclaimDisputedTask(slashTaskId);
        AgentBondManager.Task memory slashTask = manager.getTask(slashTaskId);
        assertTrue(slashTask.status == AgentBondManager.TaskStatus.Slashed);
        assertEq(manager.registryFailureSince(slashTaskId), 0);

        manager.reclaimDisputedTask(unavailableTaskId);
        AgentBondManager.Task memory unavailableTask = manager.getTask(unavailableTaskId);
        assertTrue(unavailableTask.status == AgentBondManager.TaskStatus.Disputed);
        assertGt(manager.registryFailureSince(unavailableTaskId), 0);
    }

    function test_reclaimDisputedTask_canonicalFailureUnsupportedStateIsCached() public {
        vm.prank(agentOwner);
        manager.depositBond{value: 10 ether}(agentId);

        uint256 taskId = _createTask(keccak256("unsupported-request-state"), block.timestamp + 1 days, 1 ether);

        // Canonical cache cannot be populated if getAgentValidations reverts, so we record unsupported.
        validation.setForceRevert(true);
        vm.prank(client);
        manager.disputeTask(taskId);

        validation.setForceStatusRevert(true, "status read failed");
        vm.warp(block.timestamp + DISPUTE_PERIOD + 1);

        // First reclaim: records first failure and stays disputed.
        manager.reclaimDisputedTask(taskId);
        assertGt(manager.registryFailureSince(taskId), 0);
        assertTrue(manager.getTask(taskId).status == AgentBondManager.TaskStatus.Disputed);

        // If reclaim rescans request-knowwness, this mutable override should force slash.
        bytes32[] memory emptySet = new bytes32[](0);
        validation.setAgentValidationsOverride(agentId, emptySet);
        validation.setForceRevert(false);

        vm.warp(block.timestamp + 3 days + 1);
        manager.reclaimDisputedTask(taskId);

        assertTrue(manager.getTask(taskId).status == AgentBondManager.TaskStatus.Refunded);
    }

    function test_reclaimDisputedTask_canonicalFailureExceedsScanCapIsUnsupported() public {
        vm.prank(agentOwner);
        manager.depositBond{value: 10 ether}(agentId);

        uint256 taskId = _createTask(keccak256("scan-cap-request"), block.timestamp + 1 days, 1 ether);
        bytes32 reqHash = manager.requestHash(taskId);

        bytes32[] memory requestHashes = new bytes32[](513);
        for (uint256 i; i < requestHashes.length; i++) {
            requestHashes[i] = keccak256(abi.encode(i));
        }
        requestHashes[requestHashes.length - 1] = reqHash;
        validation.setAgentValidationsOverride(agentId, requestHashes);

        vm.prank(client);
        manager.disputeTask(taskId);

        validation.setForceStatusRevert(true, "status read failed");
        vm.warp(block.timestamp + DISPUTE_PERIOD + 1);

        manager.reclaimDisputedTask(taskId);
        assertTrue(manager.getTask(taskId).status == AgentBondManager.TaskStatus.Disputed);
        assertGt(manager.registryFailureSince(taskId), 0);

        vm.warp(block.timestamp + 3 days + 1);
        manager.reclaimDisputedTask(taskId);
        assertTrue(manager.getTask(taskId).status == AgentBondManager.TaskStatus.Refunded);
    }

    function test_reclaimDisputedTask_statusPolicySnapshottedAtDispute() public {
        vm.prank(agentOwner);
        manager.depositBond{value: 10 ether}(agentId);

        manager.setStatusLookupFailurePolicy(STATUS_LOOKUP_POLICY_ALWAYS_UNAVAILABLE);
        uint256 taskId = _createTask(keccak256("status-policy-snapshot"), block.timestamp + 1 days, 1 ether);

        vm.prank(client);
        manager.disputeTask(taskId);

        manager.setStatusLookupFailurePolicy(STATUS_LOOKUP_POLICY_ALWAYS_MISSING);
        validation.setForceStatusRevert(true, "status-read-failure");
        vm.warp(block.timestamp + DISPUTE_PERIOD + 1);

        manager.reclaimDisputedTask(taskId);

        assertGt(manager.registryFailureSince(taskId), 0);
        assertTrue(manager.getTask(taskId).status == AgentBondManager.TaskStatus.Disputed);
    }

    /// @dev If a validator responded, reclaim must fail (H2 fix).
    function test_reclaimDisputedTask_revertsIfValidationExists() public {
        vm.prank(agentOwner);
        manager.depositBond{value: 10 ether}(agentId);

        uint256 taskId = _createTask(keccak256("validated"), block.timestamp + 1 days, 1 ether);

        vm.prank(client);
        manager.disputeTask(taskId);

        bytes32 reqHash = manager.requestHash(taskId);
        validation.setValidation(reqHash, validator, agentId, 80, true);

        vm.warp(block.timestamp + DISPUTE_PERIOD + 1);

        vm.expectRevert(AgentBondManager.ValidationExists.selector);
        manager.reclaimDisputedTask(taskId);
    }

    function test_reclaimDisputedTask_revertsIfPeriodActive() public {
        vm.prank(agentOwner);
        manager.depositBond{value: 10 ether}(agentId);

        uint256 taskId = _createTask(keccak256("task"), block.timestamp + 1 days, 1 ether);

        vm.prank(client);
        manager.disputeTask(taskId);

        vm.expectRevert(AgentBondManager.DisputePeriodActive.selector);
        manager.reclaimDisputedTask(taskId);
    }

    function test_claimExpiredTask() public {
        vm.prank(agentOwner);
        manager.depositBond{value: 10 ether}(agentId);

        uint256 taskId = _createTask(keccak256("task"), block.timestamp + 1 days, 1 ether);

        vm.warp(block.timestamp + 1 days + 1);
        manager.claimExpiredTask(taskId);

        assertEq(manager.claimable(agentOwner), 1 ether);

        AgentBondManager.Task memory task = manager.getTask(taskId);
        assertTrue(task.status == AgentBondManager.TaskStatus.Expired);
    }

    function test_claimExpiredTask_revertsBeforeDeadline() public {
        vm.prank(agentOwner);
        manager.depositBond{value: 10 ether}(agentId);

        uint256 taskId = _createTask(keccak256("task"), block.timestamp + 1 days, 1 ether);

        vm.expectRevert(AgentBondManager.NotExpired.selector);
        manager.claimExpiredTask(taskId);
    }

    function test_disputeTask_revertsAfterDeadline() public {
        vm.prank(agentOwner);
        manager.depositBond{value: 10 ether}(agentId);

        uint256 taskId = _createTask(keccak256("task"), block.timestamp + 1 days, 1 ether);

        vm.warp(block.timestamp + 1 days + 1);

        vm.prank(client);
        vm.expectRevert(AgentBondManager.DeadlinePassed.selector);
        manager.disputeTask(taskId);
    }

    // --- Pull Payment Tests ---

    function test_claim() public {
        vm.prank(agentOwner);
        manager.depositBond{value: 10 ether}(agentId);

        uint256 taskId = _createTask(keccak256("task"), block.timestamp + 1 days, 2 ether);

        vm.prank(client);
        manager.completeTask(taskId);

        assertEq(manager.claimable(agentOwner), 2 ether);

        uint256 balBefore = agentOwner.balance;
        vm.prank(agentOwner);
        manager.claim();

        assertEq(agentOwner.balance, balBefore + 2 ether);
        assertEq(manager.claimable(agentOwner), 0);
    }

    function test_claim_revertsForZeroBalance() public {
        vm.prank(agentOwner);
        vm.expectRevert(AgentBondManager.ZeroValue.selector);
        manager.claim();
    }

    // --- Snapshot Tests (H3) ---

    function test_snapshotPreservation() public {
        vm.prank(agentOwner);
        manager.depositBond{value: 10 ether}(agentId);

        uint256 taskId = _createTask(keccak256("snapshot"), block.timestamp + 1 days, 1 ether);

        // Change global params after task creation
        manager.setSlashBps(10_000);
        manager.setMinPassingScore(99);
        manager.setDisputePeriod(1);

        AgentBondManager.Task memory task = manager.getTask(taskId);
        assertEq(task.snapshotSlashBps, SLASH_BPS);
        assertEq(task.snapshotMinPassingScore, MIN_PASSING_SCORE);
        assertEq(task.snapshotDisputePeriod, DISPUTE_PERIOD);
    }

    function test_snapshotSlashBps_usedInSlash() public {
        vm.prank(agentOwner);
        manager.depositBond{value: 10 ether}(agentId);

        uint256 taskId = _createTask(keccak256("slash-snap"), block.timestamp + 1 days, 1 ether);

        // Double global slashBps after task creation
        manager.setSlashBps(10_000);

        vm.prank(client);
        manager.disputeTask(taskId);

        bytes32 reqHash = manager.requestHash(taskId);
        validation.setValidation(reqHash, validator, agentId, 30, true);
        manager.resolveDispute(taskId);

        // Slash uses the snapshot (5000), not the new global (10000)
        uint256 expectedSlash = (1 ether * SLASH_BPS) / 10_000;
        assertEq(manager.claimable(client), 1 ether + expectedSlash);
    }

    function test_snapshotMinPassingScore_usedInResolve() public {
        vm.prank(agentOwner);
        manager.depositBond{value: 10 ether}(agentId);

        uint256 taskId = _createTask(keccak256("mps-snap"), block.timestamp + 1 days, 1 ether);

        // Lower global minPassingScore below the validation response
        manager.setMinPassingScore(10);

        vm.prank(client);
        manager.disputeTask(taskId);

        // Response is 30, snapshot minPassingScore is 50 → slash
        bytes32 reqHash = manager.requestHash(taskId);
        validation.setValidation(reqHash, validator, agentId, 30, true);
        manager.resolveDispute(taskId);

        AgentBondManager.Task memory task = manager.getTask(taskId);
        assertTrue(task.status == AgentBondManager.TaskStatus.Slashed);
    }

    // --- Scorer Tests ---

    function test_noReputation_requiresFullBond() public view {
        assertEq(scorer.getRequiredBond(agentId, 1 ether), 1 ether);
    }

    function test_highReputation_lowersBond() public {
        address reviewer = makeAddr("reviewer");
        reputation.setFeedback(agentId, reviewer, 90, 0, "starred", "");
        scorer.addTrustedReviewer(reviewer);

        assertLt(scorer.getRequiredBond(agentId, 1 ether), 1 ether);
    }

    function test_perfectReputation_minimumBond() public {
        address reviewer = makeAddr("reviewer");
        reputation.setFeedback(agentId, reviewer, 100, 0, "starred", "");
        scorer.addTrustedReviewer(reviewer);

        assertEq(scorer.getRequiredBond(agentId, 10 ether), 0.5 ether);
    }

    function test_reputedAgent_locksSmallerBond() public {
        address reviewer = makeAddr("reviewer");
        reputation.setFeedback(agentId, reviewer, 100, 0, "starred", "");
        scorer.addTrustedReviewer(reviewer);

        vm.prank(agentOwner);
        manager.depositBond{value: 1 ether}(agentId);

        uint256 taskId = _createTask(keccak256("big-task"), block.timestamp + 1 days, 10 ether);

        AgentBondManager.Task memory task = manager.getTask(taskId);
        assertEq(task.bondLocked, 0.5 ether);

        (, uint256 locked) = manager.getBond(agentId);
        assertEq(locked, 0.5 ether);
    }

    function test_scorer_combinesReputationAndValidation() public {
        address reviewer = makeAddr("reviewer");
        reputation.setFeedback(agentId, reviewer, 80, 0, "starred", "");
        scorer.addTrustedReviewer(reviewer);
        scorer.addTrustedValidator(validator);
        validation.setValidation(keccak256("v1"), validator, agentId, 90, true);

        (uint256 score, uint64 count) = scorer.getScore(agentId);
        assertEq(count, 2);
        assertEq(score, 8300);
    }

    function test_scorer_reputationOnly() public {
        address reviewer = makeAddr("reviewer");
        reputation.setFeedback(agentId, reviewer, 75, 0, "starred", "");
        scorer.addTrustedReviewer(reviewer);

        (uint256 score, uint64 count) = scorer.getScore(agentId);
        assertEq(count, 1);
        assertEq(score, 7500);
    }

    function test_scorer_validationOnly() public {
        scorer.addTrustedValidator(validator);
        validation.setValidation(keccak256("v1"), validator, agentId, 60, true);

        (uint256 score, uint64 count) = scorer.getScore(agentId);
        assertEq(count, 1);
        assertEq(score, 6000);
    }

    function test_scorer_noTrustedValidators_returnsZero() public {
        validation.setValidation(keccak256("v1"), validator, agentId, 90, true);

        (uint256 score, uint64 count) = scorer.getScore(agentId);
        assertEq(score, 0);
        assertEq(count, 0);
    }

    function test_scorer_noData_zeroScore() public view {
        (uint256 score, uint64 count) = scorer.getScore(agentId);
        assertEq(score, 0);
        assertEq(count, 0);
    }

    function test_scorer_setWeights_bounded() public {
        vm.expectRevert(ReputationScorer.InvalidWeights.selector);
        scorer.setWeights(10_001, 1);

        vm.expectRevert(ReputationScorer.InvalidWeights.selector);
        scorer.setWeights(1, 10_001);

        scorer.setWeights(10_000, 10_000);
        assertEq(scorer.reputationWeight(), 10_000);
        assertEq(scorer.validationWeight(), 10_000);
    }

    // --- Multi-task Tests ---

    function test_multipleTasks_lockCumulatively() public {
        vm.prank(agentOwner);
        manager.depositBond{value: 10 ether}(agentId);

        _createTask(keccak256("t1"), block.timestamp + 1 days, 3 ether);
        _createTask(keccak256("t2"), block.timestamp + 1 days, 2 ether);

        (, uint256 locked) = manager.getBond(agentId);
        assertEq(locked, 5 ether);
        assertEq(manager.availableBond(agentId), 5 ether);
    }

    function test_multipleTasks_independentResolution() public {
        vm.prank(agentOwner);
        manager.depositBond{value: 10 ether}(agentId);

        uint256 id1 = _createTask(keccak256("t1"), block.timestamp + 1 days, 2 ether);
        uint256 id2 = _createTask(keccak256("t2"), block.timestamp + 1 days, 3 ether);

        vm.prank(client);
        manager.completeTask(id1);

        vm.prank(client);
        manager.disputeTask(id2);

        validation.setValidation(manager.requestHash(id2), validator, agentId, 75, true);
        manager.resolveDispute(id2);

        (, uint256 locked) = manager.getBond(agentId);
        assertEq(locked, 0);
        (uint256 amt,) = manager.getBond(agentId);
        assertEq(amt, 10 ether);
    }

    function test_sameTaskHash_differentRequestHash_cannotReuse() public {
        vm.prank(agentOwner);
        manager.depositBond{value: 20 ether}(agentId);

        bytes32 sharedHash = keccak256("same-spec");

        uint256 id1 = _createTask(sharedHash, block.timestamp + 1 days, 1 ether);
        uint256 id2 = _createTask(sharedHash, block.timestamp + 1 days, 5 ether);

        bytes32 req1 = manager.requestHash(id1);
        bytes32 req2 = manager.requestHash(id2);
        assertTrue(req1 != req2);

        vm.startPrank(client);
        manager.disputeTask(id1);
        manager.disputeTask(id2);
        vm.stopPrank();

        validation.setValidation(req1, validator, agentId, 80, true);
        manager.resolveDispute(id1);

        vm.expectRevert(AgentBondManager.NoValidationResponse.selector);
        manager.resolveDispute(id2);

        assertTrue(manager.getTask(id2).status == AgentBondManager.TaskStatus.Disputed);
    }

    function test_identicalTaskParams_differentRequestHash() public {
        vm.prank(agentOwner);
        manager.depositBond{value: 20 ether}(agentId);

        bytes32 taskHash = keccak256("repeated-job");

        uint256 id1 = _createTask(taskHash, block.timestamp + 1 days, 1 ether);
        uint256 id2 = _createTask(taskHash, block.timestamp + 1 days, 1 ether);

        assertTrue(manager.requestHash(id1) != manager.requestHash(id2));
    }

    // --- UUPS Tests ---

    function test_cannotReinitialize() public {
        vm.expectRevert();
        manager.initialize(
            address(identity), address(validation), address(scorer), DISPUTE_PERIOD, MIN_PASSING_SCORE, SLASH_BPS
        );
    }

    function test_cannotReinitializeScorer() public {
        vm.expectRevert();
        scorer.initialize(address(reputation), address(validation), "starred", 100);
    }

    function test_upgradeOnlyOwner() public {
        AgentBondManager newImpl = new AgentBondManager();

        vm.prank(client);
        vm.expectRevert(AgentBondManager.NotOwner.selector);
        manager.upgradeToAndCall(address(newImpl), "");
    }

    function test_ownerCanUpgrade() public {
        AgentBondManager newImpl = new AgentBondManager();
        manager.upgradeToAndCall(address(newImpl), "");

        assertEq(manager.disputePeriod(), DISPUTE_PERIOD);
    }

    // --- Admin Validation ---

    function test_setMinPassingScore_rejectsZero() public {
        vm.expectRevert(AgentBondManager.InvalidParameter.selector);
        manager.setMinPassingScore(0);
    }

    function test_setMinPassingScore_rejectsAbove100() public {
        vm.expectRevert(AgentBondManager.InvalidParameter.selector);
        manager.setMinPassingScore(101);
    }

    function test_setDisputePeriod_rejectsAboveMax() public {
        vm.expectRevert(AgentBondManager.InvalidParameter.selector);
        manager.setDisputePeriod(91 days);
    }

    function test_setDisputePeriod_acceptsMax() public {
        manager.setDisputePeriod(90 days);
        assertEq(manager.disputePeriod(), 90 days);
    }

    function test_setRegistryFailureGracePeriod_rejectsAboveMax() public {
        vm.expectRevert(AgentBondManager.InvalidParameter.selector);
        manager.setRegistryFailureGracePeriod(91 days);
    }

    function test_setRegistryFailureGracePeriod_acceptsMax() public {
        manager.setRegistryFailureGracePeriod(90 days);
        assertEq(manager.registryFailureGracePeriod(), 90 days);
    }

    function test_setRegistryFailureGracePeriod_acceptsZero() public {
        manager.setRegistryFailureGracePeriod(0);
        assertEq(manager.registryFailureGracePeriod(), 0);
    }

    function test_setValidationFinalityPolicy_acceptsValues() public {
        manager.setValidationFinalityPolicy(FINALITY_POLICY_ANY_STATUS_RECORD);
        assertEq(uint8(manager.validationFinalityPolicy()), FINALITY_POLICY_ANY_STATUS_RECORD);
        manager.setValidationFinalityPolicy(FINALITY_POLICY_RESPONSE_HASH_REQUIRED);
        assertEq(uint8(manager.validationFinalityPolicy()), FINALITY_POLICY_RESPONSE_HASH_REQUIRED);
    }

    function test_setValidationFinalityPolicy_rejectsInvalid() public {
        vm.expectRevert(AgentBondManager.InvalidParameter.selector);
        manager.setValidationFinalityPolicy(2);
    }

    function test_setStatusLookupFailurePolicy_acceptsValues() public {
        manager.setStatusLookupFailurePolicy(STATUS_LOOKUP_POLICY_CANONICAL_UNKNOWN_AS_MISSING);
        assertEq(uint8(manager.statusLookupFailurePolicy()), STATUS_LOOKUP_POLICY_CANONICAL_UNKNOWN_AS_MISSING);
        manager.setStatusLookupFailurePolicy(STATUS_LOOKUP_POLICY_ALWAYS_MISSING);
        assertEq(uint8(manager.statusLookupFailurePolicy()), STATUS_LOOKUP_POLICY_ALWAYS_MISSING);
        manager.setStatusLookupFailurePolicy(STATUS_LOOKUP_POLICY_ALWAYS_UNAVAILABLE);
        assertEq(uint8(manager.statusLookupFailurePolicy()), STATUS_LOOKUP_POLICY_ALWAYS_UNAVAILABLE);
    }

    function test_setStatusLookupFailurePolicy_rejectsInvalid() public {
        vm.expectRevert(AgentBondManager.InvalidParameter.selector);
        manager.setStatusLookupFailurePolicy(3);
    }

    // --- P1: Unbounded reviewer set removal ---

    function test_scorer_noTrustedReviewers_returnsZero() public {
        address reviewer = makeAddr("reviewer");
        reputation.setFeedback(agentId, reviewer, 90, 0, "starred", "");

        (uint256 score, uint64 count) = scorer.getScore(agentId);
        assertEq(score, 0);
        assertEq(count, 0);
        assertEq(scorer.getRequiredBond(agentId, 1 ether), 1 ether);
    }

    // --- P2a: Decimals overflow ---

    function test_scorer_largeDecimals_doesNotRevert() public {
        address reviewer = makeAddr("reviewer");
        reputation.setFeedback(agentId, reviewer, 90, 0, "starred", "");
        reputation.setSummaryDecimals(agentId, 255);
        scorer.addTrustedReviewer(reviewer);

        (uint256 score, uint64 count) = scorer.getScore(agentId);
        assertEq(score, 0);
        assertEq(count, 1);
        assertEq(scorer.getRequiredBond(agentId, 1 ether), 1 ether);
    }

    function test_scorer_hugeMaxExpectedValue_doesNotRevert() public {
        ReputationScorer scorerImpl = new ReputationScorer();
        ERC1967Proxy scorerProxy = new ERC1967Proxy(
            address(scorerImpl),
            abi.encodeCall(
                ReputationScorer.initialize, (address(reputation), address(validation), "starred", type(uint256).max)
            )
        );
        ReputationScorer overflowScorer = ReputationScorer(address(scorerProxy));

        address reviewer = makeAddr("reviewer-huge-max");
        reputation.setFeedback(agentId, reviewer, 1, 0, "starred", "");
        reputation.setSummaryDecimals(agentId, 18);
        overflowScorer.addTrustedReviewer(reviewer);

        (uint256 score, uint64 count) = overflowScorer.getScore(agentId);
        assertEq(score, 0);
        assertEq(count, 1);
        assertEq(overflowScorer.getRequiredBond(agentId, 1 ether), 1 ether);
    }

    // --- P2b: Mismatched agentId liveness lock ---

    function test_reclaimDisputedTask_succeedsWithMismatchedAgentId() public {
        vm.prank(agentOwner);
        manager.depositBond{value: 10 ether}(agentId);

        uint256 taskId = _createTask(keccak256("mismatch"), block.timestamp + 1 days, 1 ether);

        vm.prank(client);
        manager.disputeTask(taskId);

        bytes32 reqHash = manager.requestHash(taskId);
        validation.setValidation(reqHash, validator, agentId + 1, 80, true);

        vm.warp(block.timestamp + DISPUTE_PERIOD + 1);
        manager.reclaimDisputedTask(taskId);

        AgentBondManager.Task memory task = manager.getTask(taskId);
        assertTrue(task.status == AgentBondManager.TaskStatus.Slashed);
    }

    function test_resolveDispute_revertsOnMismatchedAgentId() public {
        vm.prank(agentOwner);
        manager.depositBond{value: 10 ether}(agentId);

        uint256 taskId = _createTask(keccak256("mismatch-resolve"), block.timestamp + 1 days, 1 ether);

        vm.prank(client);
        manager.disputeTask(taskId);

        bytes32 reqHash = manager.requestHash(taskId);
        validation.setValidation(reqHash, validator, agentId + 1, 80, true);

        vm.expectRevert(AgentBondManager.AgentMismatch.selector);
        manager.resolveDispute(taskId);
    }

    function test_resolveDispute_revertsOnValidatorMismatch() public {
        vm.prank(agentOwner);
        manager.depositBond{value: 10 ether}(agentId);

        uint256 taskId = _createTask(keccak256("validator-mismatch-resolve"), block.timestamp + 1 days, 1 ether);

        vm.prank(client);
        manager.disputeTask(taskId);

        bytes32 reqHash = manager.requestHash(taskId);
        validation.setValidation(reqHash, makeAddr("other-validator"), agentId, 80, true);

        vm.expectRevert(AgentBondManager.ValidatorMismatch.selector);
        manager.resolveDispute(taskId);
    }

    function test_reclaimDisputedTask_slashesWhenValidatorMismatched() public {
        vm.prank(agentOwner);
        manager.depositBond{value: 10 ether}(agentId);

        uint256 taskId = _createTask(keccak256("validator-mismatch-reclaim"), block.timestamp + 1 days, 1 ether);

        vm.prank(client);
        manager.disputeTask(taskId);

        bytes32 reqHash = manager.requestHash(taskId);
        validation.setValidation(reqHash, makeAddr("other-validator"), agentId, 80, true);

        vm.warp(block.timestamp + DISPUTE_PERIOD + 1);
        manager.reclaimDisputedTask(taskId);

        AgentBondManager.Task memory task = manager.getTask(taskId);
        assertTrue(task.status == AgentBondManager.TaskStatus.Slashed);
    }

    // --- P3: Zero-address ownership transfer ---

    function test_transferOwnership_rejectsZeroAddress() public {
        vm.expectRevert(AgentBondManager.ZeroAddress.selector);
        manager.transferOwnership(address(0));
    }

    function test_scorer_transferOwnership_rejectsZeroAddress() public {
        vm.expectRevert(ReputationScorer.ZeroAddress.selector);
        scorer.transferOwnership(address(0));
    }

    function test_scorer_addTrustedReviewer_rejectsZeroAddress() public {
        vm.expectRevert(ReputationScorer.ZeroAddress.selector);
        scorer.addTrustedReviewer(address(0));
    }

    function test_scorer_addTrustedValidator_rejectsZeroAddress() public {
        vm.expectRevert(ReputationScorer.ZeroAddress.selector);
        scorer.addTrustedValidator(address(0));
    }

    function test_scorer_addTrustedReviewer_rejectsWhenFull() public {
        for (uint256 i = 1; i <= 200; i++) {
            scorer.addTrustedReviewer(address(uint160(i)));
        }
        vm.expectRevert(ReputationScorer.ListFull.selector);
        scorer.addTrustedReviewer(address(uint160(201)));
    }

    function test_scorer_addTrustedValidator_rejectsWhenFull() public {
        for (uint256 i = 1; i <= 200; i++) {
            scorer.addTrustedValidator(address(uint160(i)));
        }
        vm.expectRevert(ReputationScorer.ListFull.selector);
        scorer.addTrustedValidator(address(uint160(201)));
    }

    // --- Registry failure grace window ---

    function test_reclaimDisputedTask_registryFailure_firstCallRecordsTimestamp() public {
        vm.prank(agentOwner);
        manager.depositBond{value: 10 ether}(agentId);

        uint256 taskId = _createTask(keccak256("grace"), block.timestamp + 1 days, 1 ether);
        bytes32 reqHash = manager.requestHash(taskId);
        validation.setValidation(reqHash, validator, agentId, 0, false);

        vm.prank(client);
        manager.disputeTask(taskId);

        validation.setForceRevert(true);
        vm.warp(block.timestamp + DISPUTE_PERIOD + 1);

        manager.reclaimDisputedTask(taskId);

        assertGt(manager.registryFailureSince(taskId), 0);
        assertTrue(manager.getTask(taskId).status == AgentBondManager.TaskStatus.Disputed);
    }

    function test_reclaimDisputedTask_registryFailure_revertsWithinGrace() public {
        vm.prank(agentOwner);
        manager.depositBond{value: 10 ether}(agentId);

        uint256 taskId = _createTask(keccak256("grace2"), block.timestamp + 1 days, 1 ether);
        bytes32 reqHash = manager.requestHash(taskId);
        validation.setValidation(reqHash, validator, agentId, 0, false);

        vm.prank(client);
        manager.disputeTask(taskId);

        validation.setForceRevert(true);
        vm.warp(block.timestamp + DISPUTE_PERIOD + 1);

        manager.reclaimDisputedTask(taskId);

        vm.warp(block.timestamp + 1 days);
        vm.expectRevert(AgentBondManager.RegistryUnavailable.selector);
        manager.reclaimDisputedTask(taskId);
    }

    function test_reclaimDisputedTask_registryFailure_refundsAfterGrace() public {
        vm.prank(agentOwner);
        manager.depositBond{value: 10 ether}(agentId);

        uint256 taskId = _createTask(keccak256("grace3"), block.timestamp + 1 days, 1 ether);
        bytes32 reqHash = manager.requestHash(taskId);
        validation.setValidation(reqHash, validator, agentId, 0, false);

        vm.prank(client);
        manager.disputeTask(taskId);

        validation.setForceRevert(true);
        vm.warp(block.timestamp + DISPUTE_PERIOD + 1);

        manager.reclaimDisputedTask(taskId);

        vm.warp(block.timestamp + 3 days);
        vm.expectEmit(true, true, false, false, address(manager));
        emit DisputeRefundedNoRegistry(taskId, client);
        manager.reclaimDisputedTask(taskId);

        AgentBondManager.Task memory task = manager.getTask(taskId);
        assertTrue(task.status == AgentBondManager.TaskStatus.Refunded);
        assertEq(manager.claimable(client), 1 ether);

        (uint256 bondAmt, uint256 bondLocked) = manager.getBond(agentId);
        assertEq(bondAmt, 10 ether);
        assertEq(bondLocked, 0);
    }

    function test_reclaimDisputedTask_registryFailure_refundsCustomClientRecipientAfterGrace() public {
        vm.prank(agentOwner);
        manager.depositBond{value: 10 ether}(agentId);

        address clientRecipient_ = makeAddr("client-refund-recipient");
        uint256 taskId = _createTaskWithRecipients(
            keccak256("grace-custom-recipient"), block.timestamp + 1 days, 1 ether, agentOwner, clientRecipient_
        );
        bytes32 reqHash = manager.requestHash(taskId);
        validation.setValidation(reqHash, validator, agentId, 0, false);

        vm.prank(client);
        manager.disputeTask(taskId);

        validation.setForceRevert(true);
        vm.warp(block.timestamp + DISPUTE_PERIOD + 1);

        manager.reclaimDisputedTask(taskId);

        vm.warp(block.timestamp + 3 days);
        vm.expectEmit(true, true, false, false, address(manager));
        emit DisputeRefundedNoRegistry(taskId, clientRecipient_);
        manager.reclaimDisputedTask(taskId);

        AgentBondManager.Task memory task = manager.getTask(taskId);
        assertTrue(task.status == AgentBondManager.TaskStatus.Refunded);
        assertEq(manager.claimable(clientRecipient_), 1 ether);
        assertEq(manager.claimable(client), 0);
    }

    function test_reclaimDisputedTask_registryRecovers_slashesNormally() public {
        vm.prank(agentOwner);
        manager.depositBond{value: 10 ether}(agentId);

        uint256 taskId = _createTask(keccak256("grace4"), block.timestamp + 1 days, 1 ether);
        bytes32 reqHash = manager.requestHash(taskId);
        validation.setValidation(reqHash, validator, agentId, 0, false);

        vm.prank(client);
        manager.disputeTask(taskId);

        validation.setForceRevert(true);
        vm.warp(block.timestamp + DISPUTE_PERIOD + 1);

        manager.reclaimDisputedTask(taskId);

        validation.setForceRevert(false);
        manager.reclaimDisputedTask(taskId);

        AgentBondManager.Task memory task = manager.getTask(taskId);
        assertTrue(task.status == AgentBondManager.TaskStatus.Slashed);
    }

    function test_reclaimDisputedTask_gracePeriodSnapshotted() public {
        vm.prank(agentOwner);
        manager.depositBond{value: 10 ether}(agentId);

        uint256 taskId = _createTask(keccak256("snap-grace"), block.timestamp + 1 days, 1 ether);
        bytes32 reqHash = manager.requestHash(taskId);
        validation.setValidation(reqHash, validator, agentId, 0, false);

        vm.prank(client);
        manager.disputeTask(taskId);

        // Grace was 3 days at dispute time; change to 30 days after
        manager.setRegistryFailureGracePeriod(30 days);

        validation.setForceRevert(true);
        vm.warp(block.timestamp + DISPUTE_PERIOD + 1);

        // Record failure
        manager.reclaimDisputedTask(taskId);

        // 3 days later (snapshot grace), should refund despite global being 30 days
        vm.warp(block.timestamp + 3 days);
        manager.reclaimDisputedTask(taskId);

        AgentBondManager.Task memory task = manager.getTask(taskId);
        assertTrue(task.status == AgentBondManager.TaskStatus.Refunded);
    }
}
