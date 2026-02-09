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

    bytes32 private constant TASK_PERMIT_TYPEHASH = keccak256(
        "TaskPermit(uint256 agentId,address client,uint256 payment,uint256 deadline,bytes32 taskHash,uint256 nonce)"
    );

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
        uint256 payment,
        uint256 deadline,
        bytes32 taskHash_,
        uint256 nonce
    ) internal view returns (bytes memory) {
        bytes32 structHash =
            keccak256(abi.encode(TASK_PERMIT_TYPEHASH, agentId_, client_, payment, deadline, taskHash_, nonce));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", manager.domainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(AGENT_OWNER_PK, digest);
        return abi.encodePacked(r, s, v);
    }

    function _createTask(bytes32 taskHash, uint256 deadline, uint256 payment) internal returns (uint256) {
        uint256 nonce = manager.agentNonces(agentId);
        bytes memory sig = _signPermit(agentId, client, payment, deadline, taskHash, nonce);
        vm.prank(client);
        return manager.createTask{value: payment}(agentId, taskHash, deadline, agentOwner, sig);
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
        assertTrue(task.status == AgentBondManager.TaskStatus.Active);
    }

    function test_createTask_revertsForInvalidSignature() public {
        vm.prank(agentOwner);
        manager.depositBond{value: 10 ether}(agentId);

        // Sign with wrong private key
        bytes32 taskHash = keccak256("task");
        uint256 deadline = block.timestamp + 1 days;
        uint256 nonce = manager.agentNonces(agentId);
        bytes32 structHash =
            keccak256(abi.encode(TASK_PERMIT_TYPEHASH, agentId, client, 1 ether, deadline, taskHash, nonce));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", manager.domainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(0xDEAD, digest);
        bytes memory badSig = abi.encodePacked(r, s, v);

        vm.prank(client);
        vm.expectRevert(AgentBondManager.InvalidSignature.selector);
        manager.createTask{value: 1 ether}(agentId, taskHash, deadline, agentOwner, badSig);
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
        bytes memory sig = _signPermit(agentId, client, 1 ether, block.timestamp + 1 days, keccak256("task"), nonce);

        vm.prank(client);
        vm.expectRevert(AgentBondManager.InsufficientBond.selector);
        manager.createTask{value: 1 ether}(agentId, keccak256("task"), block.timestamp + 1 days, agentOwner, sig);
    }

    function test_createTask_revertsForPastDeadline() public {
        vm.prank(agentOwner);
        manager.depositBond{value: 10 ether}(agentId);

        uint256 nonce = manager.agentNonces(agentId);
        bytes memory sig = _signPermit(agentId, client, 1 ether, block.timestamp - 1, keccak256("task"), nonce);

        vm.prank(client);
        vm.expectRevert(AgentBondManager.DeadlineInPast.selector);
        manager.createTask{value: 1 ether}(agentId, keccak256("task"), block.timestamp - 1, agentOwner, sig);
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

    function test_resolveDispute_revertsWithoutValidation() public {
        vm.prank(agentOwner);
        manager.depositBond{value: 10 ether}(agentId);

        uint256 taskId = _createTask(keccak256("unvalidated"), block.timestamp + 1 days, 1 ether);

        vm.prank(client);
        manager.disputeTask(taskId);

        vm.expectRevert(AgentBondManager.AgentMismatch.selector);
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

    function test_noReputation_requiresFullBond() public {
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

    function test_scorer_noData_zeroScore() public {
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

        vm.expectRevert(AgentBondManager.AgentMismatch.selector);
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

        vm.prank(client);
        manager.disputeTask(taskId);

        validation.setForceRevert(true);
        vm.warp(block.timestamp + DISPUTE_PERIOD + 1);

        manager.reclaimDisputedTask(taskId);

        vm.warp(block.timestamp + 3 days);
        manager.reclaimDisputedTask(taskId);

        AgentBondManager.Task memory task = manager.getTask(taskId);
        assertTrue(task.status == AgentBondManager.TaskStatus.Refunded);
        assertEq(manager.claimable(client), 1 ether);

        (uint256 bondAmt, uint256 bondLocked) = manager.getBond(agentId);
        assertEq(bondAmt, 10 ether);
        assertEq(bondLocked, 0);
    }

    function test_reclaimDisputedTask_registryRecovers_slashesNormally() public {
        vm.prank(agentOwner);
        manager.depositBond{value: 10 ether}(agentId);

        uint256 taskId = _createTask(keccak256("grace4"), block.timestamp + 1 days, 1 ether);

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
