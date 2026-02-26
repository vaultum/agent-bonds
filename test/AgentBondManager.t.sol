// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {AgentBondManager} from "../src/AgentBondManager.sol";
import {ReputationScorer} from "../src/ReputationScorer.sol";
import {MockIdentityRegistry, MockValidationRegistry} from "./mocks/MockERC8004.sol";
import {MockERC20} from "./mocks/MockERC20.sol";
import {MockPermit2} from "./mocks/MockPermit2.sol";

contract AgentBondManagerTest is Test {
    MockIdentityRegistry identity;
    MockValidationRegistry validation;
    MockERC20 settlementToken;
    MockPermit2 permit2;
    ReputationScorer scorer;
    AgentBondManager manager;

    uint256 internal constant AGENT_OWNER_PK = 0xA11CE;
    uint256 internal constant VALIDATOR_PK = 0xB0B;
    address internal agentOwner;
    address client = makeAddr("client");
    address validator;
    uint256 agentId;

    uint256 constant DISPUTE_PERIOD = 7 days;
    uint8 constant MIN_PASSING_SCORE = 50;
    uint256 constant SLASH_BPS = 5000;
    uint256 constant SCORER_PRIOR_VALUE = 1 ether;
    uint256 constant SCORER_SLASH_MULTIPLIER_BPS = 15_000;
    uint8 constant FINALITY_POLICY_RESPONSE_HASH_REQUIRED = 0;
    uint8 constant FINALITY_POLICY_ANY_STATUS_RECORD = 1;
    uint8 constant STATUS_LOOKUP_POLICY_CANONICAL_UNKNOWN_AS_MISSING = 0;
    uint8 constant STATUS_LOOKUP_POLICY_ALWAYS_MISSING = 1;
    uint8 constant STATUS_LOOKUP_POLICY_ALWAYS_UNAVAILABLE = 2;
    uint8 constant VALIDATOR_SELECTION_POLICY_DESIGNATED_ONLY = 0;
    uint8 constant VALIDATOR_SELECTION_POLICY_DESIGNATED_AND_ALLOWLISTED = 1;
    uint256 constant DEFAULT_VALIDATOR_FEE_WEI = 0;

    bytes32 private constant TASK_PERMIT_TYPEHASH = keccak256(
        "TaskPermit(uint256 agentId,address client,address agentRecipient,address clientRecipient,address committedValidator,uint256 validatorFeeAmount,uint256 paymentAmount,uint256 deadline,bytes32 taskHash,uint256 nonce)"
    );
    bytes32 private constant VALIDATOR_COMMITMENT_TYPEHASH = keccak256(
        "ValidatorCommitment(uint256 agentId,address client,bytes32 taskHash,uint256 feeAmount,uint256 deadline,uint256 nonce)"
    );

    event DisputeExpiredClaimed(uint256 indexed taskId, address indexed beneficiary);
    event DisputeRefundedNoRegistry(uint256 indexed taskId, address indexed beneficiary);

    function setUp() public {
        agentOwner = vm.addr(AGENT_OWNER_PK);
        validator = vm.addr(VALIDATOR_PK);

        identity = new MockIdentityRegistry();
        validation = new MockValidationRegistry();
        settlementToken = new MockERC20("MockUSDC", "mUSDC", 6);
        permit2 = new MockPermit2();

        vm.prank(agentOwner);
        agentId = identity.register(agentOwner);

        ReputationScorer scorerImpl = new ReputationScorer();
        ERC1967Proxy scorerProxy = new ERC1967Proxy(
            address(scorerImpl),
            abi.encodeCall(ReputationScorer.initialize, (SCORER_PRIOR_VALUE, SCORER_SLASH_MULTIPLIER_BPS))
        );
        scorer = ReputationScorer(address(scorerProxy));

        AgentBondManager managerImpl = new AgentBondManager();
        ERC1967Proxy managerProxy = new ERC1967Proxy(
            address(managerImpl),
            abi.encodeCall(
                AgentBondManager.initialize,
                (
                    address(identity),
                    address(validation),
                    address(scorer),
                    address(settlementToken),
                    DISPUTE_PERIOD,
                    MIN_PASSING_SCORE,
                    SLASH_BPS
                )
            )
        );
        manager = AgentBondManager(address(managerProxy));
        scorer.setBondManager(address(manager));
        manager.setPermit2(address(permit2));

        uint256 mintAmount = 100_000 ether;
        settlementToken.mint(agentOwner, mintAmount);
        settlementToken.mint(client, mintAmount);

        vm.startPrank(agentOwner);
        settlementToken.approve(address(manager), type(uint256).max);
        settlementToken.approve(address(permit2), type(uint256).max);
        vm.stopPrank();
        vm.startPrank(client);
        settlementToken.approve(address(manager), type(uint256).max);
        settlementToken.approve(address(permit2), type(uint256).max);
        vm.stopPrank();
    }

    // --- Helpers ---

    function _signPermit(
        uint256 agentId_,
        address client_,
        address agentRecipient_,
        address clientRecipient_,
        address committedValidator_,
        uint256 validatorFeeWei_,
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
                validatorFeeWei_,
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

    function _signValidatorCommitment(
        uint256 agentId_,
        address client_,
        bytes32 taskHash_,
        uint256 validatorFeeWei_,
        uint256 deadline,
        uint256 nonce
    ) internal view returns (bytes memory) {
        bytes32 structHash = keccak256(
            abi.encode(
                VALIDATOR_COMMITMENT_TYPEHASH, agentId_, client_, taskHash_, validatorFeeWei_, deadline, nonce
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", manager.domainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(VALIDATOR_PK, digest);
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
        return _createTaskWithRecipientsValidatorAndFee(
            taskHash,
            deadline,
            payment,
            agentRecipient_,
            clientRecipient_,
            committedValidator_,
            DEFAULT_VALIDATOR_FEE_WEI
        );
    }

    function _createTaskWithRecipientsValidatorAndFee(
        bytes32 taskHash,
        uint256 deadline,
        uint256 payment,
        address agentRecipient_,
        address clientRecipient_,
        address committedValidator_,
        uint256 validatorFeeWei
    ) internal returns (uint256) {
        uint256 nonce = manager.agentNonces(agentId);
        uint256 validatorNonce = manager.validatorNonces(committedValidator_);
        bytes memory sig = _signPermit(
            agentId,
            client,
            agentRecipient_,
            clientRecipient_,
            committedValidator_,
            validatorFeeWei,
            payment,
            deadline,
            taskHash,
            nonce
        );
        bytes memory validatorSig =
            _signValidatorCommitment(agentId, client, taskHash, validatorFeeWei, deadline, validatorNonce);
        vm.prank(client);
        return manager.createTask(
            agentId,
            taskHash,
            deadline,
            payment,
            agentOwner,
            agentRecipient_,
            clientRecipient_,
            committedValidator_,
            validatorFeeWei,
            validatorSig,
            sig
        );
    }

    function _expectedScore(uint256 successValue, uint256 slashValue) internal pure returns (uint256) {
        uint256 slashPenalty = (slashValue * SCORER_SLASH_MULTIPLIER_BPS) / 10_000;
        uint256 denominator = successValue + slashPenalty + SCORER_PRIOR_VALUE;
        if (denominator == 0) {
            return 0;
        }
        return (successValue * 10_000) / denominator;
    }

    // --- Bond Tests ---

    function test_depositBond() public {
        vm.prank(agentOwner);
        manager.depositBond(agentId, 10 ether);

        (uint256 amount, uint256 locked) = manager.getBond(agentId);
        assertEq(amount, 10 ether);
        assertEq(locked, 0);
    }

    function test_depositBond_revertsForNonOwner() public {
        vm.prank(client);
        vm.expectRevert(AgentBondManager.NotAgentOwner.selector);
        manager.depositBond(agentId, 10 ether);
    }

    function test_depositBond_revertsForZeroValue() public {
        vm.prank(agentOwner);
        vm.expectRevert(AgentBondManager.ZeroValue.selector);
        manager.depositBond(agentId, 0);
    }

    function test_depositBondWithPermit2() public {
        uint256 amount = 10 ether;
        vm.prank(agentOwner);
        manager.depositBondWithPermit2(
            agentId,
            amount,
            amount,
            block.timestamp + 1 days,
            0,
            block.timestamp + 1 days,
            hex"abcd"
        );

        (uint256 bondedAmount, uint256 locked) = manager.getBond(agentId);
        assertEq(bondedAmount, amount);
        assertEq(locked, 0);
    }

    function test_depositBondWithEip3009() public {
        uint256 amount = 10 ether;
        vm.prank(agentOwner);
        manager.depositBondWithEip3009(
            agentId,
            amount,
            block.timestamp - 1,
            block.timestamp + 1 days,
            keccak256("deposit-eip3009"),
            27,
            bytes32(uint256(1)),
            bytes32(uint256(2))
        );

        (uint256 bondedAmount, uint256 locked) = manager.getBond(agentId);
        assertEq(bondedAmount, amount);
        assertEq(locked, 0);
    }

    function test_withdrawBond() public {
        vm.prank(agentOwner);
        manager.depositBond(agentId, 10 ether);

        uint256 balanceBefore = settlementToken.balanceOf(agentOwner);

        vm.prank(agentOwner);
        manager.withdrawBond(agentId, 5 ether);

        (uint256 amount,) = manager.getBond(agentId);
        assertEq(amount, 5 ether);
        assertEq(settlementToken.balanceOf(agentOwner), balanceBefore + 5 ether);
    }

    function test_withdrawBond_revertsIfLocked() public {
        vm.prank(agentOwner);
        manager.depositBond(agentId, 10 ether);

        _createTask(keccak256("task"), block.timestamp + 1 days, 5 ether);

        vm.prank(agentOwner);
        vm.expectRevert(AgentBondManager.InsufficientBond.selector);
        manager.withdrawBond(agentId, 10 ether);
    }

    // --- Task Creation Tests ---

    function test_createTask() public {
        vm.prank(agentOwner);
        manager.depositBond(agentId, 10 ether);

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
        manager.depositBond(agentId, 10 ether);

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
        manager.depositBond(agentId, 10 ether);

        address permittedAgentRecipient = makeAddr("permitted-agent-recipient");
        address permittedClientRecipient = makeAddr("permitted-client-recipient");

        bytes32 taskHash = keccak256("recipient-mismatch");
        uint256 deadline = block.timestamp + 1 days;
        uint256 validatorFeeWei = DEFAULT_VALIDATOR_FEE_WEI;
        uint256 nonce = manager.agentNonces(agentId);
        bytes memory sig = _signPermit(
            agentId,
            client,
            permittedAgentRecipient,
            permittedClientRecipient,
            validator,
            validatorFeeWei,
            1 ether,
            deadline,
            taskHash,
            nonce
        );
        bytes memory validatorSig =
            _signValidatorCommitment(agentId, client, taskHash, validatorFeeWei, deadline, manager.validatorNonces(validator));

        vm.prank(client);
        vm.expectRevert(AgentBondManager.InvalidSignature.selector);
        manager.createTask(
            agentId,
            taskHash,
            deadline,
            1 ether,
            agentOwner,
            permittedAgentRecipient,
            makeAddr("different-client-recipient"),
            validator,
            validatorFeeWei,
            validatorSig,
            sig
        );
    }

    function test_createTask_revertsForInvalidSignature() public {
        vm.prank(agentOwner);
        manager.depositBond(agentId, 10 ether);

        // Sign with wrong private key
        bytes32 taskHash = keccak256("task");
        uint256 deadline = block.timestamp + 1 days;
        uint256 validatorFeeWei = DEFAULT_VALIDATOR_FEE_WEI;
        uint256 nonce = manager.agentNonces(agentId);
        bytes32 structHash = keccak256(
            abi.encode(
                TASK_PERMIT_TYPEHASH,
                agentId,
                client,
                agentOwner,
                client,
                validator,
                validatorFeeWei,
                1 ether,
                deadline,
                taskHash,
                nonce
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", manager.domainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(0xDEAD, digest);
        bytes memory badSig = abi.encodePacked(r, s, v);
        bytes memory validatorSig =
            _signValidatorCommitment(agentId, client, taskHash, validatorFeeWei, deadline, manager.validatorNonces(validator));

        vm.prank(client);
        vm.expectRevert(AgentBondManager.InvalidSignature.selector);
        manager.createTask(
            agentId,
            taskHash,
            deadline,
            1 ether,
            agentOwner,
            agentOwner,
            client,
            validator,
            validatorFeeWei,
            validatorSig,
            badSig
        );

        assertEq(manager.agentNonces(agentId), nonce);
    }

    function test_createTask_revertsForZeroRecipient() public {
        vm.prank(agentOwner);
        manager.depositBond(agentId, 10 ether);

        vm.prank(client);
        vm.expectRevert(AgentBondManager.ZeroAddress.selector);
        manager.createTask(
            agentId,
            keccak256("zero-recipient"),
            block.timestamp + 1 days,
            1 ether,
            agentOwner,
            address(0),
            client,
            validator,
            DEFAULT_VALIDATOR_FEE_WEI,
            hex"",
            hex""
        );
    }

    function test_createTask_revertsForZeroCommittedValidator() public {
        vm.prank(agentOwner);
        manager.depositBond(agentId, 10 ether);

        uint256 nonce = manager.agentNonces(agentId);
        bytes memory sig = _signPermit(
            agentId,
            client,
            agentOwner,
            client,
            address(0),
            DEFAULT_VALIDATOR_FEE_WEI,
            1 ether,
            block.timestamp + 1 days,
            keccak256("zero-validator"),
            nonce
        );

        vm.prank(client);
        vm.expectRevert(AgentBondManager.ZeroAddress.selector);
        manager.createTask(
            agentId,
            keccak256("zero-validator"),
            block.timestamp + 1 days,
            1 ether,
            agentOwner,
            agentOwner,
            client,
            address(0),
            DEFAULT_VALIDATOR_FEE_WEI,
            hex"",
            sig
        );
    }

    function test_createTask_nonceIncrementsPerTask() public {
        vm.prank(agentOwner);
        manager.depositBond(agentId, 10 ether);

        assertEq(manager.agentNonces(agentId), 0);
        _createTask(keccak256("t1"), block.timestamp + 1 days, 1 ether);
        assertEq(manager.agentNonces(agentId), 1);
        _createTask(keccak256("t2"), block.timestamp + 1 days, 1 ether);
        assertEq(manager.agentNonces(agentId), 2);
    }

    function test_createTask_historyRetainsLatestBoundedEntries() public {
        vm.prank(agentOwner);
        manager.depositBond(agentId, 10 ether);

        manager.setMaxAgentTaskHistory(2);

        _createTask(keccak256("task-history-1"), block.timestamp + 1 days, 1 ether);
        _createTask(keccak256("task-history-2"), block.timestamp + 1 days, 1 ether);
        _createTask(keccak256("task-history-3"), block.timestamp + 1 days, 1 ether);

        uint256[] memory allTaskIds = manager.agentTaskIds(agentId);
        assertEq(allTaskIds.length, 2);
        assertEq(allTaskIds[0], 1);
        assertEq(allTaskIds[1], 2);

        uint256[] memory slice = manager.agentTaskIdsSlice(agentId, 0, 10);
        assertEq(slice.length, 2);
        assertEq(slice[0], 1);
        assertEq(slice[1], 2);
    }

    function test_setMaxAgentTaskHistory_lowerCapConvergesImmediately() public {
        vm.prank(agentOwner);
        manager.depositBond(agentId, 20 ether);

        manager.setMaxAgentTaskHistory(5);
        for (uint256 i; i < 5; i++) {
            _createTask(keccak256(abi.encodePacked("task-history-converge-", i)), block.timestamp + 1 days, 1 ether);
        }

        uint256[] memory beforeLowering = manager.agentTaskIds(agentId);
        assertEq(beforeLowering.length, 5);

        manager.setMaxAgentTaskHistory(2);

        uint256[] memory allTaskIds = manager.agentTaskIds(agentId);
        assertEq(allTaskIds.length, 2);
        assertEq(allTaskIds[0], 3);
        assertEq(allTaskIds[1], 4);

        uint256[] memory slice = manager.agentTaskIdsSlice(agentId, 0, 10);
        assertEq(slice.length, 2);
        assertEq(slice[0], 3);
        assertEq(slice[1], 4);
    }

    function test_createTask_revertsIfInsufficientBond() public {
        uint256 validatorFeeWei = DEFAULT_VALIDATOR_FEE_WEI;
        uint256 deadline = block.timestamp + 1 days;
        bytes32 taskHash = keccak256("task");
        uint256 nonce = manager.agentNonces(agentId);
        bytes memory sig = _signPermit(
            agentId, client, agentOwner, client, validator, validatorFeeWei, 1 ether, deadline, taskHash, nonce
        );
        bytes memory validatorSig =
            _signValidatorCommitment(agentId, client, taskHash, validatorFeeWei, deadline, manager.validatorNonces(validator));

        vm.prank(client);
        vm.expectRevert(AgentBondManager.InsufficientBond.selector);
        manager.createTask(
            agentId, taskHash, deadline, 1 ether, agentOwner, agentOwner, client, validator, validatorFeeWei, validatorSig, sig
        );
    }

    function test_createTask_revertsForPastDeadline() public {
        vm.prank(agentOwner);
        manager.depositBond(agentId, 10 ether);

        uint256 nonce = manager.agentNonces(agentId);
        bytes memory sig = _signPermit(
            agentId,
            client,
            agentOwner,
            client,
            validator,
            DEFAULT_VALIDATOR_FEE_WEI,
            1 ether,
            block.timestamp - 1,
            keccak256("task"),
            nonce
        );

        vm.prank(client);
        vm.expectRevert(AgentBondManager.DeadlineInPast.selector);
        manager.createTask(
            agentId,
            keccak256("task"),
            block.timestamp - 1,
            1 ether,
            agentOwner,
            agentOwner,
            client,
            validator,
            DEFAULT_VALIDATOR_FEE_WEI,
            hex"",
            sig
        );
    }

    function test_createTask_revertsWhenValidatorFeeBelowMinimum() public {
        vm.prank(agentOwner);
        manager.depositBond(agentId, 10 ether);

        manager.setMinValidatorFee(2_000_000);

        bytes32 taskHash = keccak256("validator-fee-too-low");
        uint256 deadline = block.timestamp + 1 days;
        uint256 validatorFeeWei = 1_000_000;
        uint256 nonce = manager.agentNonces(agentId);
        uint256 validatorNonce = manager.validatorNonces(validator);
        bytes memory sig =
            _signPermit(agentId, client, agentOwner, client, validator, validatorFeeWei, 1 ether, deadline, taskHash, nonce);
        bytes memory validatorSig =
            _signValidatorCommitment(agentId, client, taskHash, validatorFeeWei, deadline, validatorNonce);

        vm.prank(client);
        vm.expectRevert(AgentBondManager.ValidatorFeeBelowMinimum.selector);
        manager.createTask(
            agentId, taskHash, deadline, 1 ether, agentOwner, agentOwner, client, validator, validatorFeeWei, validatorSig, sig
        );
    }

    function test_createTask_revertsWhenCommittedValidatorNotTrustedUnderAllowlistedPolicy() public {
        vm.prank(agentOwner);
        manager.depositBond(agentId, 10 ether);

        manager.setValidatorSelectionPolicy(VALIDATOR_SELECTION_POLICY_DESIGNATED_AND_ALLOWLISTED);

        bytes32 taskHash = keccak256("untrusted-allowlisted-policy");
        uint256 deadline = block.timestamp + 1 days;
        uint256 validatorFeeWei = DEFAULT_VALIDATOR_FEE_WEI;
        uint256 nonce = manager.agentNonces(agentId);
        uint256 validatorNonce = manager.validatorNonces(validator);
        bytes memory sig =
            _signPermit(agentId, client, agentOwner, client, validator, validatorFeeWei, 1 ether, deadline, taskHash, nonce);
        bytes memory validatorSig =
            _signValidatorCommitment(agentId, client, taskHash, validatorFeeWei, deadline, validatorNonce);

        vm.prank(client);
        vm.expectRevert(AgentBondManager.ValidatorNotTrusted.selector);
        manager.createTask(
            agentId, taskHash, deadline, 1 ether, agentOwner, agentOwner, client, validator, validatorFeeWei, validatorSig, sig
        );
    }

    function test_createTask_acceptsTrustedCommittedValidatorUnderAllowlistedPolicy() public {
        vm.prank(agentOwner);
        manager.depositBond(agentId, 10 ether);

        manager.setValidatorSelectionPolicy(VALIDATOR_SELECTION_POLICY_DESIGNATED_AND_ALLOWLISTED);
        manager.addTrustedValidator(validator);

        uint256 taskId = _createTask(keccak256("trusted-allowlisted-policy"), block.timestamp + 1 days, 1 ether);
        assertEq(manager.getTask(taskId).committedValidator, validator);
    }

    function test_createTask_revertsForInvalidValidatorSignature() public {
        vm.prank(agentOwner);
        manager.depositBond(agentId, 10 ether);

        bytes32 taskHash = keccak256("validator-sig-invalid");
        uint256 deadline = block.timestamp + 1 days;
        uint256 validatorFeeWei = 0.01 ether;
        uint256 nonce = manager.agentNonces(agentId);
        uint256 validatorNonce = manager.validatorNonces(validator);
        bytes memory sig =
            _signPermit(agentId, client, agentOwner, client, validator, validatorFeeWei, 1 ether, deadline, taskHash, nonce);

        bytes32 validatorStructHash = keccak256(
            abi.encode(
                VALIDATOR_COMMITMENT_TYPEHASH, agentId, client, taskHash, validatorFeeWei, deadline, validatorNonce
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", manager.domainSeparator(), validatorStructHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(0xDEAD, digest);
        bytes memory badValidatorSig = abi.encodePacked(r, s, v);

        vm.prank(client);
        vm.expectRevert(AgentBondManager.InvalidSignature.selector);
        manager.createTask(
            agentId,
            taskHash,
            deadline,
            1 ether,
            agentOwner,
            agentOwner,
            client,
            validator,
            validatorFeeWei,
            badValidatorSig,
            sig
        );
    }

    function test_createTaskWithPermit2() public {
        vm.prank(agentOwner);
        manager.depositBond(agentId, 10 ether);

        bytes32 taskHash = keccak256("task-with-permit2");
        uint256 deadline = block.timestamp + 1 days;
        uint256 paymentAmount = 1 ether;
        uint256 validatorFeeAmount = DEFAULT_VALIDATOR_FEE_WEI;

        bytes memory sig = _signPermit(
            agentId,
            client,
            agentOwner,
            client,
            validator,
            validatorFeeAmount,
            paymentAmount,
            deadline,
            taskHash,
            manager.agentNonces(agentId)
        );
        bytes memory validatorSig = _signValidatorCommitment(
            agentId, client, taskHash, validatorFeeAmount, deadline, manager.validatorNonces(validator)
        );

        vm.prank(client);
        uint256 taskId = manager.createTaskWithPermit2(
            agentId,
            taskHash,
            deadline,
            paymentAmount,
            agentOwner,
            agentOwner,
            client,
            validator,
            validatorFeeAmount,
            validatorSig,
            sig,
            paymentAmount,
            block.timestamp + 1 days,
            0,
            block.timestamp + 1 days,
            hex"abcd"
        );

        AgentBondManager.Task memory task = manager.getTask(taskId);
        assertEq(uint8(task.status), uint8(AgentBondManager.TaskStatus.Active));
        assertEq(task.payment, paymentAmount);
    }

    function test_createTaskWithEip3009() public {
        vm.prank(agentOwner);
        manager.depositBond(agentId, 10 ether);

        bytes32 taskHash = keccak256("task-with-eip3009");
        uint256 deadline = block.timestamp + 1 days;
        uint256 paymentAmount = 1 ether;
        uint256 validatorFeeAmount = DEFAULT_VALIDATOR_FEE_WEI;

        bytes memory sig = _signPermit(
            agentId,
            client,
            agentOwner,
            client,
            validator,
            validatorFeeAmount,
            paymentAmount,
            deadline,
            taskHash,
            manager.agentNonces(agentId)
        );
        bytes memory validatorSig = _signValidatorCommitment(
            agentId, client, taskHash, validatorFeeAmount, deadline, manager.validatorNonces(validator)
        );

        vm.prank(client);
        uint256 taskId = manager.createTaskWithEip3009(
            agentId,
            taskHash,
            deadline,
            paymentAmount,
            agentOwner,
            agentOwner,
            client,
            validator,
            validatorFeeAmount,
            validatorSig,
            sig,
            block.timestamp - 1,
            block.timestamp + 1 days,
            keccak256("create-task-eip3009"),
            27,
            bytes32(uint256(3)),
            bytes32(uint256(4))
        );

        AgentBondManager.Task memory task = manager.getTask(taskId);
        assertEq(uint8(task.status), uint8(AgentBondManager.TaskStatus.Active));
        assertEq(task.payment, paymentAmount);
    }

    function test_disputeTask_revertsWhenValidatorFeeInsufficient() public {
        vm.prank(agentOwner);
        manager.depositBond(agentId, 10 ether);

        uint256 taskId = _createTaskWithRecipientsValidatorAndFee(
            keccak256("insufficient-validator-fee"),
            block.timestamp + 1 days,
            1 ether,
            agentOwner,
            client,
            validator,
            0.01 ether
        );

        vm.prank(client);
        vm.expectRevert(AgentBondManager.InsufficientValidatorFee.selector);
        manager.disputeTask(taskId, 0.009 ether);
    }

    function test_disputeTaskWithPermit2() public {
        vm.prank(agentOwner);
        manager.depositBond(agentId, 10 ether);

        uint256 validatorFeeAmount = 0.01 ether;
        uint256 taskId = _createTaskWithRecipientsValidatorAndFee(
            keccak256("dispute-permit2"),
            block.timestamp + 1 days,
            1 ether,
            agentOwner,
            client,
            validator,
            validatorFeeAmount
        );

        vm.prank(client);
        manager.disputeTaskWithPermit2(
            taskId,
            validatorFeeAmount,
            validatorFeeAmount,
            block.timestamp + 1 days,
            0,
            block.timestamp + 1 days,
            hex"abcd"
        );

        assertEq(manager.validatorFeeEscrow(taskId), validatorFeeAmount);
    }

    function test_disputeTaskWithEip3009() public {
        vm.prank(agentOwner);
        manager.depositBond(agentId, 10 ether);

        uint256 validatorFeeAmount = 0.01 ether;
        uint256 taskId = _createTaskWithRecipientsValidatorAndFee(
            keccak256("dispute-eip3009"),
            block.timestamp + 1 days,
            1 ether,
            agentOwner,
            client,
            validator,
            validatorFeeAmount
        );

        vm.prank(client);
        manager.disputeTaskWithEip3009(
            taskId,
            validatorFeeAmount,
            block.timestamp - 1,
            block.timestamp + 1 days,
            keccak256("dispute-task-eip3009"),
            27,
            bytes32(uint256(5)),
            bytes32(uint256(6))
        );

        assertEq(manager.validatorFeeEscrow(taskId), validatorFeeAmount);
    }

    function test_disputeAndResolve_paysValidatorFee() public {
        vm.prank(agentOwner);
        manager.depositBond(agentId, 10 ether);

        uint256 validatorFeeWei = 0.01 ether;
        uint256 taskId = _createTaskWithRecipientsValidatorAndFee(
            keccak256("validator-fee-payout"),
            block.timestamp + 1 days,
            1 ether,
            agentOwner,
            client,
            validator,
            validatorFeeWei
        );
        assertEq(manager.validatorFeeCommitment(taskId), validatorFeeWei);

        vm.prank(client);
        manager.disputeTask(taskId, validatorFeeWei);
        assertEq(manager.validatorFeeEscrow(taskId), validatorFeeWei);

        bytes32 reqHash = manager.requestHash(taskId);
        validation.setValidation(reqHash, validator, agentId, 80, true);

        manager.resolveDispute(taskId);
        assertEq(manager.validatorFeeEscrow(taskId), 0);
        assertEq(manager.claimable(validator), validatorFeeWei);
    }

    function test_reclaimDisputedTask_refundsValidatorFeeToClient() public {
        vm.prank(agentOwner);
        manager.depositBond(agentId, 10 ether);

        uint256 validatorFeeWei = 0.02 ether;
        uint256 taskId = _createTaskWithRecipientsValidatorAndFee(
            keccak256("validator-fee-refund"),
            block.timestamp + 1 days,
            1 ether,
            agentOwner,
            client,
            validator,
            validatorFeeWei
        );

        vm.prank(client);
        manager.disputeTask(taskId, validatorFeeWei);

        vm.warp(block.timestamp + DISPUTE_PERIOD + 1);
        manager.reclaimDisputedTask(taskId);

        uint256 expectedSlash = (1 ether * SLASH_BPS) / 10_000;
        assertEq(manager.validatorFeeEscrow(taskId), 0);
        assertEq(manager.claimable(client), 1 ether + expectedSlash + validatorFeeWei);
    }

    // --- Complete Task Tests ---

    function test_completeTask() public {
        vm.prank(agentOwner);
        manager.depositBond(agentId, 10 ether);

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
        manager.depositBond(agentId, 10 ether);

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
        manager.depositBond(agentId, 10 ether);

        uint256 taskId = _createTask(keccak256("task"), block.timestamp + 1 days, 1 ether);

        vm.prank(agentOwner);
        vm.expectRevert(AgentBondManager.NotClient.selector);
        manager.completeTask(taskId);
    }

    // --- Dispute & Resolution Tests ---

    function test_disputeAndResolve_agentWins() public {
        vm.prank(agentOwner);
        manager.depositBond(agentId, 10 ether);

        uint256 taskId = _createTask(keccak256("task-deliver"), block.timestamp + 1 days, 1 ether);

        vm.prank(client);
        manager.disputeTask(taskId, 0);

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
        manager.depositBond(agentId, 10 ether);

        uint256 taskId = _createTask(keccak256("task-bad"), block.timestamp + 1 days, 1 ether);

        vm.prank(client);
        manager.disputeTask(taskId, 0);

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
        manager.depositBond(agentId, 10 ether);

        address clientRecipient_ = makeAddr("client-slash-recipient");
        uint256 taskId = _createTaskWithRecipients(
            keccak256("task-bad-custom-recipient"), block.timestamp + 1 days, 1 ether, agentOwner, clientRecipient_
        );

        vm.prank(client);
        manager.disputeTask(taskId, 0);

        bytes32 reqHash = manager.requestHash(taskId);
        validation.setValidation(reqHash, validator, agentId, 30, true);

        manager.resolveDispute(taskId);

        uint256 expectedSlash = (1 ether * SLASH_BPS) / 10_000;
        assertEq(manager.claimable(clientRecipient_), 1 ether + expectedSlash);
        assertEq(manager.claimable(client), 0);
    }

    function test_resolveDispute_revertsWithoutValidation() public {
        vm.prank(agentOwner);
        manager.depositBond(agentId, 10 ether);

        uint256 taskId = _createTask(keccak256("unvalidated"), block.timestamp + 1 days, 1 ether);

        vm.prank(client);
        manager.disputeTask(taskId, 0);

        vm.expectRevert(AgentBondManager.NoValidationResponse.selector);
        manager.resolveDispute(taskId);
    }

    /// @dev response == 0 is a valid "fail" → slashes (M1 fix).
    function test_resolveDispute_zeroResponseSlashes() public {
        vm.prank(agentOwner);
        manager.depositBond(agentId, 10 ether);

        uint256 taskId = _createTask(keccak256("zero-response"), block.timestamp + 1 days, 1 ether);

        vm.prank(client);
        manager.disputeTask(taskId, 0);

        bytes32 reqHash = manager.requestHash(taskId);
        validation.setValidation(reqHash, validator, agentId, 0, true);

        manager.resolveDispute(taskId);

        AgentBondManager.Task memory task = manager.getTask(taskId);
        assertTrue(task.status == AgentBondManager.TaskStatus.Slashed);
    }

    function test_resolveDispute_revertsWhenValidationPending() public {
        vm.prank(agentOwner);
        manager.depositBond(agentId, 10 ether);

        uint256 taskId = _createTask(keccak256("pending-response"), block.timestamp + 1 days, 1 ether);

        vm.prank(client);
        manager.disputeTask(taskId, 0);

        bytes32 reqHash = manager.requestHash(taskId);
        validation.setValidation(reqHash, validator, agentId, 0, false);

        vm.expectRevert(AgentBondManager.NoValidationResponse.selector);
        manager.resolveDispute(taskId);
    }

    function test_resolveDispute_pendingCanSettleWhenAnyStatusPolicy() public {
        vm.prank(agentOwner);
        manager.depositBond(agentId, 10 ether);

        manager.setValidationFinalityPolicy(FINALITY_POLICY_ANY_STATUS_RECORD);

        uint256 taskId = _createTask(keccak256("pending-policy"), block.timestamp + 1 days, 1 ether);

        vm.prank(client);
        manager.disputeTask(taskId, 0);

        bytes32 reqHash = manager.requestHash(taskId);
        validation.setValidation(reqHash, validator, agentId, 0, false);

        manager.resolveDispute(taskId);

        AgentBondManager.Task memory task = manager.getTask(taskId);
        assertTrue(task.status == AgentBondManager.TaskStatus.Slashed);
    }

    function test_resolveDispute_missingRecordRevertsNoValidationResponseWhenAnyStatusPolicy() public {
        vm.prank(agentOwner);
        manager.depositBond(agentId, 10 ether);

        manager.setValidationFinalityPolicy(FINALITY_POLICY_ANY_STATUS_RECORD);

        uint256 taskId = _createTask(keccak256("missing-record-any-status"), block.timestamp + 1 days, 1 ether);

        vm.prank(client);
        manager.disputeTask(taskId, 0);

        vm.expectRevert(AgentBondManager.NoValidationResponse.selector);
        manager.resolveDispute(taskId);
    }

    function test_resolveDispute_validationPolicySnapshottedAtDispute() public {
        vm.prank(agentOwner);
        manager.depositBond(agentId, 10 ether);

        uint256 taskId = _createTask(keccak256("pending-policy-snapshot"), block.timestamp + 1 days, 1 ether);

        vm.prank(client);
        manager.disputeTask(taskId, 0);

        manager.setValidationFinalityPolicy(FINALITY_POLICY_ANY_STATUS_RECORD);

        bytes32 reqHash = manager.requestHash(taskId);
        validation.setValidation(reqHash, validator, agentId, 0, false);

        vm.expectRevert(AgentBondManager.NoValidationResponse.selector);
        manager.resolveDispute(taskId);
    }

    function test_resolveDispute_revertsWithoutValidation_whenUnknownReverts() public {
        vm.prank(agentOwner);
        manager.depositBond(agentId, 10 ether);

        uint256 taskId = _createTask(keccak256("unknown-no-validation"), block.timestamp + 1 days, 1 ether);

        vm.prank(client);
        manager.disputeTask(taskId, 0);

        validation.setUnknownReverts(true);

        vm.expectRevert(AgentBondManager.NoValidationResponse.selector);
        manager.resolveDispute(taskId);
    }

    // --- Reclaim & Expiry Tests ---

    function test_reclaimDisputedTask() public {
        vm.prank(agentOwner);
        manager.depositBond(agentId, 10 ether);

        uint256 taskId = _createTask(keccak256("abandoned"), block.timestamp + 1 days, 1 ether);

        vm.prank(client);
        manager.disputeTask(taskId, 0);

        vm.warp(block.timestamp + DISPUTE_PERIOD + 1);
        manager.reclaimDisputedTask(taskId);

        uint256 expectedSlash = (1 ether * SLASH_BPS) / 10_000;
        assertEq(manager.claimable(client), 1 ether + expectedSlash);

        AgentBondManager.Task memory task = manager.getTask(taskId);
        assertTrue(task.status == AgentBondManager.TaskStatus.Slashed);
    }

    function test_reclaimDisputedTask_slashesWhenValidationPending() public {
        vm.prank(agentOwner);
        manager.depositBond(agentId, 10 ether);

        uint256 taskId = _createTask(keccak256("pending-reclaim"), block.timestamp + 1 days, 1 ether);

        vm.prank(client);
        manager.disputeTask(taskId, 0);

        bytes32 reqHash = manager.requestHash(taskId);
        validation.setValidation(reqHash, validator, agentId, 0, false);

        vm.warp(block.timestamp + DISPUTE_PERIOD + 1);
        manager.reclaimDisputedTask(taskId);

        AgentBondManager.Task memory task = manager.getTask(taskId);
        assertTrue(task.status == AgentBondManager.TaskStatus.Slashed);
    }

    function test_reclaimDisputedTask_unknownRevertSlashes() public {
        vm.prank(agentOwner);
        manager.depositBond(agentId, 10 ether);

        address clientRecipient_ = makeAddr("client-reclaim-slash-recipient");
        uint256 taskId = _createTaskWithRecipients(
            keccak256("unknown-reclaim"), block.timestamp + 1 days, 1 ether, agentOwner, clientRecipient_
        );

        vm.prank(client);
        manager.disputeTask(taskId, 0);

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
        manager.depositBond(agentId, 10 ether);

        uint256 taskId = _createTask(keccak256("status-revert-reclaim"), block.timestamp + 1 days, 1 ether);

        vm.prank(client);
        manager.disputeTask(taskId, 0);

        validation.setForceStatusRevert(true, "custom status error");
        vm.warp(block.timestamp + DISPUTE_PERIOD + 1);

        manager.reclaimDisputedTask(taskId);

        AgentBondManager.Task memory task = manager.getTask(taskId);
        assertTrue(task.status == AgentBondManager.TaskStatus.Slashed);
        assertEq(manager.registryFailureSince(taskId), 0);
    }

    function test_reclaimDisputedTask_canonicalFailureUsesCachedRequestKnownness_knownRequest() public {
        vm.prank(agentOwner);
        manager.depositBond(agentId, 10 ether);

        uint256 taskId = _createTask(keccak256("cached-known-request"), block.timestamp + 1 days, 1 ether);
        bytes32 reqHash = manager.requestHash(taskId);
        validation.setValidation(reqHash, validator, agentId, 0, false);

        vm.prank(client);
        manager.disputeTask(taskId, 0);

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
        manager.depositBond(agentId, 10 ether);

        uint256 taskId = _createTask(keccak256("cached-unknown-request"), block.timestamp + 1 days, 1 ether);
        bytes32 reqHash = manager.requestHash(taskId);

        vm.prank(client);
        manager.disputeTask(taskId, 0);

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
        manager.depositBond(agentId, 10 ether);

        uint256 taskId = _createTask(keccak256("status-revert-known-request"), block.timestamp + 1 days, 1 ether);
        bytes32 reqHash = manager.requestHash(taskId);
        validation.setValidation(reqHash, validator, agentId, 0, false);

        vm.prank(client);
        manager.disputeTask(taskId, 0);

        validation.setForceStatusRevert(true, "custom status error");
        vm.warp(block.timestamp + DISPUTE_PERIOD + 1);

        manager.reclaimDisputedTask(taskId);

        assertGt(manager.registryFailureSince(taskId), 0);
        assertTrue(manager.getTask(taskId).status == AgentBondManager.TaskStatus.Disputed);
    }

    function test_reclaimDisputedTask_statusRevertSlashesWhenPolicyAlwaysMissing() public {
        vm.prank(agentOwner);
        manager.depositBond(agentId, 10 ether);

        uint256 taskId = _createTask(keccak256("status-revert-missing"), block.timestamp + 1 days, 1 ether);

        vm.prank(client);
        manager.disputeTask(taskId, 0);

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
        manager.depositBond(agentId, 20 ether);

        manager.setStatusLookupFailurePolicy(STATUS_LOOKUP_POLICY_ALWAYS_MISSING);
        uint256 slashTaskId = _createTask(keccak256("non-canonical-missing"), block.timestamp + 1 days, 1 ether);
        vm.prank(client);
        manager.disputeTask(slashTaskId, 0);

        manager.setStatusLookupFailurePolicy(STATUS_LOOKUP_POLICY_ALWAYS_UNAVAILABLE);
        uint256 unavailableTaskId =
            _createTask(keccak256("non-canonical-unavailable"), block.timestamp + 1 days, 1 ether);
        vm.prank(client);
        manager.disputeTask(unavailableTaskId, 0);

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
        manager.depositBond(agentId, 10 ether);

        uint256 taskId = _createTask(keccak256("unsupported-request-state"), block.timestamp + 1 days, 1 ether);

        // Canonical cache cannot be populated if getAgentValidations reverts, so we record unsupported.
        validation.setForceRevert(true);
        vm.prank(client);
        manager.disputeTask(taskId, 0);

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
        manager.depositBond(agentId, 10 ether);

        uint256 taskId = _createTask(keccak256("scan-cap-request"), block.timestamp + 1 days, 1 ether);
        bytes32 reqHash = manager.requestHash(taskId);

        bytes32[] memory requestHashes = new bytes32[](513);
        for (uint256 i; i < requestHashes.length; i++) {
            requestHashes[i] = keccak256(abi.encode(i));
        }
        requestHashes[requestHashes.length - 1] = reqHash;
        validation.setAgentValidationsOverride(agentId, requestHashes);

        vm.prank(client);
        manager.disputeTask(taskId, 0);

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
        manager.depositBond(agentId, 10 ether);

        manager.setStatusLookupFailurePolicy(STATUS_LOOKUP_POLICY_ALWAYS_UNAVAILABLE);
        uint256 taskId = _createTask(keccak256("status-policy-snapshot"), block.timestamp + 1 days, 1 ether);

        vm.prank(client);
        manager.disputeTask(taskId, 0);

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
        manager.depositBond(agentId, 10 ether);

        uint256 taskId = _createTask(keccak256("validated"), block.timestamp + 1 days, 1 ether);

        vm.prank(client);
        manager.disputeTask(taskId, 0);

        bytes32 reqHash = manager.requestHash(taskId);
        validation.setValidation(reqHash, validator, agentId, 80, true);

        vm.warp(block.timestamp + DISPUTE_PERIOD + 1);

        vm.expectRevert(AgentBondManager.ValidationExists.selector);
        manager.reclaimDisputedTask(taskId);
    }

    function test_reclaimDisputedTask_revertsIfPeriodActive() public {
        vm.prank(agentOwner);
        manager.depositBond(agentId, 10 ether);

        uint256 taskId = _createTask(keccak256("task"), block.timestamp + 1 days, 1 ether);

        vm.prank(client);
        manager.disputeTask(taskId, 0);

        vm.expectRevert(AgentBondManager.DisputePeriodActive.selector);
        manager.reclaimDisputedTask(taskId);
    }

    function test_claimExpiredTask() public {
        vm.prank(agentOwner);
        manager.depositBond(agentId, 10 ether);

        uint256 taskId = _createTask(keccak256("task"), block.timestamp + 1 days, 1 ether);

        vm.warp(block.timestamp + 1 days + 1);
        manager.claimExpiredTask(taskId);

        assertEq(manager.claimable(agentOwner), 1 ether);

        AgentBondManager.Task memory task = manager.getTask(taskId);
        assertTrue(task.status == AgentBondManager.TaskStatus.Expired);
    }

    function test_claimExpiredTask_revertsBeforeDeadline() public {
        vm.prank(agentOwner);
        manager.depositBond(agentId, 10 ether);

        uint256 taskId = _createTask(keccak256("task"), block.timestamp + 1 days, 1 ether);

        vm.expectRevert(AgentBondManager.NotExpired.selector);
        manager.claimExpiredTask(taskId);
    }

    function test_disputeTask_revertsAfterDeadline() public {
        vm.prank(agentOwner);
        manager.depositBond(agentId, 10 ether);

        uint256 taskId = _createTask(keccak256("task"), block.timestamp + 1 days, 1 ether);

        vm.warp(block.timestamp + 1 days + 1);

        vm.prank(client);
        vm.expectRevert(AgentBondManager.DeadlinePassed.selector);
        manager.disputeTask(taskId, 0);
    }

    function test_completeTask_revertsAfterDeadline() public {
        vm.prank(agentOwner);
        manager.depositBond(agentId, 10 ether);

        uint256 taskId = _createTask(keccak256("task"), block.timestamp + 1 days, 1 ether);
        vm.warp(block.timestamp + 1 days + 1);

        vm.prank(client);
        vm.expectRevert(AgentBondManager.DeadlinePassed.selector);
        manager.completeTask(taskId);
    }

    // --- Pull Payment Tests ---

    function test_claim() public {
        vm.prank(agentOwner);
        manager.depositBond(agentId, 10 ether);

        uint256 taskId = _createTask(keccak256("task"), block.timestamp + 1 days, 2 ether);

        vm.prank(client);
        manager.completeTask(taskId);

        assertEq(manager.claimable(agentOwner), 2 ether);

        uint256 balBefore = settlementToken.balanceOf(agentOwner);
        vm.prank(agentOwner);
        manager.claim();

        assertEq(settlementToken.balanceOf(agentOwner), balBefore + 2 ether);
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
        manager.depositBond(agentId, 10 ether);

        uint256 taskId = _createTask(keccak256("snapshot"), block.timestamp + 1 days, 1 ether);

        // Change global params after task creation
        manager.setSlashBps(10_000);
        manager.setMinPassingScore(99);
        manager.setDisputePeriod(1 hours);

        AgentBondManager.Task memory task = manager.getTask(taskId);
        assertEq(task.snapshotSlashBps, SLASH_BPS);
        assertEq(task.snapshotMinPassingScore, MIN_PASSING_SCORE);
        assertEq(task.snapshotDisputePeriod, DISPUTE_PERIOD);
    }

    function test_snapshotSlashBps_usedInSlash() public {
        vm.prank(agentOwner);
        manager.depositBond(agentId, 10 ether);

        uint256 taskId = _createTask(keccak256("slash-snap"), block.timestamp + 1 days, 1 ether);

        // Double global slashBps after task creation
        manager.setSlashBps(10_000);

        vm.prank(client);
        manager.disputeTask(taskId, 0);

        bytes32 reqHash = manager.requestHash(taskId);
        validation.setValidation(reqHash, validator, agentId, 30, true);
        manager.resolveDispute(taskId);

        // Slash uses the snapshot (5000), not the new global (10000)
        uint256 expectedSlash = (1 ether * SLASH_BPS) / 10_000;
        assertEq(manager.claimable(client), 1 ether + expectedSlash);
    }

    function test_snapshotMinPassingScore_usedInResolve() public {
        vm.prank(agentOwner);
        manager.depositBond(agentId, 10 ether);

        uint256 taskId = _createTask(keccak256("mps-snap"), block.timestamp + 1 days, 1 ether);

        // Lower global minPassingScore below the validation response
        manager.setMinPassingScore(10);

        vm.prank(client);
        manager.disputeTask(taskId, 0);

        // Response is 30, snapshot minPassingScore is 50 → slash
        bytes32 reqHash = manager.requestHash(taskId);
        validation.setValidation(reqHash, validator, agentId, 30, true);
        manager.resolveDispute(taskId);

        AgentBondManager.Task memory task = manager.getTask(taskId);
        assertTrue(task.status == AgentBondManager.TaskStatus.Slashed);
    }

    // --- Scorer Tests ---

    function test_scorer_noData_zeroScore() public view {
        (uint256 score, uint64 count) = scorer.getScore(agentId);
        assertEq(score, 0);
        assertEq(count, 0);
        assertEq(scorer.getRequiredBond(agentId, 1 ether), 1 ether);
    }

    function test_scorer_successOutcome_lowersBond() public {
        vm.prank(agentOwner);
        manager.depositBond(agentId, 20 ether);

        uint256 taskId = _createTask(keccak256("success-outcome"), block.timestamp + 1 days, 1 ether);
        vm.prank(client);
        manager.completeTask(taskId);

        (uint256 score, uint64 count) = scorer.getScore(agentId);
        assertEq(count, 1);
        assertEq(score, _expectedScore(1 ether, 0));
        assertLt(scorer.getRequiredBond(agentId, 1 ether), 1 ether);
    }

    function test_scorer_mixedOutcomes_balancesWinsAndSlashes() public {
        vm.prank(agentOwner);
        manager.depositBond(agentId, 30 ether);

        // Success outcome
        uint256 successTaskId = _createTask(keccak256("mixed-success"), block.timestamp + 1 days, 2 ether);
        vm.prank(client);
        manager.completeTask(successTaskId);

        // Slashed outcome
        uint256 slashTaskId = _createTask(keccak256("mixed-slash"), block.timestamp + 1 days, 1 ether);
        uint256 slashBondLocked = manager.getTask(slashTaskId).bondLocked;
        vm.prank(client);
        manager.disputeTask(slashTaskId, 0);
        validation.setValidation(manager.requestHash(slashTaskId), validator, agentId, 10, true);
        manager.resolveDispute(slashTaskId);

        uint256 slashAmount = (1 ether * SLASH_BPS) / 10_000;
        if (slashAmount > slashBondLocked) {
            slashAmount = slashBondLocked;
        }
        (uint256 score, uint64 count) = scorer.getScore(agentId);
        assertEq(count, 2);
        assertEq(score, _expectedScore(2 ether, 1 ether + slashAmount));

        uint256 requiredBond = scorer.getRequiredBond(agentId, 1 ether);
        assertGt(requiredBond, 0);
        assertLt(requiredBond, 1 ether);
    }

    function test_scorer_slashOnly_staysAtMaxBond() public {
        vm.prank(agentOwner);
        manager.depositBond(agentId, 10 ether);

        uint256 taskId = _createTask(keccak256("slash-only"), block.timestamp + 1 days, 1 ether);
        vm.prank(client);
        manager.disputeTask(taskId, 0);
        validation.setValidation(manager.requestHash(taskId), validator, agentId, 0, true);
        manager.resolveDispute(taskId);

        (uint256 score, uint64 count) = scorer.getScore(agentId);
        assertEq(count, 1);
        assertEq(score, 0);
        assertEq(scorer.getRequiredBond(agentId, 1 ether), 1 ether);
    }

    function test_manager_tracksOutcomeCounters() public {
        vm.prank(agentOwner);
        manager.depositBond(agentId, 30 ether);

        uint256 completeTaskId = _createTask(keccak256("counter-complete"), block.timestamp + 1 days, 2 ether);
        vm.prank(client);
        manager.completeTask(completeTaskId);

        uint256 slashTaskId = _createTask(keccak256("counter-slash"), block.timestamp + 1 days, 1 ether);
        uint256 slashBondLocked = manager.getTask(slashTaskId).bondLocked;
        vm.prank(client);
        manager.disputeTask(slashTaskId, 0);
        validation.setValidation(manager.requestHash(slashTaskId), validator, agentId, 0, true);
        manager.resolveDispute(slashTaskId);

        uint256 neutralTaskId = _createTask(keccak256("counter-neutral"), block.timestamp + 1 days, 1 ether);
        bytes32 neutralReqHash = manager.requestHash(neutralTaskId);
        validation.setValidation(neutralReqHash, validator, agentId, 0, false);
        vm.prank(client);
        manager.disputeTask(neutralTaskId, 0);
        validation.setForceRevert(true);
        vm.warp(block.timestamp + DISPUTE_PERIOD + 1);
        manager.reclaimDisputedTask(neutralTaskId);
        vm.warp(block.timestamp + 3 days + 1);
        manager.reclaimDisputedTask(neutralTaskId);

        (
            uint256 successValue,
            uint256 slashValue,
            uint64 successCount,
            uint64 slashCount,
            uint256 slashAmount,
            uint64 neutralCount
        ) = manager.getAgentOutcomeTotals(agentId);
        uint256 expectedSlashAmount = (1 ether * SLASH_BPS) / 10_000;
        if (expectedSlashAmount > slashBondLocked) {
            expectedSlashAmount = slashBondLocked;
        }

        assertEq(successValue, 2 ether);
        assertEq(slashValue, 1 ether + expectedSlashAmount);
        assertEq(successCount, 1);
        assertEq(slashCount, 1);
        assertEq(slashAmount, expectedSlashAmount);
        assertEq(neutralCount, 1);
    }

    // --- Multi-task Tests ---

    function test_multipleTasks_lockCumulatively() public {
        vm.prank(agentOwner);
        manager.depositBond(agentId, 10 ether);

        _createTask(keccak256("t1"), block.timestamp + 1 days, 3 ether);
        _createTask(keccak256("t2"), block.timestamp + 1 days, 2 ether);

        (, uint256 locked) = manager.getBond(agentId);
        assertEq(locked, 5 ether);
        assertEq(manager.availableBond(agentId), 5 ether);
    }

    function test_multipleTasks_independentResolution() public {
        vm.prank(agentOwner);
        manager.depositBond(agentId, 10 ether);

        uint256 id1 = _createTask(keccak256("t1"), block.timestamp + 1 days, 2 ether);
        uint256 id2 = _createTask(keccak256("t2"), block.timestamp + 1 days, 3 ether);

        vm.prank(client);
        manager.completeTask(id1);

        vm.prank(client);
        manager.disputeTask(id2, 0);

        validation.setValidation(manager.requestHash(id2), validator, agentId, 75, true);
        manager.resolveDispute(id2);

        (, uint256 locked) = manager.getBond(agentId);
        assertEq(locked, 0);
        (uint256 amt,) = manager.getBond(agentId);
        assertEq(amt, 10 ether);
    }

    function test_sameTaskHash_differentRequestHash_cannotReuse() public {
        vm.prank(agentOwner);
        manager.depositBond(agentId, 20 ether);

        bytes32 sharedHash = keccak256("same-spec");

        uint256 id1 = _createTask(sharedHash, block.timestamp + 1 days, 1 ether);
        uint256 id2 = _createTask(sharedHash, block.timestamp + 1 days, 5 ether);

        bytes32 req1 = manager.requestHash(id1);
        bytes32 req2 = manager.requestHash(id2);
        assertTrue(req1 != req2);

        vm.startPrank(client);
        manager.disputeTask(id1, 0);
        manager.disputeTask(id2, 0);
        vm.stopPrank();

        validation.setValidation(req1, validator, agentId, 80, true);
        manager.resolveDispute(id1);

        vm.expectRevert(AgentBondManager.NoValidationResponse.selector);
        manager.resolveDispute(id2);

        assertTrue(manager.getTask(id2).status == AgentBondManager.TaskStatus.Disputed);
    }

    function test_identicalTaskParams_differentRequestHash() public {
        vm.prank(agentOwner);
        manager.depositBond(agentId, 20 ether);

        bytes32 taskHash = keccak256("repeated-job");

        uint256 id1 = _createTask(taskHash, block.timestamp + 1 days, 1 ether);
        uint256 id2 = _createTask(taskHash, block.timestamp + 1 days, 1 ether);

        assertTrue(manager.requestHash(id1) != manager.requestHash(id2));
    }

    // --- UUPS Tests ---

    function test_cannotReinitialize() public {
        vm.expectRevert();
        manager.initialize(
            address(identity),
            address(validation),
            address(scorer),
            address(settlementToken),
            DISPUTE_PERIOD,
            MIN_PASSING_SCORE,
            SLASH_BPS
        );
    }

    function test_cannotReinitializeScorer() public {
        vm.expectRevert();
        scorer.initialize(SCORER_PRIOR_VALUE, SCORER_SLASH_MULTIPLIER_BPS);
    }

    function test_initialize_rejectsDisputePeriodBelowMin() public {
        AgentBondManager managerImpl = new AgentBondManager();
        vm.expectRevert(AgentBondManager.InvalidParameter.selector);
        new ERC1967Proxy(
            address(managerImpl),
            abi.encodeCall(
                AgentBondManager.initialize,
                (
                    address(identity),
                    address(validation),
                    address(scorer),
                    address(settlementToken),
                    1,
                    MIN_PASSING_SCORE,
                    SLASH_BPS
                )
            )
        );
    }

    function test_initialize_rejectsIdentityRegistryWithoutCode() public {
        AgentBondManager managerImpl = new AgentBondManager();
        vm.expectRevert(AgentBondManager.AddressWithoutCode.selector);
        new ERC1967Proxy(
            address(managerImpl),
            abi.encodeCall(
                AgentBondManager.initialize,
                (
                    makeAddr("no-code-identity"),
                    address(validation),
                    address(scorer),
                    address(settlementToken),
                    DISPUTE_PERIOD,
                    MIN_PASSING_SCORE,
                    SLASH_BPS
                )
            )
        );
    }

    function test_initialize_rejectsValidationRegistryWithoutCode() public {
        AgentBondManager managerImpl = new AgentBondManager();
        vm.expectRevert(AgentBondManager.AddressWithoutCode.selector);
        new ERC1967Proxy(
            address(managerImpl),
            abi.encodeCall(
                AgentBondManager.initialize,
                (
                    address(identity),
                    makeAddr("no-code-validation"),
                    address(scorer),
                    address(settlementToken),
                    DISPUTE_PERIOD,
                    MIN_PASSING_SCORE,
                    SLASH_BPS
                )
            )
        );
    }

    function test_initialize_rejectsScorerWithoutCode() public {
        AgentBondManager managerImpl = new AgentBondManager();
        vm.expectRevert(AgentBondManager.AddressWithoutCode.selector);
        new ERC1967Proxy(
            address(managerImpl),
            abi.encodeCall(
                AgentBondManager.initialize,
                (
                    address(identity),
                    address(validation),
                    makeAddr("no-code-scorer"),
                    address(settlementToken),
                    DISPUTE_PERIOD,
                    MIN_PASSING_SCORE,
                    SLASH_BPS
                )
            )
        );
    }

    function test_initialize_rejectsSettlementTokenWithoutCode() public {
        AgentBondManager managerImpl = new AgentBondManager();
        vm.expectRevert(AgentBondManager.AddressWithoutCode.selector);
        new ERC1967Proxy(
            address(managerImpl),
            abi.encodeCall(
                AgentBondManager.initialize,
                (
                    address(identity),
                    address(validation),
                    address(scorer),
                    makeAddr("no-code-settlement"),
                    DISPUTE_PERIOD,
                    MIN_PASSING_SCORE,
                    SLASH_BPS
                )
            )
        );
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

    function test_setDisputePeriod_rejectsBelowMin() public {
        vm.expectRevert(AgentBondManager.InvalidParameter.selector);
        manager.setDisputePeriod(1);
    }

    function test_setMinValidatorFee_rejectsAboveCap() public {
        uint256 cap = 1_000_000 * (10 ** uint256(settlementToken.decimals()));
        vm.expectRevert(AgentBondManager.InvalidParameter.selector);
        manager.setMinValidatorFee(cap + 1);
    }

    function test_setMinValidatorFee_acceptsCapBoundary() public {
        uint256 cap = 1_000_000 * (10 ** uint256(settlementToken.decimals()));
        manager.setMinValidatorFee(cap);
        assertEq(manager.minValidatorFee(), cap);
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

    function test_setValidatorSelectionPolicy_acceptsValues() public {
        manager.setValidatorSelectionPolicy(VALIDATOR_SELECTION_POLICY_DESIGNATED_AND_ALLOWLISTED);
        assertEq(uint8(manager.validatorSelectionPolicy()), VALIDATOR_SELECTION_POLICY_DESIGNATED_AND_ALLOWLISTED);
        manager.setValidatorSelectionPolicy(VALIDATOR_SELECTION_POLICY_DESIGNATED_ONLY);
        assertEq(uint8(manager.validatorSelectionPolicy()), VALIDATOR_SELECTION_POLICY_DESIGNATED_ONLY);
    }

    function test_setValidatorSelectionPolicy_rejectsInvalid() public {
        vm.expectRevert(AgentBondManager.InvalidParameter.selector);
        manager.setValidatorSelectionPolicy(2);
    }

    function test_setMaxAgentTaskHistory_rejectsZero() public {
        vm.expectRevert(AgentBondManager.InvalidParameter.selector);
        manager.setMaxAgentTaskHistory(0);
    }

    function test_setPermit2_rejectsAddressWithoutCode() public {
        vm.expectRevert(AgentBondManager.AddressWithoutCode.selector);
        manager.setPermit2(makeAddr("no-code-permit2"));
    }

    function test_addTrustedValidator_andRemoveTrustedValidator() public {
        manager.addTrustedValidator(validator);
        assertTrue(manager.trustedValidators(validator));

        manager.removeTrustedValidator(validator);
        assertFalse(manager.trustedValidators(validator));
    }

    function test_addTrustedValidator_rejectsDuplicate() public {
        manager.addTrustedValidator(validator);
        vm.expectRevert(AgentBondManager.InvalidParameter.selector);
        manager.addTrustedValidator(validator);
    }

    function test_removeTrustedValidator_rejectsUnknownValidator() public {
        vm.expectRevert(AgentBondManager.InvalidParameter.selector);
        manager.removeTrustedValidator(validator);
    }

    // --- Scorer configuration validation ---

    function test_scorer_rejectsZeroPriorValue() public {
        ReputationScorer scorerImpl = new ReputationScorer();
        vm.expectRevert(ReputationScorer.InvalidParameter.selector);
        new ERC1967Proxy(address(scorerImpl), abi.encodeCall(ReputationScorer.initialize, (0, SCORER_SLASH_MULTIPLIER_BPS)));
    }

    function test_scorer_rejectsLowSlashMultiplier() public {
        ReputationScorer scorerImpl = new ReputationScorer();
        vm.expectRevert(ReputationScorer.InvalidParameter.selector);
        new ERC1967Proxy(address(scorerImpl), abi.encodeCall(ReputationScorer.initialize, (SCORER_PRIOR_VALUE, 9_999)));
    }

    function test_scorer_setBondManager_onlyOwnerOnce() public {
        ReputationScorer scorerImpl = new ReputationScorer();
        ERC1967Proxy scorerProxy =
            new ERC1967Proxy(address(scorerImpl), abi.encodeCall(ReputationScorer.initialize, (1 ether, 15_000)));
        ReputationScorer localScorer = ReputationScorer(address(scorerProxy));

        vm.prank(client);
        vm.expectRevert(ReputationScorer.NotOwner.selector);
        localScorer.setBondManager(address(manager));

        localScorer.setBondManager(address(manager));

        vm.expectRevert(ReputationScorer.BondManagerAlreadyConfigured.selector);
        localScorer.setBondManager(address(identity));
    }

    // --- P2b: Mismatched agentId liveness lock ---

    function test_reclaimDisputedTask_succeedsWithMismatchedAgentId() public {
        vm.prank(agentOwner);
        manager.depositBond(agentId, 10 ether);

        uint256 taskId = _createTask(keccak256("mismatch"), block.timestamp + 1 days, 1 ether);

        vm.prank(client);
        manager.disputeTask(taskId, 0);

        bytes32 reqHash = manager.requestHash(taskId);
        validation.setValidation(reqHash, validator, agentId + 1, 80, true);

        vm.warp(block.timestamp + DISPUTE_PERIOD + 1);
        manager.reclaimDisputedTask(taskId);

        AgentBondManager.Task memory task = manager.getTask(taskId);
        assertTrue(task.status == AgentBondManager.TaskStatus.Slashed);
    }

    function test_resolveDispute_revertsOnMismatchedAgentId() public {
        vm.prank(agentOwner);
        manager.depositBond(agentId, 10 ether);

        uint256 taskId = _createTask(keccak256("mismatch-resolve"), block.timestamp + 1 days, 1 ether);

        vm.prank(client);
        manager.disputeTask(taskId, 0);

        bytes32 reqHash = manager.requestHash(taskId);
        validation.setValidation(reqHash, validator, agentId + 1, 80, true);

        vm.expectRevert(AgentBondManager.AgentMismatch.selector);
        manager.resolveDispute(taskId);
    }

    function test_resolveDispute_revertsOnValidatorMismatch() public {
        vm.prank(agentOwner);
        manager.depositBond(agentId, 10 ether);

        uint256 taskId = _createTask(keccak256("validator-mismatch-resolve"), block.timestamp + 1 days, 1 ether);

        vm.prank(client);
        manager.disputeTask(taskId, 0);

        bytes32 reqHash = manager.requestHash(taskId);
        validation.setValidation(reqHash, makeAddr("other-validator"), agentId, 80, true);

        vm.expectRevert(AgentBondManager.ValidatorMismatch.selector);
        manager.resolveDispute(taskId);
    }

    function test_reclaimDisputedTask_slashesWhenValidatorMismatched() public {
        vm.prank(agentOwner);
        manager.depositBond(agentId, 10 ether);

        uint256 taskId = _createTask(keccak256("validator-mismatch-reclaim"), block.timestamp + 1 days, 1 ether);

        vm.prank(client);
        manager.disputeTask(taskId, 0);

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

    function test_scorer_setBondManager_rejectsZeroAddress() public {
        ReputationScorer scorerImpl = new ReputationScorer();
        ERC1967Proxy scorerProxy =
            new ERC1967Proxy(address(scorerImpl), abi.encodeCall(ReputationScorer.initialize, (1 ether, 15_000)));
        ReputationScorer localScorer = ReputationScorer(address(scorerProxy));

        vm.expectRevert(ReputationScorer.ZeroAddress.selector);
        localScorer.setBondManager(address(0));
    }

    function test_scorer_setBondManager_rejectsAddressWithoutCode() public {
        ReputationScorer scorerImpl = new ReputationScorer();
        ERC1967Proxy scorerProxy =
            new ERC1967Proxy(address(scorerImpl), abi.encodeCall(ReputationScorer.initialize, (1 ether, 15_000)));
        ReputationScorer localScorer = ReputationScorer(address(scorerProxy));

        vm.expectRevert(ReputationScorer.AddressWithoutCode.selector);
        localScorer.setBondManager(makeAddr("no-code-bond-manager"));
    }

    function test_scorer_getScore_revertsWhenBondManagerUnset() public {
        ReputationScorer scorerImpl = new ReputationScorer();
        ERC1967Proxy scorerProxy =
            new ERC1967Proxy(address(scorerImpl), abi.encodeCall(ReputationScorer.initialize, (1 ether, 15_000)));
        ReputationScorer localScorer = ReputationScorer(address(scorerProxy));

        vm.expectRevert(ReputationScorer.BondManagerNotConfigured.selector);
        localScorer.getScore(agentId);
    }

    // --- Registry failure grace window ---

    function test_reclaimDisputedTask_registryFailure_firstCallRecordsTimestamp() public {
        vm.prank(agentOwner);
        manager.depositBond(agentId, 10 ether);

        uint256 taskId = _createTask(keccak256("grace"), block.timestamp + 1 days, 1 ether);
        bytes32 reqHash = manager.requestHash(taskId);
        validation.setValidation(reqHash, validator, agentId, 0, false);

        vm.prank(client);
        manager.disputeTask(taskId, 0);

        validation.setForceRevert(true);
        vm.warp(block.timestamp + DISPUTE_PERIOD + 1);

        manager.reclaimDisputedTask(taskId);

        assertGt(manager.registryFailureSince(taskId), 0);
        assertTrue(manager.getTask(taskId).status == AgentBondManager.TaskStatus.Disputed);
    }

    function test_reclaimDisputedTask_registryFailure_revertsWithinGrace() public {
        vm.prank(agentOwner);
        manager.depositBond(agentId, 10 ether);

        uint256 taskId = _createTask(keccak256("grace2"), block.timestamp + 1 days, 1 ether);
        bytes32 reqHash = manager.requestHash(taskId);
        validation.setValidation(reqHash, validator, agentId, 0, false);

        vm.prank(client);
        manager.disputeTask(taskId, 0);

        validation.setForceRevert(true);
        vm.warp(block.timestamp + DISPUTE_PERIOD + 1);

        manager.reclaimDisputedTask(taskId);

        vm.warp(block.timestamp + 1 days);
        vm.expectRevert(AgentBondManager.RegistryUnavailable.selector);
        manager.reclaimDisputedTask(taskId);
    }

    function test_reclaimDisputedTask_registryFailure_refundsAfterGrace() public {
        vm.prank(agentOwner);
        manager.depositBond(agentId, 10 ether);

        uint256 taskId = _createTask(keccak256("grace3"), block.timestamp + 1 days, 1 ether);
        bytes32 reqHash = manager.requestHash(taskId);
        validation.setValidation(reqHash, validator, agentId, 0, false);

        vm.prank(client);
        manager.disputeTask(taskId, 0);

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
        manager.depositBond(agentId, 10 ether);

        address clientRecipient_ = makeAddr("client-refund-recipient");
        uint256 taskId = _createTaskWithRecipients(
            keccak256("grace-custom-recipient"), block.timestamp + 1 days, 1 ether, agentOwner, clientRecipient_
        );
        bytes32 reqHash = manager.requestHash(taskId);
        validation.setValidation(reqHash, validator, agentId, 0, false);

        vm.prank(client);
        manager.disputeTask(taskId, 0);

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
        manager.depositBond(agentId, 10 ether);

        uint256 taskId = _createTask(keccak256("grace4"), block.timestamp + 1 days, 1 ether);
        bytes32 reqHash = manager.requestHash(taskId);
        validation.setValidation(reqHash, validator, agentId, 0, false);

        vm.prank(client);
        manager.disputeTask(taskId, 0);

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
        manager.depositBond(agentId, 10 ether);

        uint256 taskId = _createTask(keccak256("snap-grace"), block.timestamp + 1 days, 1 ether);
        bytes32 reqHash = manager.requestHash(taskId);
        validation.setValidation(reqHash, validator, agentId, 0, false);

        vm.prank(client);
        manager.disputeTask(taskId, 0);

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

    function testFuzz_completeTask_creditsExpectedPayment(uint96 paymentRaw) public {
        uint256 payment = bound(uint256(paymentRaw), 1, 1_000 ether);

        vm.prank(agentOwner);
        manager.depositBond(agentId, 20_000 ether);

        uint256 taskId = _createTask(keccak256("fuzz-complete"), block.timestamp + 1 days, payment);

        vm.prank(client);
        manager.completeTask(taskId);

        AgentBondManager.Task memory task = manager.getTask(taskId);
        assertTrue(task.status == AgentBondManager.TaskStatus.Completed);
        assertEq(manager.claimable(agentOwner), payment);
    }

    function testFuzz_resolveDispute_slashMathMatchesSnapshot(uint96 paymentRaw, uint8 responseRaw) public {
        uint256 payment = bound(uint256(paymentRaw), 1, 1_000 ether);
        uint8 response = uint8(bound(uint256(responseRaw), 0, MIN_PASSING_SCORE - 1));

        vm.prank(agentOwner);
        manager.depositBond(agentId, 20_000 ether);

        uint256 taskId = _createTask(keccak256("fuzz-slash"), block.timestamp + 1 days, payment);
        bytes32 reqHash = manager.requestHash(taskId);
        validation.setValidation(reqHash, validator, agentId, response, true);

        vm.prank(client);
        manager.disputeTask(taskId, 0);
        manager.resolveDispute(taskId);

        AgentBondManager.Task memory task = manager.getTask(taskId);
        uint256 expectedSlash = (task.bondLocked * task.snapshotSlashBps) / 10_000;
        assertTrue(task.status == AgentBondManager.TaskStatus.Slashed);
        assertEq(manager.claimable(client), payment + expectedSlash);
    }
}
