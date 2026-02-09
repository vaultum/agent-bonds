// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {MinimalValidationRegistry} from "../src/MinimalValidationRegistry.sol";

contract MinimalValidationRegistryTest is Test {
    MinimalValidationRegistry registry;

    address internal requester = makeAddr("requester");
    address internal validatorA = makeAddr("validatorA");
    address internal validatorB = makeAddr("validatorB");

    uint256 internal constant AGENT_ID = 7;
    bytes32 internal constant REQUEST_HASH = keccak256("request-hash");

    event ValidationRequested(
        bytes32 indexed requestHash, uint256 indexed agentId, address indexed requester, string tag, string requestUri
    );

    event ValidationResponded(
        bytes32 indexed requestHash,
        uint256 indexed agentId,
        address indexed validatorAddress,
        uint8 response,
        bytes32 responseHash,
        string tag,
        string responseUri
    );

    function setUp() public {
        registry = new MinimalValidationRegistry();
    }

    function test_validationRequest_recordsAndEmits() public {
        vm.expectEmit(true, true, true, true);
        emit ValidationRequested(REQUEST_HASH, AGENT_ID, requester, "quality", "ipfs://request");

        vm.prank(requester);
        registry.validationRequest(REQUEST_HASH, AGENT_ID, "quality", "ipfs://request");

        (
            address storedRequester,
            uint256 storedAgentId,
            string memory tag,
            string memory requestUri,
            uint256 createdAt,
            bool exists
        ) = registry.getValidationRequest(REQUEST_HASH);

        assertEq(storedRequester, requester);
        assertEq(storedAgentId, AGENT_ID);
        assertEq(tag, "quality");
        assertEq(requestUri, "ipfs://request");
        assertEq(createdAt, block.timestamp);
        assertTrue(exists);
    }

    function test_validationRequest_revertsOnDuplicate() public {
        vm.prank(requester);
        registry.validationRequest(REQUEST_HASH, AGENT_ID, "", "");

        vm.prank(requester);
        vm.expectRevert(MinimalValidationRegistry.RequestAlreadyExists.selector);
        registry.validationRequest(REQUEST_HASH, AGENT_ID, "", "");
    }

    function test_validationRequest_revertsOnInvalidInputs() public {
        vm.prank(requester);
        vm.expectRevert(MinimalValidationRegistry.ZeroRequestHash.selector);
        registry.validationRequest(bytes32(0), AGENT_ID, "", "");

        vm.prank(requester);
        vm.expectRevert(MinimalValidationRegistry.ZeroAgentId.selector);
        registry.validationRequest(REQUEST_HASH, 0, "", "");
    }

    function test_validationRequest_revertsOnOversizedTagOrUri() public {
        string memory longTag = new string(registry.MAX_TAG_LENGTH() + 1);
        string memory longUri = new string(registry.MAX_URI_LENGTH() + 1);

        vm.prank(requester);
        vm.expectRevert(MinimalValidationRegistry.TagTooLong.selector);
        registry.validationRequest(REQUEST_HASH, AGENT_ID, longTag, "ipfs://request");

        vm.prank(requester);
        vm.expectRevert(MinimalValidationRegistry.UriTooLong.selector);
        registry.validationRequest(REQUEST_HASH, AGENT_ID, "quality", longUri);
    }

    function test_validationResponse_recordsAndEmits() public {
        vm.prank(requester);
        registry.validationRequest(REQUEST_HASH, AGENT_ID, "quality", "ipfs://request");

        bytes32 responseHash = keccak256("response-hash");
        vm.expectEmit(true, true, true, true);
        emit ValidationResponded(REQUEST_HASH, AGENT_ID, validatorA, 88, responseHash, "quality", "ipfs://response");

        vm.prank(validatorA);
        registry.validationResponse(REQUEST_HASH, AGENT_ID, 88, responseHash, "quality", "ipfs://response");

        (
            address storedValidator,
            uint256 storedAgentId,
            uint8 response,
            bytes32 storedResponseHash,
            string memory tag,
            uint256 lastUpdate
        ) = registry.getValidationStatus(REQUEST_HASH);

        assertEq(storedValidator, validatorA);
        assertEq(storedAgentId, AGENT_ID);
        assertEq(response, 88);
        assertEq(storedResponseHash, responseHash);
        assertEq(tag, "quality");
        assertEq(lastUpdate, block.timestamp);
        assertEq(registry.getResponseUri(REQUEST_HASH), "ipfs://response");
    }

    function test_validationResponse_isPermissionless() public {
        address anyone = makeAddr("anyone");

        vm.prank(requester);
        registry.validationRequest(REQUEST_HASH, AGENT_ID, "", "");

        vm.prank(anyone);
        registry.validationResponse(REQUEST_HASH, AGENT_ID, 70, keccak256("permissionless"), "", "");

        (address validator,,,,,) = registry.getValidationStatus(REQUEST_HASH);
        assertEq(validator, anyone);
    }

    function test_validationResponse_revertsOnMissingRequest() public {
        vm.prank(validatorA);
        vm.expectRevert(MinimalValidationRegistry.RequestNotFound.selector);
        registry.validationResponse(REQUEST_HASH, AGENT_ID, 80, keccak256("missing"), "", "");
    }

    function test_validationResponse_revertsOnMismatchedAgent() public {
        vm.prank(requester);
        registry.validationRequest(REQUEST_HASH, AGENT_ID, "", "");

        vm.prank(validatorA);
        vm.expectRevert(MinimalValidationRegistry.AgentMismatch.selector);
        registry.validationResponse(REQUEST_HASH, AGENT_ID + 1, 80, keccak256("mismatch"), "", "");
    }

    function test_validationResponse_revertsOnInvalidResponseAndDuplicate() public {
        vm.prank(requester);
        registry.validationRequest(REQUEST_HASH, AGENT_ID, "", "");

        vm.prank(validatorA);
        vm.expectRevert(MinimalValidationRegistry.InvalidResponse.selector);
        registry.validationResponse(REQUEST_HASH, AGENT_ID, 101, keccak256("invalid"), "", "");

        vm.prank(validatorA);
        registry.validationResponse(REQUEST_HASH, AGENT_ID, 80, keccak256("first"), "", "");

        vm.prank(validatorB);
        vm.expectRevert(MinimalValidationRegistry.ResponseAlreadyExists.selector);
        registry.validationResponse(REQUEST_HASH, AGENT_ID, 90, keccak256("second"), "", "");
    }

    function test_validationResponse_revertsOnZeroAgentId() public {
        vm.prank(requester);
        registry.validationRequest(REQUEST_HASH, AGENT_ID, "", "");

        vm.prank(validatorA);
        vm.expectRevert(MinimalValidationRegistry.ZeroAgentId.selector);
        registry.validationResponse(REQUEST_HASH, 0, 80, keccak256("zero-agent"), "", "");
    }

    function test_validationResponse_revertsOnZeroResponseHash() public {
        vm.prank(requester);
        registry.validationRequest(REQUEST_HASH, AGENT_ID, "", "");

        vm.prank(validatorA);
        vm.expectRevert(MinimalValidationRegistry.ZeroResponseHash.selector);
        registry.validationResponse(REQUEST_HASH, AGENT_ID, 80, bytes32(0), "", "");
    }

    function test_validationResponse_revertsOnOversizedTagOrUri() public {
        vm.prank(requester);
        registry.validationRequest(REQUEST_HASH, AGENT_ID, "", "");

        string memory longTag = new string(registry.MAX_TAG_LENGTH() + 1);
        string memory longUri = new string(registry.MAX_URI_LENGTH() + 1);

        vm.prank(validatorA);
        vm.expectRevert(MinimalValidationRegistry.TagTooLong.selector);
        registry.validationResponse(REQUEST_HASH, AGENT_ID, 80, keccak256("long-tag"), longTag, "");

        vm.prank(validatorA);
        vm.expectRevert(MinimalValidationRegistry.UriTooLong.selector);
        registry.validationResponse(REQUEST_HASH, AGENT_ID, 80, keccak256("long-uri"), "", longUri);
    }

    function test_getValidationStatus_returnsZeroValuesWhenMissing() public view {
        (
            address validatorAddress,
            uint256 agentId,
            uint8 response,
            bytes32 responseHash,
            string memory tag,
            uint256 lastUpdate
        ) = registry.getValidationStatus(bytes32(uint256(123)));

        assertEq(validatorAddress, address(0));
        assertEq(agentId, 0);
        assertEq(response, 0);
        assertEq(responseHash, bytes32(0));
        assertEq(bytes(tag).length, 0);
        assertEq(lastUpdate, 0);
    }

    function test_getResponseUri_returnsEmptyWhenMissing() public view {
        assertEq(bytes(registry.getResponseUri(bytes32(uint256(404)))).length, 0);
    }

    function test_getSummary_allTags() public {
        bytes32 r1 = keccak256("r1");
        bytes32 r2 = keccak256("r2");

        vm.prank(requester);
        registry.validationRequest(r1, AGENT_ID, "", "");
        vm.prank(requester);
        registry.validationRequest(r2, AGENT_ID, "", "");

        vm.prank(validatorA);
        registry.validationResponse(r1, AGENT_ID, 80, keccak256("r1"), "quality", "");
        vm.prank(validatorB);
        registry.validationResponse(r2, AGENT_ID, 40, keccak256("r2"), "speed", "");

        address[] memory validators = new address[](2);
        validators[0] = validatorA;
        validators[1] = validatorB;

        (uint64 count, uint8 avgResponse) = registry.getSummary(AGENT_ID, validators, "");
        assertEq(count, 2);
        assertEq(avgResponse, 60);
    }

    function test_getSummary_filtersByTagAndValidatorSet() public {
        bytes32 r1 = keccak256("r1");
        bytes32 r2 = keccak256("r2");
        bytes32 r3 = keccak256("r3");

        vm.startPrank(requester);
        registry.validationRequest(r1, AGENT_ID, "", "");
        registry.validationRequest(r2, AGENT_ID, "", "");
        registry.validationRequest(r3, AGENT_ID, "", "");
        vm.stopPrank();

        vm.prank(validatorA);
        registry.validationResponse(r1, AGENT_ID, 90, keccak256("f1"), "quality", "");
        vm.prank(validatorA);
        registry.validationResponse(r2, AGENT_ID, 30, keccak256("f2"), "speed", "");
        vm.prank(validatorB);
        registry.validationResponse(r3, AGENT_ID, 70, keccak256("f3"), "quality", "");

        address[] memory onlyA = new address[](1);
        onlyA[0] = validatorA;
        (uint64 countA, uint8 avgA) = registry.getSummary(AGENT_ID, onlyA, "quality");
        assertEq(countA, 1);
        assertEq(avgA, 90);

        address[] memory both = new address[](2);
        both[0] = validatorA;
        both[1] = validatorB;

        (uint64 countQuality, uint8 avgQuality) = registry.getSummary(AGENT_ID, both, "quality");
        assertEq(countQuality, 2);
        assertEq(avgQuality, 80);

        (uint64 countMissing, uint8 avgMissing) = registry.getSummary(AGENT_ID, both, "non-existent");
        assertEq(countMissing, 0);
        assertEq(avgMissing, 0);
    }
}
