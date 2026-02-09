// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {IERC8004Validation} from "./interfaces/IERC8004Validation.sol";

/// @title MinimalValidationRegistry
/// @author Vaultum
/// @custom:security-contact dev@vaultum.app
/// @notice Permissionless ERC-8004-style validation registry for testnets.
///         Anyone can open a validation request and anyone can post one response.
///         First response wins to keep dispute outcomes deterministic.
contract MinimalValidationRegistry is IERC8004Validation {
    struct ValidationRequestData {
        address requester;
        uint256 agentId;
        string tag;
        string requestUri;
        uint64 createdAt;
        bool exists;
    }

    struct ValidationData {
        address validatorAddress;
        uint256 agentId;
        uint8 response;
        bytes32 responseHash;
        string tag;
        string responseUri;
        uint64 lastUpdate;
    }

    struct Stats {
        uint64 count;
        uint128 totalResponse;
    }

    uint8 public constant MAX_RESPONSE = 100;
    uint256 public constant MAX_TAG_LENGTH = 64;
    uint256 public constant MAX_URI_LENGTH = 2048;

    mapping(bytes32 requestHash => ValidationRequestData) private _requests;
    mapping(bytes32 requestHash => ValidationData) private _responses;

    mapping(uint256 agentId => mapping(address validator => Stats)) private _validatorStats;
    mapping(uint256 agentId => mapping(address validator => mapping(bytes32 tagHash => Stats))) private
        _validatorTagStats;

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

    error ZeroRequestHash();
    error ZeroAgentId();
    error RequestAlreadyExists();
    error RequestNotFound();
    error ResponseAlreadyExists();
    error InvalidResponse();
    error ZeroResponseHash();
    error AgentMismatch();
    error TagTooLong();
    error UriTooLong();

    /// @notice Create a validation request. Permissionless by design.
    function validationRequest(bytes32 requestHash, uint256 agentId, string calldata tag, string calldata requestUri)
        external
    {
        if (requestHash == bytes32(0)) revert ZeroRequestHash();
        if (agentId == 0) revert ZeroAgentId();
        if (_requests[requestHash].exists) revert RequestAlreadyExists();
        _validateText(tag, requestUri);

        _requests[requestHash] = ValidationRequestData({
            requester: msg.sender,
            agentId: agentId,
            tag: tag,
            requestUri: requestUri,
            createdAt: uint64(block.timestamp),
            exists: true
        });

        emit ValidationRequested(requestHash, agentId, msg.sender, tag, requestUri);
    }

    /// @notice Submit a validation response for an existing request. Permissionless by design.
    ///         First response wins (subsequent responses revert).
    function validationResponse(
        bytes32 requestHash,
        uint256 agentId,
        uint8 response,
        bytes32 responseHash,
        string calldata tag,
        string calldata responseUri
    ) external {
        if (requestHash == bytes32(0)) revert ZeroRequestHash();
        if (agentId == 0) revert ZeroAgentId();
        if (response > MAX_RESPONSE) revert InvalidResponse();
        if (responseHash == bytes32(0)) revert ZeroResponseHash();
        _validateText(tag, responseUri);

        ValidationRequestData storage requestData = _requests[requestHash];
        if (!requestData.exists) revert RequestNotFound();
        if (requestData.agentId != agentId) revert AgentMismatch();

        ValidationData storage stored = _responses[requestHash];
        if (stored.lastUpdate != 0) revert ResponseAlreadyExists();

        stored.validatorAddress = msg.sender;
        stored.agentId = agentId;
        stored.response = response;
        stored.responseHash = responseHash;
        stored.tag = tag;
        stored.responseUri = responseUri;
        stored.lastUpdate = uint64(block.timestamp);

        _bumpStats(_validatorStats[agentId][msg.sender], response);
        _bumpStats(_validatorTagStats[agentId][msg.sender][keccak256(bytes(tag))], response);

        emit ValidationResponded(requestHash, agentId, msg.sender, response, responseHash, tag, responseUri);
    }

    /// @inheritdoc IERC8004Validation
    function getValidationStatus(bytes32 requestHash)
        external
        view
        returns (
            address validatorAddress,
            uint256 agentId,
            uint8 response,
            bytes32 responseHash,
            string memory tag,
            uint256 lastUpdate
        )
    {
        ValidationData storage validation = _responses[requestHash];
        if (validation.lastUpdate == 0) {
            return (address(0), 0, 0, bytes32(0), "", 0);
        }

        return (
            validation.validatorAddress,
            validation.agentId,
            validation.response,
            validation.responseHash,
            validation.tag,
            validation.lastUpdate
        );
    }

    /// @inheritdoc IERC8004Validation
    function getSummary(uint256 agentId, address[] calldata validatorAddresses, string calldata tag)
        external
        view
        returns (uint64 count, uint8 avgResponse)
    {
        uint256 totalCount;
        uint256 totalResponse;
        bytes32 tagHash = keccak256(bytes(tag));
        bool filterByTag = bytes(tag).length > 0;

        for (uint256 i; i < validatorAddresses.length; i++) {
            Stats storage stats = filterByTag
                ? _validatorTagStats[agentId][validatorAddresses[i]][tagHash]
                : _validatorStats[agentId][validatorAddresses[i]];

            totalCount += stats.count;
            totalResponse += stats.totalResponse;
        }

        if (totalCount == 0) return (0, 0);

        count = totalCount > type(uint64).max ? type(uint64).max : uint64(totalCount);
        avgResponse = uint8(totalResponse / totalCount);
    }

    /// @notice Returns the full request payload for off-chain tooling.
    function getValidationRequest(bytes32 requestHash)
        external
        view
        returns (
            address requester,
            uint256 agentId,
            string memory tag,
            string memory requestUri,
            uint256 createdAt,
            bool exists
        )
    {
        ValidationRequestData storage requestData = _requests[requestHash];
        return (
            requestData.requester,
            requestData.agentId,
            requestData.tag,
            requestData.requestUri,
            requestData.createdAt,
            requestData.exists
        );
    }

    /// @notice Returns response URI stored for a request hash.
    function getResponseUri(bytes32 requestHash) external view returns (string memory) {
        return _responses[requestHash].responseUri;
    }

    function _validateText(string calldata tag, string calldata uri) private pure {
        if (bytes(tag).length > MAX_TAG_LENGTH) revert TagTooLong();
        if (bytes(uri).length > MAX_URI_LENGTH) revert UriTooLong();
    }

    function _bumpStats(Stats storage stats, uint8 response) private {
        stats.count += 1;
        stats.totalResponse += response;
    }
}
