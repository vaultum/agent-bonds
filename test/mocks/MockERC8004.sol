// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

contract MockIdentityRegistry {
    mapping(uint256 => address) public agentOwners;
    mapping(uint256 => address) public agentWallets;
    mapping(uint256 => mapping(address => bool)) public operators;
    uint256 public nextId = 1;

    function register(address to) external returns (uint256 agentId) {
        agentId = nextId++;
        agentOwners[agentId] = to;
        agentWallets[agentId] = to;
    }

    function ownerOf(uint256 agentId) external view returns (address) {
        address o = agentOwners[agentId];
        require(o != address(0), "ERC721NonexistentToken");
        return o;
    }

    function isAuthorizedOrOwner(address spender, uint256 agentId) external view returns (bool) {
        address o = agentOwners[agentId];
        require(o != address(0), "ERC721NonexistentToken");
        return spender == o || operators[agentId][spender];
    }

    function getAgentWallet(uint256 agentId) external view returns (address) {
        return agentWallets[agentId];
    }

    function setOperator(uint256 agentId, address op, bool approved) external {
        operators[agentId][op] = approved;
    }

    function setAgentWallet(uint256 agentId, address wallet) external {
        agentWallets[agentId] = wallet;
    }
}

contract MockReputationRegistry {
    struct MockFeedback {
        int128 value;
        uint8 valueDecimals;
        string tag1;
        string tag2;
        bool isRevoked;
    }

    mapping(uint256 => mapping(address => mapping(uint64 => MockFeedback))) public feedback;
    mapping(uint256 => mapping(address => uint64)) public lastIndex;
    mapping(uint256 => address[]) private _clients;
    mapping(uint256 => mapping(address => bool)) private _clientExists;
    mapping(uint256 => uint8) private _summaryDecimals;
    mapping(uint256 => bool) private _decimalsOverridden;

    function setFeedback(
        uint256 agentId,
        address client,
        int128 value,
        uint8 valueDecimals,
        string memory tag1,
        string memory tag2
    ) external {
        if (!_clientExists[agentId][client]) {
            _clients[agentId].push(client);
            _clientExists[agentId][client] = true;
        }
        uint64 idx = ++lastIndex[agentId][client];
        feedback[agentId][client][idx] = MockFeedback(value, valueDecimals, tag1, tag2, false);
    }

    function getSummary(
        uint256 agentId,
        address[] calldata clientAddresses,
        string calldata tag1,
        string calldata /* tag2 */
    ) external view returns (uint64 count, int128 summaryValue, uint8 summaryValueDecimals) {
        require(clientAddresses.length > 0, "clientAddresses required");

        bytes32 emptyHash = keccak256(bytes(""));
        bytes32 tag1Hash = keccak256(bytes(tag1));
        int256 sum;

        for (uint256 i; i < clientAddresses.length; i++) {
            uint64 lastIdx = lastIndex[agentId][clientAddresses[i]];
            for (uint64 j = 1; j <= lastIdx; j++) {
                MockFeedback storage fb = feedback[agentId][clientAddresses[i]][j];
                if (fb.isRevoked) continue;
                if (emptyHash != tag1Hash && tag1Hash != keccak256(bytes(fb.tag1))) continue;
                sum += int256(fb.value);
                count++;
            }
        }

        if (count > 0) {
            summaryValue = int128(sum / int256(uint256(count)));
            summaryValueDecimals = _decimalsOverridden[agentId] ? _summaryDecimals[agentId] : 0;
        }
    }

    function setSummaryDecimals(uint256 agentId, uint8 dec) external {
        _summaryDecimals[agentId] = dec;
        _decimalsOverridden[agentId] = true;
    }

    function getClients(uint256 agentId) external view returns (address[] memory) {
        return _clients[agentId];
    }
}

contract MockValidationRegistry {
    struct MockValidation {
        address validatorAddress;
        uint256 agentId;
        uint8 response;
        bytes32 responseHash;
        string tag;
        uint256 lastUpdate;
        bool exists;
    }

    mapping(bytes32 => MockValidation) public validations;
    mapping(uint256 => uint64) private _validationCounts;
    mapping(uint256 => uint256) private _validationTotals;
    bool public forceRevert;

    function setForceRevert(bool on) external {
        forceRevert = on;
    }

    function setValidation(
        bytes32 requestHash,
        address validatorAddress,
        uint256 agentId,
        uint8 response,
        bool hasResponse
    ) external {
        validations[requestHash] = MockValidation({
            validatorAddress: validatorAddress,
            agentId: agentId,
            response: response,
            responseHash: bytes32(0),
            tag: "",
            lastUpdate: block.timestamp,
            exists: true
        });

        if (hasResponse) {
            _validationCounts[agentId]++;
            _validationTotals[agentId] += response;
        }
    }

    function getValidationStatus(bytes32 requestHash) external view returns (
        address validatorAddress,
        uint256 agentId,
        uint8 response,
        bytes32 responseHash,
        string memory tag,
        uint256 lastUpdate
    ) {
        require(!forceRevert, "registry unavailable");
        MockValidation memory v = validations[requestHash];
        return (v.validatorAddress, v.agentId, v.response, v.responseHash, v.tag, v.lastUpdate);
    }

    function getSummary(
        uint256 agentId,
        address[] calldata,
        string calldata
    ) external view returns (uint64 count, uint8 avgResponse) {
        count = uint64(_validationCounts[agentId]);
        if (count > 0) {
            avgResponse = uint8(_validationTotals[agentId] / count);
        }
    }
}
