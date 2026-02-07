// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

/// @title IERC8004Identity
/// @author Vaultum
interface IERC8004Identity {
    function ownerOf(uint256 tokenId) external view returns (address);
    function isAuthorizedOrOwner(address spender, uint256 agentId) external view returns (bool);
    function getAgentWallet(uint256 agentId) external view returns (address);
}
