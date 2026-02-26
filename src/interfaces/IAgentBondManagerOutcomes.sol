// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

/// @title IAgentBondManagerOutcomes
/// @author Vaultum
/// @notice Read-only performance counters exposed by AgentBondManager.
interface IAgentBondManagerOutcomes {
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
        );
}
