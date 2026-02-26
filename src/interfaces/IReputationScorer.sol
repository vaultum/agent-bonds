// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

/// @title IReputationScorer
/// @author Vaultum
/// @notice Composable interface for ERC-8004 agent reputation scoring.
interface IReputationScorer {
    /// @return score         Basis points (0 = unknown, 10000 = perfect).
    /// @return evidenceCount Number of settled outcome samples behind the score.
    function getScore(uint256 agentId) external view returns (uint256 score, uint64 evidenceCount);

    /// @return bondAmount Minimum bond collateral required.
    function getRequiredBond(uint256 agentId, uint256 taskValue) external view returns (uint256 bondAmount);
}
