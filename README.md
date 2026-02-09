# Agent Bonds

Reputation-collateralized bonding protocol for [ERC-8004](https://eips.ethereum.org/EIPS/eip-8004) AI agents. Agents stake ETH as a quality signal; bond requirements scale inversely with on-chain reputation. Disputes resolve through the ERC-8004 Validation Registry with economic consequences.

## Why

ERC-8004 provides identity, reputation, and validation registries for autonomous agents -- but intentionally leaves economic incentives out of scope. Agent Bonds fills that gap:

- Agents post collateral proportional to their reputation (high rep = lower bond)
- Clients get economic guarantees -- disputed work triggers validation and automatic slashing
- Reputation feedback loop -- completed tasks build reputation, lowering future bond costs
- Sybil resistance -- each agent identity requires real capital at stake

## Contracts

| Contract | Description |
|---|---|
| `AgentBondManager.sol` | Bond deposits, task lifecycle, dispute resolution, pull payments. UUPS upgradeable. |
| `ReputationScorer.sol` | Combines Reputation + Validation registry data into a normalized score. Maps score to bond requirement. UUPS upgradeable. |
| `MinimalValidationRegistry.sol` | Permissionless testnet validation registry (open request + first-response-wins), compatible with `IERC8004Validation`. |
| `IReputationScorer.sol` | Composable scoring interface any protocol can implement. |

## Task Lifecycle

```
Client creates task (with agent's EIP-712 consent)
    │
    ├─ completeTask()      → Agent paid, bond unlocked
    ├─ claimExpiredTask()   → Deadline passed, agent paid
    └─ disputeTask()
         │
         ├─ resolveDispute()          → Validator score >= threshold: agent wins
         │                            → Validator score < threshold: bond slashed
         ├─ reclaimDisputedTask()     → No validation after timeout: bond slashed
         └─ (registry unavailable)    → Grace period → refund-only (no slash)
```

All payouts use pull-payments via `claim()`.

## Security Properties

- **Agent consent**: Tasks require EIP-712 signature (supports EOA and ERC-1271 smart wallets)
- **Parameter snapshots**: `minPassingScore`, `slashBps`, `disputePeriod`, `registryGracePeriod` are captured per-task at creation/dispute time -- admin changes don't affect in-flight tasks
- **Bounded admin controls**: Dispute period capped at 90 days, slash basis points at 10,000, scoring weights at 10,000, trusted lists at 200 entries
- **Registry failure handling**: Grace window prevents immediate slashing during validation registry outages
- **Pull payments**: Eliminates stuck-task risk from reverting recipients
- **Reentrancy protection**: Transient storage lock on all state-mutating external functions

## Validation Registry Compatibility

`AgentBondManager` expects `getValidationStatus(requestHash)` to return zero-values (not revert) when no response exists for a request hash. This is how `MinimalValidationRegistry` behaves and how the contract distinguishes "no validation yet" from "registry unavailable."

If you point at a registry that reverts on missing records instead of returning zeroes, `reclaimDisputedTask` will enter the "registry unavailable" path (refund after grace period, no slash) rather than the "no validation" path (slash). The economic outcome differs: refund protects the agent's bond, slash does not. Choose a registry implementation accordingly.

## Build

Requires [Foundry](https://book.getfoundry.sh/).

```bash
forge install
forge build
forge test -v
```

## Dependencies

- [OpenZeppelin Contracts Upgradeable v5](https://github.com/OpenZeppelin/openzeppelin-contracts-upgradeable) (UUPS, SignatureChecker, Initializable)
- Solidity 0.8.24

## Deployment

Both contracts deploy behind ERC-1967 proxies (UUPS pattern). Foundry scripts handle the full lifecycle.

### Environment

```bash
cp .env.example .env
# Edit .env with your values (RPC URLs, registry addresses, parameters)
```

| Variable | Description |
|---|---|
| `DEPLOYER_ADDRESS` | Deployer EOA |
| `IDENTITY_REGISTRY` | ERC-8004 Identity Registry |
| `REPUTATION_REGISTRY` | ERC-8004 Reputation Registry |
| `VALIDATION_REGISTRY` | ERC-8004 Validation Registry |
| `REPUTATION_TAG` | Tag to filter reputation feedback (e.g. `"starred"`) |
| `MAX_EXPECTED_VALUE` | Max expected feedback value for scoring normalization |
| `DISPUTE_PERIOD` | Dispute window in seconds (max 90 days) |
| `MIN_PASSING_SCORE` | Minimum validation score to pass dispute (1-100) |
| `SLASH_BPS` | Slash percentage in basis points (max 10000) |

### Deploy

The `deploy.sh` wrapper handles env loading, network resolution, signer selection, and chains the Solidity scripts together.

```bash
# Pre-flight checks
./script/deploy.sh preflight --network base-sepolia

# Dry-run (no broadcast)
./script/deploy.sh dry-run --network base-sepolia

# Deploy with Ledger (default)
./script/deploy.sh deploy --network base-sepolia

# Deploy with Foundry keystore
./script/deploy.sh deploy --network base-sepolia --account deployer

# Deploy standalone MinimalValidationRegistry (if no public registry is available yet)
./script/deploy.sh deploy-validation --network base-sepolia --account deployer

# Post-deployment verification only
./script/deploy.sh smoke-test --network base-sepolia

# Upgrade AgentBondManager proxy
./script/deploy.sh upgrade --network base-sepolia --target manager

# Upgrade ReputationScorer proxy
./script/deploy.sh upgrade --network base-sepolia --target scorer
```

Signing options: Ledger (default) or Foundry encrypted keystore (`--account <name>`). To import a key into the keystore:

```bash
cast wallet import deployer --interactive
```

### Optional: Run your own validation registry on testnet

If an official ERC-8004 validation registry is not available on your target network yet:

1. Deploy `MinimalValidationRegistry` using `deploy-validation`.
2. Set `VALIDATION_REGISTRY` in `.env` to the deployed address.
3. Point your validator service at this contract and handle:
   - `validationRequest(requestHash, agentId, tag, requestURI)` from requestors
   - `validationResponse(requestHash, agentId, response, responseHash, tag, responseURI)` from validators

`responseHash` is required and must be non-zero (use a deterministic hash of your evidence payload).

`AgentBondManager` and `ReputationScorer` only depend on `getValidationStatus` and `getSummary`, so this drop-in registry enables full dispute-flow testing before the official registry ships.

## Status

**Unaudited.** This code has been through multiple internal review rounds but has not been formally audited. Use on testnet. See [SECURITY.md](SECURITY.md) to report vulnerabilities.

## License

[CC0-1.0](LICENSE)
