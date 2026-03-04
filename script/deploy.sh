#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DEPLOYMENTS_DIR="$PROJECT_ROOT/deployments"
SIGNER_MODE="ledger"

usage() {
    cat << EOF
Agent Bonds Deployment Script

Usage: $0 <command> [options]

Commands:
    preflight       Run pre-flight checks
    dry-run         Execute deployment in dry-run mode (no broadcast)
    deploy          Execute deployment with broadcast
    smoke-test      Run post-deployment smoke tests
    predict         Predict deterministic deployment addresses
    upgrade         Upgrade a proxy to new implementation

Options:
    --network <network>   Target network (sepolia|base-sepolia|op-sepolia|mainnet|base)
    --env-file <file>     Environment file to source (default: .env)
    --salt-tag <tag>      Version tag for deterministic salt derivation (e.g., v2, staging)
    --account <name>      Use Foundry keystore account for signing
    --target <target>     Upgrade target: manager or scorer
    --help                Show this help message

Signing:
    Default: Ledger hardware wallet (--ledger --sender DEPLOYER_ADDRESS)
    Keystore: --account <name> (uses ~/.foundry/keystores/<name>, prompts for password)

    To import a key into Foundry keystore:
        cast wallet import <name> --interactive

Environment Variables:
    DEPLOYER_ADDRESS          Sender address (required for Ledger, auto-derived for keystore)
    DEPLOYMENT_SALT_SECRET    Secret for deterministic deployment salt derivation
    SALT_TAG                  Optional version tag for deterministic salts
    OWNER_ADDRESS             Governance owner address for ownership handoff
    IDENTITY_REGISTRY         ERC-8004 Identity Registry address
    VALIDATION_REGISTRY       ERC-8004 Validation Registry address
    SETTLEMENT_TOKEN          ERC-20 settlement token address (non-zero)
    SCORER_PRIOR_VALUE        Prior value dampener for on-chain scoring
    SCORER_SLASH_MULTIPLIER_BPS  Slash severity multiplier (10000-100000)
    DISPUTE_PERIOD            Dispute window in seconds (max 90 days)
    MIN_PASSING_SCORE         Minimum validation score (1-100)
    SLASH_BPS                 Slash percentage in basis points (max 10000)
    VALIDATION_FINALITY_POLICY (optional) 0=ResponseHashRequired, 1=AnyStatusRecord
    STATUS_LOOKUP_FAILURE_POLICY (optional) 0=CanonicalUnknownAsMissing, 1=AlwaysMissing, 2=AlwaysUnavailable

Examples:
    # Run pre-flight checks
    $0 preflight --network base-sepolia

    # Dry-run deployment
    $0 dry-run --network base-sepolia

    # Deploy with Ledger
    $0 deploy --network base-sepolia

    # Deploy with Foundry keystore
    $0 deploy --network base-sepolia --account deployer

    # Deploy a new version namespace with SALT_TAG
    $0 deploy --network base-sepolia --salt-tag v2

    # Predict deterministic addresses without deploying
    $0 predict --network base-sepolia --salt-tag v2

    # Post-deployment verification
    $0 smoke-test --network base-sepolia

    # Upgrade AgentBondManager
    $0 upgrade --network base-sepolia --target manager

    # Upgrade ReputationScorer
    $0 upgrade --network base-sepolia --target scorer
EOF
    exit 0
}

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

error() {
    echo "[ERROR] $*" >&2
    exit 1
}

load_env() {
    local env_file="$1"
    if [[ -f "$env_file" ]]; then
        log "Loading environment from $env_file"
        set -a
        source "$env_file"
        set +a
    else
        error "Environment file not found: $env_file"
    fi
}

SIGNER_ARGS=()
KEYSTORE_ACCOUNT=""

resolve_signer_args() {
    local sender="${1:-}"
    local network="${2:-}"

    if [[ "$SIGNER_MODE" == "keystore" ]]; then
        [[ -z "$KEYSTORE_ACCOUNT" ]] && error "--account name required"

        local keystore_path="$HOME/.foundry/keystores/$KEYSTORE_ACCOUNT"
        [[ ! -f "$keystore_path" ]] && error "Keystore not found: $keystore_path (run: cast wallet import $KEYSTORE_ACCOUNT --interactive)"

        local derived
        derived="$(cast wallet address --account "$KEYSTORE_ACCOUNT")"

        if [[ -n "$sender" ]]; then
            local sender_lower derived_lower
            sender_lower=$(echo "$sender" | tr '[:upper:]' '[:lower:]')
            derived_lower=$(echo "$derived" | tr '[:upper:]' '[:lower:]')
            if [[ "$sender_lower" != "$derived_lower" ]]; then
                error "DEPLOYER_ADDRESS ($sender) does not match keystore account ($derived)"
            fi
        fi

        export DEPLOYER_ADDRESS="$derived"
        SIGNER_ARGS=(--account "$KEYSTORE_ACCOUNT" --sender "$derived")
        return 0
    fi

    [[ -z "$sender" ]] && error "DEPLOYER_ADDRESS required for Ledger signing"
    SIGNER_ARGS=(--sender "$sender" --ledger)
}

get_rpc_url() {
    local network="$1"
    case "$network" in
        sepolia)      echo "${SEPOLIA_RPC_URL:-}" ;;
        base-sepolia) echo "${BASE_SEPOLIA_RPC_URL:-}" ;;
        op-sepolia)   echo "${OP_SEPOLIA_RPC_URL:-}" ;;
        mainnet)      echo "${MAINNET_RPC_URL:-}" ;;
        base)         echo "${BASE_RPC_URL:-}" ;;
        *)            error "Unknown network: $network" ;;
    esac
}

get_chain_id() {
    local network="$1"
    case "$network" in
        sepolia)      echo "11155111" ;;
        base-sepolia) echo "84532" ;;
        op-sepolia)   echo "11155420" ;;
        mainnet)      echo "1" ;;
        base)         echo "8453" ;;
        *)            error "Unknown network: $network" ;;
    esac
}

verify_rpc_chain() {
    local network="$1"
    local rpc_url="$2"
    local expected_chain_id
    expected_chain_id="$(get_chain_id "$network")"

    local actual_chain_id
    actual_chain_id="$(cast chain-id --rpc-url "$rpc_url" 2>/dev/null || true)"
    [[ -z "$actual_chain_id" ]] && error "Failed to read chain ID from RPC for $network"

    if [[ "$actual_chain_id" != "$expected_chain_id" ]]; then
        error "RPC chain ID mismatch for $network: expected $expected_chain_id, got $actual_chain_id"
    fi
}

ensure_deployments_dir() {
    mkdir -p "$DEPLOYMENTS_DIR"
    mkdir -p "$DEPLOYMENTS_DIR/dry-runs"
}

cmd_preflight() {
    local network="$1"
    local salt_tag="$2"
    local rpc_url
    local extra_env=""
    rpc_url=$(get_rpc_url "$network")

    [[ -z "$rpc_url" ]] && error "RPC URL not set for $network"
    verify_rpc_chain "$network" "$rpc_url"

    if [[ "$SIGNER_MODE" == "keystore" ]]; then
        resolve_signer_args "${DEPLOYER_ADDRESS:-}" "$network"
    fi

    log "Running pre-flight checks for $network..."

    if [[ -n "$salt_tag" ]]; then
        extra_env="SALT_TAG=$salt_tag"
    fi

    env $extra_env forge script "$PROJECT_ROOT/script/PreFlightCheck.s.sol:PreFlightCheck" \
        --root "$PROJECT_ROOT" \
        --rpc-url "$rpc_url" \
        -vvv
}

cmd_dry_run() {
    local network="$1"
    local salt_tag="$2"
    local rpc_url
    local expected_chain_id
    local extra_env=""
    rpc_url=$(get_rpc_url "$network")
    expected_chain_id=$(get_chain_id "$network")

    [[ -z "$rpc_url" ]] && error "RPC URL not set for $network"
    verify_rpc_chain "$network" "$rpc_url"

    ensure_deployments_dir

    local timestamp
    timestamp=$(date '+%Y%m%d_%H%M%S')
    local output_file="$DEPLOYMENTS_DIR/dry-runs/${network}_${timestamp}.txt"

    log "Running dry-run for $network..."
    log "Output will be saved to: $output_file"

    if [[ -n "$salt_tag" ]]; then
        extra_env="SALT_TAG=$salt_tag"
    fi

    env $extra_env EXPECTED_CHAIN_ID="$expected_chain_id" forge script "$PROJECT_ROOT/script/Deploy.s.sol:Deploy" \
        --root "$PROJECT_ROOT" \
        --rpc-url "$rpc_url" \
        -vvvv 2>&1 | tee "$output_file"

    local last_known="$DEPLOYMENTS_DIR/dry-runs/${network}_last_known_good.txt"
    if [[ -f "$last_known" ]]; then
        log "Comparing with last known good..."
        if diff -u "$last_known" "$output_file" > "$DEPLOYMENTS_DIR/dry-runs/${network}_diff.txt" 2>&1; then
            log "No differences from last known good"
        else
            log "Differences detected! Review: $DEPLOYMENTS_DIR/dry-runs/${network}_diff.txt"
            echo ""
            echo "=== Diff Summary ==="
            head -50 "$DEPLOYMENTS_DIR/dry-runs/${network}_diff.txt"
        fi
    else
        log "No previous dry-run to compare against"
        log "To set this as baseline: cp $output_file $last_known"
    fi
}

cmd_deploy() {
    local network="$1"
    local salt_tag="$2"
    local rpc_url
    local expected_chain_id
    local extra_env=""
    rpc_url=$(get_rpc_url "$network")
    expected_chain_id=$(get_chain_id "$network")

    [[ -z "$rpc_url" ]] && error "RPC URL not set for $network"
    verify_rpc_chain "$network" "$rpc_url"

    log "Running pre-flight checks first..."
    cmd_preflight "$network" "$salt_tag"

    log ""
    log "Pre-flight passed. Proceeding with deployment..."
    log "Network: $network"
    if [[ -n "$salt_tag" ]]; then
        log "SALT_TAG: $salt_tag"
    fi
    log ""

    if [[ "$network" == "mainnet" || "$network" == "base" ]]; then
        echo ""
        echo "========================================"
        echo "  WARNING: PRODUCTION DEPLOYMENT ($network)"
        echo "========================================"
        echo ""
        local expected_confirmation="DEPLOY ${network^^}"
        read -p "Type '$expected_confirmation' to confirm: " confirmation
        [[ "$confirmation" != "$expected_confirmation" ]] && error "Deployment cancelled"
    fi

    ensure_deployments_dir

    resolve_signer_args "${DEPLOYER_ADDRESS:-}" "$network"

    if [[ -n "$salt_tag" ]]; then
        extra_env="SALT_TAG=$salt_tag"
    fi

    env $extra_env EXPECTED_CHAIN_ID="$expected_chain_id" forge script "$PROJECT_ROOT/script/Deploy.s.sol:Deploy" \
        --root "$PROJECT_ROOT" \
        --rpc-url "$rpc_url" \
        --broadcast \
        "${SIGNER_ARGS[@]}" \
        -vvvv

    log "Deployment complete. Running smoke tests..."
    cmd_smoke_test "$network" "$salt_tag"
}

cmd_smoke_test() {
    local network="$1"
    local salt_tag="$2"
    local rpc_url
    local extra_env=""
    rpc_url=$(get_rpc_url "$network")

    [[ -z "$rpc_url" ]] && error "RPC URL not set for $network"
    verify_rpc_chain "$network" "$rpc_url"

    log "Running post-deployment smoke tests for $network..."

    if [[ -n "$salt_tag" ]]; then
        extra_env="SALT_TAG=$salt_tag"
    fi

    env $extra_env forge script "$PROJECT_ROOT/script/PostDeploymentSmokeTest.s.sol:PostDeploymentSmokeTest" \
        --root "$PROJECT_ROOT" \
        --rpc-url "$rpc_url" \
        -vvv
}

cmd_upgrade() {
    local network="$1"
    local target="$2"
    local salt_tag="$3"
    local rpc_url
    local expected_chain_id
    local extra_env=""
    rpc_url=$(get_rpc_url "$network")
    expected_chain_id=$(get_chain_id "$network")

    [[ -z "$rpc_url" ]] && error "RPC URL not set for $network"
    [[ -z "$target" ]] && error "--target required (manager or scorer)"
    verify_rpc_chain "$network" "$rpc_url"

    # For keystore mode, derive DEPLOYER_ADDRESS before Solidity preflight reads env.
    if [[ "$SIGNER_MODE" == "keystore" ]]; then
        resolve_signer_args "${DEPLOYER_ADDRESS:-}" "$network"
    fi

    log "Running upgrade preflight checks..."
    if [[ -n "$salt_tag" ]]; then
        extra_env="SALT_TAG=$salt_tag"
    fi

    env $extra_env EXPECTED_CHAIN_ID="$expected_chain_id" TARGET="$target" forge script "$PROJECT_ROOT/script/Upgrade.s.sol:Upgrade" \
        --root "$PROJECT_ROOT" \
        --rpc-url "$rpc_url" \
        --sig "validateOnly()" \
        -vvv

    if [[ "$network" == "mainnet" || "$network" == "base" ]]; then
        echo ""
        echo "========================================"
        echo "  WARNING: PRODUCTION UPGRADE ($network)"
        echo "========================================"
        echo ""
        local expected_confirmation="UPGRADE ${network^^}"
        read -p "Type '$expected_confirmation' to confirm: " confirmation
        [[ "$confirmation" != "$expected_confirmation" ]] && error "Upgrade cancelled"
    fi

    log "Upgrading $target on $network..."

    if [[ "$SIGNER_MODE" != "keystore" ]]; then
        resolve_signer_args "${DEPLOYER_ADDRESS:-}" "$network"
    fi

    env $extra_env EXPECTED_CHAIN_ID="$expected_chain_id" TARGET="$target" forge script "$PROJECT_ROOT/script/Upgrade.s.sol:Upgrade" \
        --root "$PROJECT_ROOT" \
        --rpc-url "$rpc_url" \
        --broadcast \
        "${SIGNER_ARGS[@]}" \
        -vvvv

    log "Upgrade complete. Running smoke tests..."
    cmd_smoke_test "$network" "$salt_tag"
}

cmd_predict() {
    local network="$1"
    local salt_tag="$2"
    local rpc_url
    local expected_chain_id
    local extra_env=""
    rpc_url=$(get_rpc_url "$network")
    expected_chain_id=$(get_chain_id "$network")

    [[ -z "$rpc_url" ]] && error "RPC URL not set for $network"
    verify_rpc_chain "$network" "$rpc_url"

    log "Predicting deterministic deployment addresses for $network..."

    if [[ -n "$salt_tag" ]]; then
        extra_env="SALT_TAG=$salt_tag"
    fi

    env $extra_env EXPECTED_CHAIN_ID="$expected_chain_id" forge script "$PROJECT_ROOT/script/Deploy.s.sol:Deploy" \
        --root "$PROJECT_ROOT" \
        --rpc-url "$rpc_url" \
        --sig "predictAddresses()" \
        -vvv
}

main() {
    local command=""
    local network="sepolia"
    local env_file="$PROJECT_ROOT/.env"
    local target=""
    local salt_tag=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            preflight|dry-run|deploy|smoke-test|predict|upgrade)
                command="$1"
                shift
                ;;
            --network)
                network="$2"
                shift 2
                ;;
            --env-file)
                env_file="$2"
                shift 2
                ;;
            --target)
                target="$2"
                shift 2
                ;;
            --salt-tag)
                salt_tag="$2"
                shift 2
                ;;
            --account)
                SIGNER_MODE="keystore"
                KEYSTORE_ACCOUNT="$2"
                shift 2
                ;;
            --help|-h)
                usage
                ;;
            *)
                error "Unknown option: $1"
                ;;
        esac
    done

    [[ -z "$command" ]] && usage

    load_env "$env_file"

    if [[ -n "$salt_tag" ]]; then
        export SALT_TAG="$salt_tag"
        log "Using SALT_TAG: $salt_tag"
    fi

    case "$command" in
        preflight)   cmd_preflight "$network" "$salt_tag" ;;
        dry-run)     cmd_dry_run "$network" "$salt_tag" ;;
        deploy)      cmd_deploy "$network" "$salt_tag" ;;
        smoke-test)  cmd_smoke_test "$network" "$salt_tag" ;;
        predict)     cmd_predict "$network" "$salt_tag" ;;
        upgrade)     cmd_upgrade "$network" "$target" "$salt_tag" ;;
        *)           error "Unknown command: $command" ;;
    esac
}

main "$@"
