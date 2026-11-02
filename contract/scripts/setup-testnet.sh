#!/usr/bin/env bash
# Creates the ReplayCourt testnet accounts and deploys + initializes the contract.
#
#   scripts/setup-testnet.sh <master-account>.testnet
#
# - <master> is created through the testnet faucet if it does not exist (10 NEAR).
# - Subaccounts contract./owner./verifier./hunter1./hunter2.<master> are funded from it
#   (more hunters with HUNTERS=, more accounts with EXTRA=).
# - target/near/replaycourt.wasm is deployed to contract.<master> with `new(owner_id=<master>)`.
# Keys are stored by near-cli-rs in the legacy keychain (~/.near-credentials/testnet/).
# Optional: HANDOFF=/path/testnet.json writes the account ids (no keys) as JSON.
# Optional: CONTRACT=<existing contract id> skips creating and deploying contract.<master>
#           and only creates the participant accounts (owner, verifier, hunters).
# Optional: HUNTERS=<n> creates hunter1..hunter<n>.<master> (default 2).
# Optional: EXTRA="verifier2=0.3 NEAR,..." creates more <name>.<master> accounts; the handoff
#           JSON lists them as <name>_id.
# Optional: HANDOFF_RPC=<url> (rpc_url in the handoff JSON) and HANDOFF_SECRETS_DIR=<dir>
#           (secrets_dir in the handoff JSON: where the agent keeps this deployment's verifier
#           keys, relative to the JSON file).
# Testnet only. Needs: near (near-cli-rs), python3, curl.

HERE=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=lib.sh
. "$HERE/lib.sh"

MASTER=${1:-${MASTER:-}}
[ -n "$MASTER" ] || die "usage: $0 <master-account>.testnet"
case "$MASTER" in *.testnet) ;; *) die "master account must end in .testnet" ;; esac

WASM=${WASM:-$HERE/../target/near/replaycourt.wasm}
DEPLOY=1
if [ -n "${CONTRACT:-}" ]; then
  DEPLOY=0
  account_exists "$CONTRACT" || die "CONTRACT=$CONTRACT does not exist"
else
  CONTRACT=contract.$MASTER
  [ -f "$WASM" ] || die "$WASM not found; run: cargo near build non-reproducible-wasm"
fi

OWNER=owner.$MASTER
VERIFIER=verifier.$MASTER
HUNTERS=${HUNTERS:-2}
case "$HUNTERS" in [1-9]) ;; *) die "HUNTERS must be 1..9" ;; esac
HUNTER_IDS=()
for i in $(seq 1 "$HUNTERS"); do HUNTER_IDS+=("hunter$i.$MASTER"); done
EXTRA_PAIRS=()
if [ -n "${EXTRA:-}" ]; then
  IFS=',' read -r -a _extra <<<"$EXTRA"
  for e in "${_extra[@]}"; do
    name=${e%%=*}; amount=${e#*=}
    case "$name" in *[!a-z0-9_-]*|"") die "EXTRA: bad account name '$name'" ;; esac
    [ "$name" != "$e" ] || die "EXTRA: use name=amount, e.g. verifier2=0.3 NEAR"
    EXTRA_PAIRS+=("$name.$MASTER=$amount")
  done
fi

# Funding (testnet NEAR). The contract must hold the wasm's storage stake (~1 NEAR / 100 kB).
FUND_CONTRACT=${FUND_CONTRACT:-3.2 NEAR}
FUND_OWNER=${FUND_OWNER:-3 NEAR}
FUND_VERIFIER=${FUND_VERIFIER:-0.5 NEAR}
FUND_HUNTER=${FUND_HUNTER:-1 NEAR}

report "# ReplayCourt testnet setup ($(date -u +%Y-%m-%dT%H:%MZ))"
report ""
report "| step | transaction | result |"
report "|---|---|---|"

if account_exists "$MASTER"; then
  echo "master $MASTER exists" >&2
else
  tx "create $MASTER via faucet" account create-account sponsor-by-faucet-service "$MASTER" \
    autogenerate-new-keypair save-to-legacy-keychain network-config "$NETWORK_CONFIG" create
  sleep 3
fi

ACCOUNTS=("$OWNER=$FUND_OWNER" "$VERIFIER=$FUND_VERIFIER")
for h in "${HUNTER_IDS[@]}"; do ACCOUNTS+=("$h=$FUND_HUNTER"); done
[ "${#EXTRA_PAIRS[@]}" -gt 0 ] && ACCOUNTS+=("${EXTRA_PAIRS[@]}")
[ "$DEPLOY" = 1 ] && ACCOUNTS=("$CONTRACT=$FUND_CONTRACT" "${ACCOUNTS[@]}")
for pair in "${ACCOUNTS[@]}"; do
  acct=${pair%%=*}; amount=${pair#*=}
  if account_exists "$acct"; then
    echo "$acct exists" >&2
  else
    tx "create $acct ($amount)" account create-account fund-myself "$acct" "$amount" \
      autogenerate-new-keypair save-to-legacy-keychain sign-as "$MASTER" \
      network-config "$NETWORK_CONFIG" sign-with-legacy-keychain send
  fi
done

if [ "$DEPLOY" = 1 ]; then
  tx "deploy $(basename "$WASM") to $CONTRACT + new(owner_id=$MASTER)" \
    contract deploy "$CONTRACT" use-file "$WASM" \
    with-init-call new json-args "{\"owner_id\":\"$MASTER\"}" \
    prepaid-gas '30 Tgas' attached-deposit '0 NEAR' \
    network-config "$NETWORK_CONFIG" sign-with-legacy-keychain send
fi

version=$(view version '{}')
echo "contract $CONTRACT version $version" >&2

if [ -n "${HANDOFF:-}" ]; then
  mkdir -p "$(dirname "$HANDOFF")"
  EXTRA_IDS=()
  [ "${#EXTRA_PAIRS[@]}" -gt 0 ] && for pair in "${EXTRA_PAIRS[@]}"; do EXTRA_IDS+=("${pair%%=*}"); done
  python3 - "$HANDOFF" "$NETWORK" "$CONTRACT" "$MASTER" "$OWNER" "$VERIFIER" \
    "${HANDOFF_RPC:-https://rpc.testnet.near.org}" "${HANDOFF_SECRETS_DIR:-}" \
    "${HUNTER_IDS[*]}" "${EXTRA_IDS[*]:-}" <<'PY'
import json, sys
path, network, contract, master, owner, verifier, rpc_url, secrets_dir, hunters, extra = sys.argv[1:]
data = {
    "network": network,
    "contract_id": contract,
    "contract_owner_id": master,
    "owner_id": owner,
    "verifier_id": verifier,
}
for i, h in enumerate(hunters.split(), 1):
    data["hunter%d_id" % i] = h
for acct in extra.split():
    data[acct.split(".")[0] + "_id"] = acct
data.update({
    "keychain": "near-cli-rs legacy keychain: ~/.near-credentials/testnet/<account_id>.json "
                "and ~/.near-credentials/testnet/<account_id>/ed25519_<public_key>.json",
    "rpc_url": rpc_url,
    "explorer": "https://testnet.nearblocks.io",
})
if secrets_dir:
    data["secrets_dir"] = secrets_dir
json.dump(data, open(path, "w"), indent=2)
open(path, "a").write("\n")
PY
  echo "wrote $HANDOFF" >&2
fi

echo "setup done; report: $REPORT" >&2
