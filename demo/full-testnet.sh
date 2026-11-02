#!/usr/bin/env bash
# Judge path C: the whole ReplayCourt flow on NEAR testnet with YOUR OWN fresh accounts.
#
#   demo/full-testnet.sh [<name>.testnet]
#
# From nothing: creates <name>.testnet through the testnet faucet (default name: a random
# rc-judge-<hex>.testnet), its sub-accounts, deploys your own copy of the contract, then runs
#   1. a bounty program and the verifier's keys (X25519 for sealed reports, function-call key)
#   2. sealed submissions by two hunters: 01 (valid), 03 (duplicate of 01), 04 (invalid),
#      06 (needs a human), plus attack c (sealed blob does not match the commitment)
#   3. the verifier worker, signing post_verdict with the function-call key only
#   4. finalize after the 60 s challenge window, the owner resolves 06
#   5. attack d: everything a thief can try with the stolen function-call key
#   6. verify-onchain: every verdict's evidence hash matches the files in runs/
# Re-running with the same name continues where a run stopped (state in .secrets/<name>/state.env;
# without an argument the last name is reused). Every wait is bounded.
#
# Needs: Node >= 24 + npm, Python >= 3.8, Foundry's forge (PATH, ~/.foundry/bin, or
# REPLAYCOURT_FORGE), internet access (NEAR testnet RPC, testnet faucet, a free Ethereum archive RPC).
# Writes: .secrets/<name>.json, .secrets/<name>/ (keys, git-ignored), runs/testnet/contract.<name>/.
# Testnet only: the faucet's 10 testnet NEAR pay for everything; nothing touches mainnet.

set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
cd "$ROOT"

say() { printf '\n== %s\n' "$*"; }
die() { echo "ERROR: $*" >&2; exit 1; }

# ------------------------------------------------------------------ prerequisites
command -v node >/dev/null || die "node not found (Node >= 24 needed)"
[ "$(node -p 'process.versions.node.split(".")[0]')" -ge 24 ] || die "Node >= 24 needed (found $(node --version))"
command -v npm >/dev/null || die "npm not found"
command -v python3 >/dev/null || die "python3 not found"
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' || die "Python >= 3.8 needed"
# forge: REPLAYCOURT_FORGE, PATH or foundryup's ~/.foundry/bin (the same order as the engine)
if [ -z "${REPLAYCOURT_FORGE:-}" ] && ! command -v forge >/dev/null && [ ! -x "$HOME/.foundry/bin/forge" ]; then
  die "forge not found: curl -L https://foundry.paradigm.xyz | bash && foundryup (or set REPLAYCOURT_FORGE)"
fi
[ -d agent/node_modules/near-api-js ] || (cd agent && npm ci --no-audit --no-fund)

# ------------------------------------------------------------------ name and state
LAST=.secrets/full-testnet.last
NAME=${1:-}
if [ -z "$NAME" ] && [ -f "$LAST" ]; then NAME=$(cat "$LAST"); echo "continuing the last run: $NAME"; fi
[ -n "$NAME" ] || NAME="rc-judge-$(node -e 'process.stdout.write(require("crypto").randomBytes(4).toString("hex"))').testnet"
case "$NAME" in *.testnet) ;; *) die "the name must end in .testnet" ;; esac
BASE=${NAME%.testnet}
mkdir -p ".secrets/$BASE"
echo "$NAME" > "$LAST"
STATE=".secrets/$BASE/state.env"
touch "$STATE"
get() { grep -E "^$1=" "$STATE" | tail -1 | cut -d= -f2- || true; }
put() { echo "$1=$2" >> "$STATE"; }

export REPLAYCOURT_CONFIG="$ROOT/.secrets/$BASE.json"
unset REPLAYCOURT_CONTRACT_ID REPLAYCOURT_SECRETS_DIR REPLAYCOURT_CREDENTIALS_DIR || true
RUNLOG=".secrets/$BASE/full-testnet.log"

# bounded SECONDS CMD...: run CMD and stop it after SECONDS (macOS has no timeout(1)).
bounded() {
  local secs=$1 waited=0 rc=0; shift
  "$@" & local pid=$!
  while kill -0 "$pid" 2>/dev/null; do
    if [ "$waited" -ge "$secs" ]; then
      echo "timeout after ${secs} s: $*" >&2
      kill -TERM "$pid" 2>/dev/null || true; sleep 2; kill -KILL "$pid" 2>/dev/null || true
      break
    fi
    sleep 1; waited=$((waited + 1))
  done
  wait "$pid" || rc=$?
  return "$rc"
}
# near-api-js prints every failed RPC attempt (it then fails over to the next endpoint): noise.
noise() { grep --line-buffered -vE '^(TypeError: )?fetch failed|^\s+at |\[cause\]|errno:|syscall:|hostname:|code: .(ENOTFOUND|ETIMEDOUT|ECONNRESET|UND_ERR)|^\s*\}$|^(AccountDoesNotExist|ContractCodeDoesNotExist|NoContractCode)[A-Za-z]*Error|^\s+(accountId|contractId|blockHash|blockHeight):' || true; }
# stream CMD...: run CMD (bounded to STREAM_TIMEOUT s, default 15 min), show and log its output,
# return CMD's exit code.
stream() {
  local ps
  set +e
  bounded "${STREAM_TIMEOUT:-900}" "$@" 2>&1 | noise | tee -a "$RUNLOG"
  ps=("${PIPESTATUS[@]}")
  set -e
  return "${ps[0]}"
}
cli() { stream node agent/src/cli.ts "$@"; }
# value of "label: value" in a command's output
field() { sed -nE "s/^$1: ([^ ]+).*/\\1/p" | head -1; }
status_of() { # ID -> status of the submission (empty if the RPC did not answer three times)
  local st try
  for try in 1 2 3; do
    st=$(node --input-type=module -e "
      import { loadConfig } from './agent/src/config.ts'; import { makeProvider, view } from './agent/src/near.ts';
      const c = loadConfig(); const s = await view(makeProvider(c), c.contractId, 'get_submission', { submission_id: $1 });
      console.log(s ? s.status : 'missing');" 2>/dev/null | tail -1 || true)
    [ -n "$st" ] && break
    sleep 5
  done
  echo "$st"
}
# wait_status ID STATUS SECONDS: poll until the submission has STATUS (views can lag a few blocks)
wait_status() {
  local i
  for i in $(seq 1 $(($3 / 5))); do
    [ "$(status_of "$1")" = "$2" ] && return 0
    sleep 5
  done
  return 1
}

# ------------------------------------------------------------------ 1. accounts + contract
say "1. accounts and contract for $NAME"
stream node demo/testnet-setup.ts --master "$NAME" || die "testnet setup failed (re-run this script to continue)"
CONTRACT=$(node -p "require('$REPLAYCOURT_CONFIG').contract_id")
echo "contract: $CONTRACT  https://testnet.nearblocks.io/address/$CONTRACT"

# ------------------------------------------------------------------ 2. program and verifier keys
say "2. verifier keys and bounty program"
[ -f ".secrets/$BASE/verifier-x25519.json" ] || cli keygen || die "keygen failed"
PROGRAM=$(get PROGRAM)
if [ -z "$PROGRAM" ]; then
  out=$(cli create-program --name "Judge run: Ethereum DeFi replay bounty" --pool 1.5 --bond 0.05 --verifier-fee 0.01 \
    --payouts 0.2,0.1,0.05,0.02 --challenge 60 --pending-timeout 86400 \
    --scope 1:0xd2869042E12a3506100af1D192b5b04D65137941) || die "create-program failed"
  echo "$out"
  PROGRAM=$(echo "$out" | field "program id"); [ -n "$PROGRAM" ] || die "no program id"
  put PROGRAM "$PROGRAM"
fi
echo "program $PROGRAM"
[ -f ".secrets/$BASE/verifier-fc-key.json" ] || cli setup-verifier-key --allowance 0.5 || die "setup-verifier-key failed"

# ------------------------------------------------------------------ 3. sealed submissions
say "3. sealed submissions (two hunters) and attack c (tampered seal)"
# id of the submission in PROGRAM whose commitment is the v2 commitment of (HUNTER, FILE), if it is on chain already
find_by_commitment() { node --input-type=module -e "
  import fs from 'node:fs';
  import { loadConfig, resolveAccount } from './agent/src/config.ts'; import { makeProvider, view } from './agent/src/near.ts';
  import { commitmentFor } from './agent/src/seal.ts';
  const c = loadConfig(); const p = makeProvider(c);
  const h = commitmentFor(resolveAccount(c, '$3', 'hunter1'), fs.readFileSync('$2'));
  for (let from = 0; ; from += 50) {
    const page = await view(p, c.contractId, 'list_submissions', { program_id: $1, from_index: from, limit: 50 });
    const hit = page.find((s) => s.commitment === h);
    if (hit) { console.log(hit.id); break; }
    if (page.length < 50) break;
  }" 2>/dev/null | tail -1 || true; }
# submit STATE_KEY PROGRAM REPORT HUNTER [COMMITTED_FILE] [CMD...]: idempotent; a transaction that
# landed although the RPC answer was lost is found again by its commitment.
submit() {
  local key=$1 prog=$2 report=$3 hunter=$4 id try
  id=$(get "$key")
  [ -n "$id" ] || id=$(find_by_commitment "$prog" "$report" "$hunter")
  for try in 1 2 3; do
    [ -n "$id" ] && break
    if out=$(cli submit --program "$prog" --report "$report" --as "$hunter"); then
      echo "$out"; id=$(echo "$out" | field "submission id"); break
    fi
    echo "submit $report failed (try $try of 3); checking whether it landed, then retrying in 15 s"
    sleep 15
    id=$(find_by_commitment "$prog" "$report" "$hunter")
  done
  [ -n "$id" ] || die "submit $report failed"
  [ -n "$(get "$key")" ] || put "$key" "$id"
  echo "$report -> submission #$id"
}
submit S01 "$PROGRAM" engine/reports/01_templedao_stax.md hunter1
submit S03 "$PROGRAM" engine/reports/03_stax_duplicate.md hunter2
submit S04 "$PROGRAM" engine/reports/04_seneca_bogus.md hunter2
submit S06 "$PROGRAM" engine/reports/06_local_reentrancy.md hunter1
SC=$(get SC)
[ -n "$SC" ] || SC=$(find_by_commitment "$PROGRAM" demo/attacks/c-committed.md hunter2)
for try in 1 2 3; do
  [ -n "$SC" ] && break
  if out=$(stream node demo/attacks/c-tampered-seal.ts --program "$PROGRAM" --as hunter2); then
    echo "$out"; SC=$(echo "$out" | field "submission id"); break
  fi
  echo "attack c failed (try $try of 3); checking whether it landed, then retrying in 15 s"
  sleep 15
  SC=$(find_by_commitment "$PROGRAM" demo/attacks/c-committed.md hunter2)
done
[ -n "$SC" ] || die "attack c failed"
[ -n "$(get SC)" ] || put SC "$SC"
echo "attack c -> submission #$SC"

# ------------------------------------------------------------------ 4. worker
say "4. verifier worker (engine replay; post_verdict signed with the function-call key)"
# The demo reports re-enact public incidents, so their evidence is published at once
# (--disclose immediately); a real program keeps it private until settlement (the default).
export REPLAYCOURT_WORKER_PROGRAMS="$PROGRAM"
for round in 1 2 3 4; do
  rc=0; STREAM_TIMEOUT=3600 cli worker --once --disclose immediately || rc=$?
  [ "$rc" -eq 0 ] && break
  [ "$rc" -eq 75 ] || die "worker failed (exit $rc)"
  echo "some submissions wait for a retry (archive RPC); round $round of 4, next in 30 s"
  sleep 30
done
[ "$rc" -eq 0 ] || die "worker could not judge every submission (engine exit 69: archive RPC unavailable?) - re-run this script later"

# ------------------------------------------------------------------ 5. settlement
say "5. settlement: finalize after the challenge window, owner resolves 06"
S01=$(get S01)
for i in $(seq 1 24); do
  st=$(status_of "$S01")
  [ "$st" = "paid" ] && break
  [ "$st" = "valid" ] || die "submission #$S01 is '$st', expected valid"
  if cli finalize "$S01" --as hunter2 >/dev/null 2>&1; then echo "finalized #$S01"; wait_status "$S01" paid 60 && break; fi
  echo "challenge window still open ($i/24), next try in 10 s"
  sleep 10
done
wait_status "$S01" paid 30 || die "could not finalize #$S01 within 5 minutes"
st=$(status_of "$(get S06)")
if [ "$st" = "needs_human" ]; then
  cli resolve "$(get S06)" --outcome valid --severity high --note "judge run: owner accepts the local reentrancy PoC" || die "resolve failed"
elif [ "$st" != "paid" ]; then
  echo "note: report 06 is '$st' (expected needs_human); not resolved"
fi

# ------------------------------------------------------------------ 6. attack d
say "6. attack d: stolen function-call key"
P2=$(get P2)
if [ -z "$P2" ]; then
  V2PK=$(REPLAYCOURT_SECRETS_DIR="$ROOT/.secrets/$BASE/verifier2" node agent/src/cli.ts keygen 2>/dev/null) \
    || V2PK=$(node -p "require('$ROOT/.secrets/$BASE/verifier2/verifier-x25519.json').public_key")
  out=$(cli create-program --name "Second program, judged by verifier2" --verifier verifier2 --pubkey "$V2PK" \
    --pool 1 --bond 0.05 --verifier-fee 0.01 --payouts 0.1,0.05,0.02,0.01 --challenge 60 --pending-timeout 60) || die "create-program 2 failed"
  echo "$out"
  P2=$(echo "$out" | field "program id"); put P2 "$P2"
fi
submit SD "$P2" demo/attacks/d-target.md hunter1
stream node demo/attacks/d-stolen-key.ts --foreign "$(get SD)" --judged "$(get S01)" --allowance-demo \
  --json ".secrets/$BASE/attack-d.json" \
  || die "attack d did not pass (exit $?: 1 = an attempt with the function-call key succeeded, 2 = network errors left an attempt undecided - run this script again)"

# ------------------------------------------------------------------ 7. clean up program 2
say "7. hunter withdraws the target report after its 60 s pending timeout; owner withdraws program 2's pool"
SD=$(get SD)
for i in $(seq 1 12); do
  st=$(status_of "$SD")
  [ "$st" = "withdrawn" ] && break
  if cli withdraw-pending "$SD" --as hunter1 >/dev/null 2>&1; then echo "withdrew #$SD"; wait_status "$SD" withdrawn 60 && break; fi
  echo "pending timeout not over yet ($i/12), next try in 10 s"
  sleep 10
done
wait_status "$SD" withdrawn 30 || echo "note: #$SD could not be withdrawn yet; run the script again later"
cli withdraw-pool --program "$P2" --all >/dev/null 2>&1 && echo "program $P2 pool withdrawn" || echo "program $P2: nothing left to withdraw"

# ------------------------------------------------------------------ 8. check
say "8. verify-onchain: every posted verdict against its evidence file in runs/"
rc=0; cli verify-onchain --contract "$CONTRACT" --all-programs || rc=$?
say "status"
cli status --program "$PROGRAM" || true
echo
echo "contract:  https://testnet.nearblocks.io/address/$CONTRACT"
echo "explorer:  python3 -m http.server 8000 --bind 127.0.0.1   then  http://127.0.0.1:8000/web/?contract=$CONTRACT"
echo "evidence:  runs/testnet/$CONTRACT/   keys and run log: .secrets/$BASE/"
[ "$rc" -eq 0 ] && echo "FULL TESTNET RUN PASSED" || { echo "verify-onchain FAILED"; exit 1; }
