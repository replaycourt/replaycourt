# Shared helpers for setup-testnet.sh and e2e-testnet.sh (sourced, not executed).
# Needs: near (near-cli-rs >= 0.30), python3, curl. Testnet only.

set -euo pipefail

NETWORK=${NETWORK:-testnet}
if [ "$NETWORK" != "testnet" ]; then
  echo "These scripts run on testnet only (NETWORK=$NETWORK refused)." >&2
  exit 1
fi
# near-cli-rs network config name: "testnet" (default) or e.g. "testnet-fastnear", "testnet-lava".
NETWORK_CONFIG=${NETWORK_CONFIG:-testnet}
case "$NETWORK_CONFIG" in testnet*) ;; *) echo "NETWORK_CONFIG must be a testnet config" >&2; exit 1 ;; esac
RPC=${RPC:-https://rpc.testnet.fastnear.com}
EXPLORER=${EXPLORER:-https://testnet.nearblocks.io/txns}
CRED_DIR=${CRED_DIR:-$HOME/.near-credentials/testnet}

RUN_DIR=${RUN_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/replaycourt.XXXXXX")}
mkdir -p "$RUN_DIR"
LOG=${LOG:-$RUN_DIR/near-cli.log}
REPORT=${REPORT:-$RUN_DIR/report.md}
LAST_TX=""
LAST_OUT=""

die() { echo "ERROR: $*" >&2; exit 1; }

# Strip ANSI colour codes.
nocolor() { sed -E $'s/\x1b\\[[0-9;]*m//g'; }

report() { printf '%s\n' "$*" >> "$REPORT"; }

link() { if [ -n "$1" ]; then printf '[`%s`](%s/%s)' "$1" "$EXPLORER" "$1"; else printf '(no tx id)'; fi; }

record() { report "| $1 | $(link "$2") | $3 |"; }

# json EXPR: evaluate a python expression on JSON from stdin, bound to `j`.
json() { python3 -c 'import json,sys; j=json.load(sys.stdin); r=eval(sys.argv[1]); print(r if not isinstance(r,(dict,list)) else json.dumps(r))' "$1"; }

# yocto -> "x.xxxxxxxxxxxxxxxxxxxxxxxx NEAR" (exact, for near-cli amounts)
near_amount() { python3 -c 'import sys; y=int(sys.argv[1]); print("%d.%024d NEAR" % (y//10**24, y%10**24))' "$1"; }

# Errors near-cli reports before a transaction is sent (RPC hiccups); safe to retry.
TRANSIENT='Transaction has expired|InvalidNonce|Failed to fetch|error sending request|operation timed out|Too Many Requests|429|502 Bad Gateway|503 Service'

# near_try ARGS...: runs near, retrying transient pre-send failures. Output in last.out/last.err.
near_try() {
  local out="$RUN_DIR/last.out" err="$RUN_DIR/last.err" i rc
  for i in 1 2 3 4 5; do
    rc=0
    near "$@" >"$out" 2>"$err" || rc=$?
    if [ "$rc" -ne 0 ] && ! grep -q 'Transaction ID' "$err" && nocolor <"$err" | grep -qE "$TRANSIENT"; then
      echo "    transient RPC error, retry $i" >&2
      nocolor <"$err" | grep -E "$TRANSIENT" | head -2 >>"$LOG"
      sleep $((i * 3))
      continue
    fi
    return "$rc"
  done
  return "$rc"
}

# tx LABEL NEAR_ARGS... : a transaction that must succeed. Sets LAST_TX and LAST_OUT (stdout).
tx() {
  local label="$1"; shift
  local out="$RUN_DIR/last.out" err="$RUN_DIR/last.err"
  echo ">>> $label" | tee -a "$LOG" >&2
  if ! near_try "$@"; then
    nocolor <"$err" >>"$LOG"; nocolor <"$err" >&2
    die "step failed: $label"
  fi
  nocolor <"$err" >>"$LOG"; cat "$out" >>"$LOG"
  LAST_TX=$(nocolor <"$err" | grep -oE 'Transaction ID: [1-9A-HJ-NP-Za-km-z]+' | head -1 | awk '{print $3}' || true)
  LAST_OUT=$(cat "$out")
  record "$label" "$LAST_TX" "ok"
  echo "    tx ${LAST_TX:-none}" >&2
}

# tx_fail LABEL REGEX NEAR_ARGS... : must FAIL and the output must match REGEX.
tx_fail() {
  local label="$1" expect="$2"; shift 2
  local out="$RUN_DIR/last.out" err="$RUN_DIR/last.err"
  echo ">>> $label (must fail)" | tee -a "$LOG" >&2
  if near_try "$@"; then
    nocolor <"$err" >>"$LOG"
    die "step unexpectedly succeeded: $label"
  fi
  nocolor <"$err" >>"$LOG"; cat "$out" >>"$LOG"
  local msg
  msg=$(cat "$err" "$out" | nocolor | grep -oE "$expect" | head -1 || true)
  [ -n "$msg" ] || { nocolor <"$err" >&2; die "step failed for the wrong reason: $label (expected /$expect/)"; }
  LAST_TX=$(nocolor <"$err" | grep -oE 'Transaction ID: [1-9A-HJ-NP-Za-km-z]+' | head -1 | awk '{print $3}' || true)
  local where
  if [ -n "$LAST_TX" ]; then
    where=$(link "$LAST_TX")
  elif nocolor <"$err" | grep -q 'Smart contract panicked'; then
    where="(executed on chain and failed; near-cli prints no tx id for failed txs)"
  else
    where="(rejected by the RPC, never included)"
  fi
  report "| $label | $where | failed as expected: \`$msg\` |"
  echo "    failed as expected: $msg (tx ${LAST_TX:-none})" >&2
}

# view METHOD JSON_ARGS : read-only call, prints the JSON result.
view() {
  local i out
  for i in 1 2 3 4 5 6; do
    out=$(near contract call-function as-read-only "$CONTRACT" "$1" json-args "$2" \
      network-config "$NETWORK_CONFIG" now 2>>"$LOG" || true)
    if [ -n "$out" ] && printf '%s' "$out" | python3 -c 'import json,sys; json.load(sys.stdin)' 2>/dev/null; then
      printf '%s\n' "$out"; return 0
    fi
    sleep $((i * 2))
  done
  die "view $1 failed"
}

# call LABEL SIGNER METHOD JSON_ARGS DEPOSIT : transaction signed with the legacy keychain.
call() {
  tx "$1" contract call-function as-transaction "$CONTRACT" "$3" json-args "$4" \
    prepaid-gas '100 Tgas' attached-deposit "$5" sign-as "$2" \
    network-config "$NETWORK_CONFIG" sign-with-legacy-keychain send
}

call_fail() {
  local label="$1" expect="$2"; shift 2
  tx_fail "$label" "$expect" contract call-function as-transaction "$CONTRACT" "$2" json-args "$3" \
    prepaid-gas '100 Tgas' attached-deposit "$4" sign-as "$1" \
    network-config "$NETWORK_CONFIG" sign-with-legacy-keychain send
}

# rpc JSON_BODY: JSON-RPC POST with retries (public endpoints rate-limit).
rpc() {
  local i body
  for i in 1 2 3 4 5 6; do
    body=$(curl -sS --max-time 20 "$RPC" -H 'Content-Type: application/json' -d "$1" 2>/dev/null || true)
    if printf '%s' "$body" | python3 -c 'import json,sys; json.load(sys.stdin)' 2>/dev/null; then
      printf '%s' "$body"; return 0
    fi
    sleep $((i * 2))
  done
  die "RPC $RPC did not answer"
}

account_exists() {
  rpc "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"query\",\"params\":{\"request_type\":\"view_account\",\"finality\":\"final\",\"account_id\":\"$1\"}}" \
    | python3 -c 'import json,sys; sys.exit(0 if "result" in json.load(sys.stdin) else 1)'
}

# Latest final block timestamp (ns).
chain_now() {
  rpc '{"jsonrpc":"2.0","id":1,"method":"block","params":{"finality":"final"}}' \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"]["header"]["timestamp"])'
}
