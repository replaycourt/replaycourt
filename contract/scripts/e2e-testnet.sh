#!/usr/bin/env bash
# End-to-end test of the deployed ReplayCourt v2 contract on NEAR testnet (near-cli-rs).
#
#   scripts/e2e-testnet.sh <master-account>.testnet
#
# Expects the accounts and the deployment made by scripts/setup-testnet.sh:
#   contract./owner./verifier./hunter1./hunter2.<master>, keys in the legacy keychain.
# Override with CONTRACT=, CONTRACT_OWNER=, OWNER=, VERIFIER=, HUNTER1=, HUNTER2= if needed.
#
# Covers (all windows and timeouts 60 s):
# - a function-call key for the verifier, limited to post_verdict; every verdict is signed with it;
# - dispute with the dispute bond (excess refunded), then resolve invalid: the hunter's balance
#   grows by exactly bond + dispute bond;
# - a dispute the owner does not resolve in time: resolve is refused after resolve_until, and
#   finalize pays payout + bond + dispute bond;
# - needs_human that expires through finalize after resolve_until (full bond back, to the vault);
# - a duplicate of an invalid original, refused by the contract;
# - hunter vault: deposit and policy set with a full-access key; a function-call key on the
#   hunter limited to submit_report_from_vault, finalize and withdraw_pending, used to submit
#   from the vault, to finalize and to withdraw; the same key failing on vault_withdraw and
#   vault_set_policy; a key that does allow those methods still cannot withdraw or change the
#   policy (no deposit from function-call keys, and the contract wants exactly 1 yoctoNEAR);
# - a vault policy refusal (daily spend limit), refunds of vault-funded bonds into the vault.
# Writes a Markdown table of all transactions to $REPORT (default: a temp dir).

HERE=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=lib.sh
. "$HERE/lib.sh"

MASTER=${1:-${MASTER:-}}
[ -n "$MASTER" ] || die "usage: $0 <master-account>.testnet"
CONTRACT=${CONTRACT:-contract.$MASTER}
OWNER=${OWNER:-owner.$MASTER}
VERIFIER=${VERIFIER:-verifier.$MASTER}
HUNTER1=${HUNTER1:-hunter1.$MASTER}
HUNTER2=${HUNTER2:-hunter2.$MASTER}
CONTRACT_OWNER=${CONTRACT_OWNER:-$MASTER} # the owner_id passed to new(); has no power over funds
RUN_ID=${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}
WINDOW_SEC=60                            # challenge window, pending timeout and resolve timeout
STORAGE_MARGIN=50000000000000000000000   # 0.05 NEAR on top of required_bond; the excess is bond
DISPUTE_BOND=150000000000000000000000    # 0.15 NEAR
DISPUTE_EXCESS=10000000000000000000000   # 0.01 NEAR attached on top, refunded
VAULT_DEPOSIT='1 NEAR'
MAX_BOND=100000000000000000000000        # 0.1 NEAR = the program bond
DAY_BUDGET=300000000000000000000000      # 0.3 NEAR per 24 h: two reports fit, the third does not

for a in "$CONTRACT" "$OWNER" "$VERIFIER" "$HUNTER1" "$HUNTER2"; do
  account_exists "$a" || die "account $a does not exist (run scripts/setup-testnet.sh first)"
done
[ "$(view version '{}')" = '"2.0.0"' ] || die "contract $CONTRACT is not ReplayCourt 2.0.0"

report "# ReplayCourt v2 testnet E2E run $RUN_ID"
report ""
report "Contract \`$CONTRACT\`, owner \`$OWNER\`, verifier \`$VERIFIER\`, hunters \`$HUNTER1\`, \`$HUNTER2\`."
report ""
report "| step | transaction | result |"
report "|---|---|---|"

add() { python3 -c 'import sys; print(sum(int(x) for x in sys.argv[1:]))' "$@"; }
# commitment v2 = sha256("replaycourt/commit/v2" 0x00 hunter 0x00 report), see SPEC.md
commitment() { python3 -c 'import hashlib,sys; print(hashlib.sha256(b"replaycourt/commit/v2\0"+sys.argv[1].encode()+b"\0"+sys.argv[2].encode()).hexdigest())' "$1" "$2"; }
sealed() { python3 -c 'import base64,json,sys; print(base64.b64encode(json.dumps({"v":1,"alg":"x25519-hkdf-sha256-aes256gcm","epk":"ZHVtbXk=","iv":"ZHVtbXk=","ct":base64.b64encode(sys.argv[1].encode()).decode(),"tag":"ZHVtbXk="}).encode()).decode())' "$1"; }
verdict_json() { # outcome severity|null duplicate_of|null reason
  python3 -c 'import json,sys
o,s,d,r=sys.argv[1:5]
print(json.dumps({"outcome":o,"severity":None if s=="null" else s,"duplicate_of":None if d=="null" else int(d),
 "fingerprint":"e2e-"+o,"evidence_sha256":"ab"*32,"evidence_uri":"runs/testnet/e2e/evidence.json",
 "chain_id":0,"fork_block":"0","reason":r}))' "$1" "$2" "$3" "$4"
}
report_args() { # HUNTER N TITLE
  printf '{"program_id":%s,"title":"%s","commitment":"%s","sealed":"%s"}' "$PID" "$3" \
    "$(commitment "$1" "ReplayCourt e2e $RUN_ID report $2")" "$(sealed "report $2 of run $RUN_ID")"
}
balance() { # optimistic balance in yoctoNEAR
  rpc "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"query\",\"params\":{\"request_type\":\"view_account\",\"finality\":\"optimistic\",\"account_id\":\"$1\"}}" \
    | json 'j["result"]["amount"]'
}
# expect_gain ACCOUNT BEFORE AMOUNT LABEL: the balance must grow by exactly AMOUNT (polls ~30 s)
expect_gain() {
  local i now
  for i in $(seq 1 10); do
    now=$(balance "$1")
    if [ "$(add "$now" "-$2")" = "$3" ]; then
      echo "    $1 gained exactly $(near_amount "$3")" >&2
      report "| $4 | (balance of \`$1\`) | gained exactly $(near_amount "$3") |"
      return 0
    fi
    sleep 3
  done
  die "$1 gained $(add "$now" "-$2") yoctoNEAR, expected $3 ($4)"
}
status_of() { view get_submission "{\"submission_id\":$1}" | json 'j["status"]'; }
sub_field() { view get_submission "{\"submission_id\":$1}" | json "j[\"$2\"]"; }
expect_status() { local s; s=$(status_of "$1"); [ "$s" = "$2" ] || die "submission $1: status $s, expected $2"; echo "    submission $1 is $s" >&2; }
vault_balance() { view get_vault "{\"account_id\":\"$HUNTER1\"}" | json 'int(j["balance"])'; }
wait_chain() { # NS LABEL: wait until the chain time passes NS (+2 s)
  local now
  while :; do
    now=$(chain_now)
    [ "$now" -ge "$(add "$1" 2000000000)" ] && break
    echo "    waiting for $2 ($(( ($1 - now) / 1000000000 + 2 )) s left)" >&2
    sleep 5
  done
}
# key_file ACCOUNT PUBLIC_KEY: path of the legacy-keychain file of that key
key_file() { printf '%s/%s/%s.json' "$CRED_DIR" "$1" "$(printf '%s' "$2" | tr ':' '_')"; }
new_key_file() { # after an add-key: the file near-cli saved the new key to
  nocolor <"$RUN_DIR/last.err" | grep -oE "saved in a file [^ ]+/$1/ed25519_[^ ]+\.json" | head -1 | sed 's/^saved in a file //'
}
permission() {
  rpc "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"query\",\"params\":{\"request_type\":\"view_access_key\",\"finality\":\"final\",\"account_id\":\"$1\",\"public_key\":\"$2\"}}" \
    | json 'j["result"]["permission"]'
}
# call_key LABEL SIGNER KEY_FILE METHOD JSON_ARGS DEPOSIT: transaction signed with one key file
call_key() {
  tx "$1" contract call-function as-transaction "$CONTRACT" "$4" json-args "$5" \
    prepaid-gas '100 Tgas' attached-deposit "$6" sign-as "$2" \
    network-config "$NETWORK_CONFIG" sign-with-access-key-file "$3" send
}
call_key_fail() { # LABEL REGEX SIGNER KEY_FILE METHOD JSON_ARGS DEPOSIT
  tx_fail "$1" "$2" contract call-function as-transaction "$CONTRACT" "$5" json-args "$6" \
    prepaid-gas '100 Tgas' attached-deposit "$7" sign-as "$3" \
    network-config "$NETWORK_CONFIG" sign-with-access-key-file "$4" send
}
# submit HUNTER N TITLE -> prints submission id. Deposit = required_bond + 0.05 NEAR storage.
submit() {
  local hunter="$1" req deposit
  req=$(view required_bond "{\"program_id\":$PID,\"hunter_id\":\"$hunter\"}" | json 'int(j)')
  deposit=$(near_amount "$(add "$req" "$STORAGE_MARGIN")")
  call "submit_report #$2 by $hunter (deposit $deposit)" "$hunter" submit_report \
    "$(report_args "$hunter" "$2" "$3")" "$deposit"
  echo "$LAST_OUT" | tr -d '"[:space:]'
}

# hunter1's full-access key (explicit file, so added function-call keys never sign by accident)
H1_FA_PK=$(json 'j["public_key"]' <"$CRED_DIR/$HUNTER1.json")
H1_FA_KEY=$(key_file "$HUNTER1" "$H1_FA_PK")
[ -f "$H1_FA_KEY" ] || H1_FA_KEY="$CRED_DIR/$HUNTER1.json"
[ "$(permission "$HUNTER1" "$H1_FA_PK")" = "FullAccess" ] || die "$HUNTER1.json is not a full-access key"

# ---------------------------------------------------------------- 1. program
PROGRAM_ARGS=$(python3 -c 'import json,sys
v=sys.argv[1]; w=int(sys.argv[3])
print(json.dumps({"name":"ReplayCourt v2 e2e "+sys.argv[2],
 "scope":[{"chain_id":1,"address":"0x00000000000000000000000000000000000000aa"}],
 "verifier_id":v,"verifier_pubkey":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=",
 "payouts":{"critical":"300000000000000000000000","high":"200000000000000000000000",
            "medium":"100000000000000000000000","low":"50000000000000000000000"},
 "bond":"100000000000000000000000","verifier_fee":"10000000000000000000000",
 "dispute_bond":sys.argv[4],
 "challenge_period_sec":w,"pending_timeout_sec":w,"resolve_timeout_sec":w}))' \
 "$VERIFIER" "$RUN_ID" "$WINDOW_SEC" "$DISPUTE_BOND")
call "create_program (pool 3 NEAR, dispute bond 0.15 NEAR, all windows ${WINDOW_SEC}s)" \
  "$OWNER" create_program "$PROGRAM_ARGS" '3 NEAR'
PID=$(echo "$LAST_OUT" | tr -d '"[:space:]')
echo "    program id $PID" >&2

# ------------------------------------------------------------- 2. access keys
tx "add function-call key to $VERIFIER (receiver $CONTRACT, method post_verdict only)" \
  account add-key "$VERIFIER" grant-function-call-access --allowance '0.25 NEAR' \
  --contract-account-id "$CONTRACT" --function-names post_verdict \
  autogenerate-new-keypair save-to-legacy-keychain \
  network-config "$NETWORK_CONFIG" sign-with-legacy-keychain send
V_FC_KEY=$(new_key_file "$VERIFIER")
[ -f "$V_FC_KEY" ] || die "could not find the verifier's function-call key file"
V_FC_PK=$(json 'j["public_key"]' <"$V_FC_KEY")
report "| verifier key \`$V_FC_PK\` | (see add-key tx above) | on-chain permission: \`$(permission "$VERIFIER" "$V_FC_PK")\` |"

tx "add function-call key to $HUNTER1 (receiver $CONTRACT, methods submit_report_from_vault, finalize, withdraw_pending)" \
  account add-key "$HUNTER1" grant-function-call-access --allowance '0.25 NEAR' \
  --contract-account-id "$CONTRACT" --function-names submit_report_from_vault,finalize,withdraw_pending \
  autogenerate-new-keypair save-to-legacy-keychain \
  network-config "$NETWORK_CONFIG" sign-with-access-key-file "$H1_FA_KEY" send
H_FC_KEY=$(new_key_file "$HUNTER1")
[ -f "$H_FC_KEY" ] || die "could not find the hunter's function-call key file"
H_FC_PK=$(json 'j["public_key"]' <"$H_FC_KEY")
H_FC_PERM=$(permission "$HUNTER1" "$H_FC_PK")
echo "$H_FC_PERM" | grep -q submit_report_from_vault || die "hunter key permission: $H_FC_PERM"
report "| hunter agent key \`$H_FC_PK\` | (see add-key tx above) | on-chain permission: \`$H_FC_PERM\` |"

verdict_fc() { # LABEL ID OUTCOME SEVERITY DUPLICATE_OF REASON
  call_key "$1 (verifier function-call key)" "$VERIFIER" "$V_FC_KEY" post_verdict \
    "{\"submission_id\":$2,\"verdict\":$(verdict_json "$3" "$4" "$5" "$6")}" '0 NEAR'
}
agent() { # LABEL METHOD JSON_ARGS: hunter1's function-call key
  call_key "$1 (hunter function-call key)" "$HUNTER1" "$H_FC_KEY" "$2" "$3" '0 NEAR'
}

# ------------------------------------------------------------------ 3. vault
# A spend window still open from an earlier run counts against the limit: add its spend.
SPENT_OPEN=0
OLD_VAULT=$(view get_vault "{\"account_id\":\"$HUNTER1\"}")
if [ "$OLD_VAULT" != "null" ]; then
  SPENT_OPEN=$(printf '%s' "$OLD_VAULT" | python3 -c 'import json,sys
v=json.load(sys.stdin); now=int(sys.argv[1]); ws=int(v["window_start"])
print(v["spent_in_window"] if ws > 0 and now < ws + 86400*10**9 else 0)' "$(chain_now)")
fi
MAX_SPEND=$(add "$SPENT_OPEN" "$DAY_BUDGET")
call_key "vault_deposit $VAULT_DEPOSIT by $HUNTER1 (full-access key)" "$HUNTER1" "$H1_FA_KEY" \
  vault_deposit '{}' "$VAULT_DEPOSIT"
call_key "vault_set_policy by $HUNTER1 (full-access key, 1 yoctoNEAR): max bond 0.1, $(near_amount "$MAX_SPEND")/day, allowed [$PID]" \
  "$HUNTER1" "$H1_FA_KEY" vault_set_policy \
  "{\"max_bond_per_report\":\"$MAX_BOND\",\"max_spend_per_day\":\"$MAX_SPEND\",\"allowed_programs\":[$PID]}" \
  '1 yoctoNEAR'
VAULT=$(view get_vault "{\"account_id\":\"$HUNTER1\"}")
echo "$VAULT" | json 'j["policy_set"]' | grep -q True || die "vault policy not set: $VAULT"
report "| get_vault($HUNTER1) | (view) | \`$VAULT\` |"

# ---------------------------------------------------------------- 4. reports
A=$(submit "$HUNTER2" 1 "E2E v2 A (valid, disputed, overruled)")
C=$(submit "$HUNTER2" 2 "E2E v2 C (valid, disputed, not resolved in time)")
E=$(submit "$HUNTER2" 3 "E2E v2 E (invalid)")
agent "submit_report_from_vault #4 B (needs_human, expires)" submit_report_from_vault \
  "$(report_args "$HUNTER1" 4 "E2E v2 B (vault, needs_human, expires)")"
B=$(echo "$LAST_OUT" | tr -d '"[:space:]')
agent "submit_report_from_vault #5 F (pending, withdrawn)" submit_report_from_vault \
  "$(report_args "$HUNTER1" 5 "E2E v2 F (vault, withdrawn after the timeout)")"
F=$(echo "$LAST_OUT" | tr -d '"[:space:]')
echo "    submissions A=$A C=$C E=$E B=$B F=$F" >&2
[ "$(sub_field "$B" funded_by_vault)" = "True" ] || die "B is not vault-funded"
[ "$(sub_field "$B" bond)" = "$MAX_BOND" ] || die "B bond is not exactly required_bond"
call_key_fail "submit_report_from_vault #6 G over the daily spend limit (policy refusal)" \
  'vault max_spend_per_day exceeded' "$HUNTER1" "$H_FC_KEY" submit_report_from_vault \
  "$(report_args "$HUNTER1" 6 "E2E v2 G (refused by the vault policy)")" '0 NEAR'
# (JSON arguments go through variables: bash mangles escaped quotes inside "...$(...)...")
VAULT=$(view get_vault "{\"account_id\":\"$HUNTER1\"}")
report "| get_vault($HUNTER1) after two reports | (view) | \`$VAULT\` |"
LP_ARGS="{\"program_id\":$PID,\"from_index\":0,\"limit\":50}"
PENDING=$(view list_pending "$LP_ARGS" | json '[s["id"] for s in j]')
report "| list_pending($PID) | (view) | ids \`$PENDING\` |"

# ------------------------------------- 5. what the hunter's agent key cannot do
call_key_fail "agent key tries vault_withdraw (1 yoctoNEAR)" \
  'deposit with a function call action is not allowed[^.]*|DepositWithFunctionCall|MethodNameMismatch|isn.t allowed by the access key|InvalidAccessKey[A-Za-z]*' \
  "$HUNTER1" "$H_FC_KEY" vault_withdraw '{"amount":"100000000000000000000000"}' '1 yoctoNEAR'
call_key_fail "agent key tries vault_withdraw (no deposit)" \
  'MethodNameMismatch|isn.t allowed by the access key|InvalidAccessKey[A-Za-z]*' \
  "$HUNTER1" "$H_FC_KEY" vault_withdraw '{"amount":"100000000000000000000000"}' '0 NEAR'
call_key_fail "agent key tries vault_set_policy (1 yoctoNEAR)" \
  'deposit with a function call action is not allowed[^.]*|DepositWithFunctionCall|MethodNameMismatch|isn.t allowed by the access key|InvalidAccessKey[A-Za-z]*' \
  "$HUNTER1" "$H_FC_KEY" vault_set_policy \
  "{\"max_bond_per_report\":\"$MAX_BOND\",\"max_spend_per_day\":\"100000000000000000000000000\",\"allowed_programs\":null}" '1 yoctoNEAR'
call_key_fail "agent key tries vault_set_policy (no deposit)" \
  'MethodNameMismatch|isn.t allowed by the access key|InvalidAccessKey[A-Za-z]*' \
  "$HUNTER1" "$H_FC_KEY" vault_set_policy \
  "{\"max_bond_per_report\":\"$MAX_BOND\",\"max_spend_per_day\":\"100000000000000000000000000\",\"allowed_programs\":null}" '0 NEAR'
# even a function-call key that lists these methods cannot use them
tx "add a second function-call key to $HUNTER1 that allows vault_withdraw and vault_set_policy" \
  account add-key "$HUNTER1" grant-function-call-access --allowance '0.25 NEAR' \
  --contract-account-id "$CONTRACT" --function-names vault_withdraw,vault_set_policy \
  autogenerate-new-keypair save-to-legacy-keychain \
  network-config "$NETWORK_CONFIG" sign-with-access-key-file "$H1_FA_KEY" send
W_KEY=$(new_key_file "$HUNTER1")
[ -f "$W_KEY" ] && [ "$W_KEY" != "$H_FC_KEY" ] || die "could not find the second key file"
W_PK=$(json 'j["public_key"]' <"$W_KEY")
call_key_fail "key allowing vault_withdraw calls it without deposit (contract refuses)" \
  'requires an attached deposit of exactly 1 yoctoNEAR' \
  "$HUNTER1" "$W_KEY" vault_withdraw '{"amount":"100000000000000000000000"}' '0 NEAR'
call_key_fail "key allowing vault_withdraw attaches 1 yoctoNEAR (runtime refuses)" \
  'deposit with a function call action is not allowed[^.]*|DepositWithFunctionCall|InvalidAccessKey[A-Za-z]*' \
  "$HUNTER1" "$W_KEY" vault_withdraw '{"amount":"100000000000000000000000"}' '1 yoctoNEAR'
call_key_fail "key allowing vault_set_policy calls it without deposit (contract refuses)" \
  'requires an attached deposit of exactly 1 yoctoNEAR' \
  "$HUNTER1" "$W_KEY" vault_set_policy \
  "{\"max_bond_per_report\":\"$MAX_BOND\",\"max_spend_per_day\":\"100000000000000000000000000\",\"allowed_programs\":null}" '0 NEAR'
tx "delete the second key (full-access key)" \
  account delete-keys "$HUNTER1" public-keys "$W_PK" \
  network-config "$NETWORK_CONFIG" sign-with-access-key-file "$H1_FA_KEY" send

# --------------------------------------------- 6. verdicts, disputes, duplicates
verdict_fc "post_verdict E = invalid" "$E" invalid null null "PoC does not reproduce"
expect_status "$E" invalid
verdict_fc "post_verdict B = needs_human" "$B" needs_human null null "trace ambiguous"
expect_status "$B" needs_human
B_RESOLVE_UNTIL=$(sub_field "$B" resolve_until)
call_key_fail "post_verdict F = duplicate of the invalid E (verifier function-call key)" \
  'duplicate_of must be a valid, paid or disputed submission' \
  "$VERIFIER" "$V_FC_KEY" post_verdict \
  "{\"submission_id\":$F,\"verdict\":$(verdict_json duplicate null "$E" "same as E")}" '0 NEAR'
expect_status "$F" pending

verdict_fc "post_verdict A = valid/high" "$A" valid high null "replayed on fork: drained vault"
call "dispute A by the program owner (0.16 NEAR attached: dispute bond 0.15 + 0.01 excess)" \
  "$OWNER" dispute "{\"submission_id\":$A,\"reason\":\"known issue, already fixed\"}" \
  "$(near_amount "$(add "$DISPUTE_BOND" "$DISPUTE_EXCESS")")"
expect_status "$A" disputed
[ "$(sub_field "$A" dispute_bond)" = "$DISPUTE_BOND" ] || die "A dispute bond not held"
BOND_A=$(sub_field "$A" bond)
H2_BEFORE=$(balance "$HUNTER2")
call "resolve A = invalid by the program owner (overruled: hunter gets bond + dispute bond)" \
  "$OWNER" resolve "{\"submission_id\":$A,\"outcome\":\"invalid\",\"severity\":null,\"note\":\"not exploitable on mainnet\"}" '0 NEAR'
expect_status "$A" rejected
expect_gain "$HUNTER2" "$H2_BEFORE" "$(add "$BOND_A" "$DISPUTE_BOND")" "hunter2 after resolve A = invalid: bond + dispute bond"

verdict_fc "post_verdict C = valid/medium" "$C" valid medium null "replayed on fork"
call "dispute C by the program owner (exactly the dispute bond)" \
  "$OWNER" dispute "{\"submission_id\":$C,\"reason\":\"disputed, then left alone\"}" \
  "$(near_amount "$DISPUTE_BOND")"
expect_status "$C" disputed
C_RESOLVE_UNTIL=$(sub_field "$C" resolve_until)
BOND_C=$(sub_field "$C" bond)
if [ "$(chain_now)" -lt "$(add "$C_RESOLVE_UNTIL" -15000000000)" ]; then
  call_key_fail "finalize C before resolve_until" 'resolve deadline has not passed yet' \
    "$HUNTER1" "$H_FC_KEY" finalize "{\"submission_id\":$C}" '0 NEAR'
else
  report "| finalize C before resolve_until | | skipped: RPC too slow, deadline almost over |"
fi
call_fail "resolve C = duplicate (a disputed report resolves as valid or invalid)" \
  'a disputed report resolves as valid or invalid' \
  "$OWNER" resolve "{\"submission_id\":$C,\"outcome\":\"duplicate\",\"severity\":null,\"note\":\"\"}" '0 NEAR'

# ------------------------------------------------------- 7. after the deadlines
wait_chain "$B_RESOLVE_UNTIL" "B's resolve deadline"
VB=$(vault_balance)
agent "finalize B after resolve_until (needs_human expires)" finalize "{\"submission_id\":$B}"
expect_status "$B" expired
[ "$(add "$(vault_balance)" "-$VB")" = "$MAX_BOND" ] || die "B's bond did not return to the vault"
report "| vault balance after B expired | (view) | +$(near_amount "$MAX_BOND") (bond back into the vault) |"

F_DUE=$(add "$(sub_field "$F" submitted_at)" "${WINDOW_SEC}000000000")
wait_chain "$F_DUE" "F's pending timeout"
VB=$(vault_balance)
agent "withdraw_pending F after the pending timeout" withdraw_pending "{\"submission_id\":$F}"
expect_status "$F" withdrawn
[ "$(add "$(vault_balance)" "-$VB")" = "$MAX_BOND" ] || die "F's bond did not return to the vault"
report "| vault balance after F was withdrawn | (view) | +$(near_amount "$MAX_BOND") (bond back into the vault) |"

wait_chain "$C_RESOLVE_UNTIL" "C's resolve deadline"
call_fail "resolve C after resolve_until" 'resolve deadline has passed' \
  "$OWNER" resolve "{\"submission_id\":$C,\"outcome\":\"invalid\",\"severity\":null,\"note\":\"too late\"}" '0 NEAR'
H2_BEFORE=$(balance "$HUNTER2")
agent "finalize C after resolve_until (owner did not resolve)" finalize "{\"submission_id\":$C}"
expect_status "$C" paid
expect_gain "$HUNTER2" "$H2_BEFORE" "$(add 100000000000000000000000 "$BOND_C" "$DISPUTE_BOND")" \
  "hunter2 after finalize C: payout (medium) + bond + dispute bond"

# ------------------------------------------------------------ 8. clean up, state
PROGRAM=$(view get_program "{\"program_id\":$PID}")
[ "$(echo "$PROGRAM" | json 'j["reserved"]')" = "0" ] || die "reserved should be 0: $PROGRAM"
[ "$(echo "$PROGRAM" | json 'j["stats"]["overruled"]')" = "1" ] || die "stats.overruled should be 1"
POOL=$(echo "$PROGRAM" | json 'j["pool"]')
call "owner withdraws the whole remaining pool ($(near_amount "$POOL"))" "$OWNER" withdraw_pool \
  "{\"program_id\":$PID,\"amount\":\"$POOL\"}" '0 NEAR'
VB=$(vault_balance)
call_key "vault_withdraw of the whole vault by $HUNTER1 (full-access key, 1 yoctoNEAR)" \
  "$HUNTER1" "$H1_FA_KEY" vault_withdraw "{\"amount\":\"$(add "$VB" 1)\"}" '1 yoctoNEAR'
[ "$(vault_balance)" = "0" ] || die "vault not empty"

FINAL_PROGRAM=$(view get_program "{\"program_id\":$PID}")
H1_ARGS="{\"program_id\":$PID,\"account_id\":\"$HUNTER1\"}"
H2_ARGS="{\"program_id\":$PID,\"account_id\":\"$HUNTER2\"}"
FINAL_H1=$(view get_hunter_in_program "$H1_ARGS")
FINAL_H2=$(view get_hunter_in_program "$H2_ARGS")
FINAL_VAULT=$(view get_vault "{\"account_id\":\"$HUNTER1\"}")
report ""
report "Final state:"
report ""
report '```'
report "get_program($PID): $FINAL_PROGRAM"
report "get_hunter_in_program($PID, $HUNTER1): $FINAL_H1"
report "get_hunter_in_program($PID, $HUNTER2): $FINAL_H2"
report "get_vault($HUNTER1): $FINAL_VAULT"
FIELDS='{k:j[k] for k in ("id","status","bond","payout","dispute_bond","funded_by_vault","storage_cost")}'
for s in "$A" "$C" "$E" "$B" "$F"; do
  ROW=$(view get_submission "{\"submission_id\":$s}" | json "$FIELDS")
  report "submission $s: $ROW"
done
report '```'
echo "E2E PASSED. Report: $REPORT" >&2
