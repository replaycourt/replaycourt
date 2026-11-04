#!/usr/bin/env bash
# Judge path B: replay the demo reports with the engine on your machine (no NEAR account needed).
#
#   demo/engine-replay.sh            reports 01-06 in commit order, fresh duplicate registry
#   demo/engine-replay.sh --all      also the attack reports a/b and the engine probes
#
# Needs: python3 (>= 3.8), Foundry's forge (PATH, ~/.foundry/bin or REPLAYCOURT_FORGE), internet
# access to a free Ethereum archive RPC (engine/config/chains.json). Writes only to a temporary
# directory (printed at the end; OUT=<dir> to choose it). Exit 0 only if every outcome matches.
# An engine exit 69 means "archive RPC unavailable, no verdict": the script retries it twice.

set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
OUT=${OUT:-$(mktemp -d "${TMPDIR:-/tmp}/replaycourt-replay.XXXXXX")}
mkdir -p "$OUT"
REGISTRY="$OUT/registry.jsonl"
rm -f "$REGISTRY"

command -v python3 >/dev/null || { echo "python3 not found" >&2; exit 2; }

# report path | expected outcome (as in verdict.json) | expected duplicate-of (or -) | engine options
CASES=(
  "engine/reports/01_templedao_stax.md|valid|-"
  "engine/reports/02_seneca_chamber.md|valid|-"
  "engine/reports/03_stax_duplicate.md|duplicate|01-templedao-stax"
  "engine/reports/04_seneca_bogus.md|invalid|-"
  "engine/reports/05_fake_profit.md|invalid|-"
  "engine/reports/06_local_reentrancy.md|needs_human|-"
)
if [ "${1:-}" = "--all" ]; then
  CASES+=(
    "demo/attacks/a-prompt-injection.md|invalid|-"
    "demo/attacks/b-sandbox-escape.md|invalid|-"
    "demo/attacks/engine-probes/fake-transfer-event.md|invalid|-"
    "demo/attacks/engine-probes/fake-transfer-helper.md|invalid|-"
    "demo/attacks/engine-probes/foreign-fork-url.md|invalid|-"
    "demo/attacks/engine-probes/foreign-fork-real-exploit.md|needs_human|-"
    "demo/attacks/engine-probes/dead-fork-url.md|invalid|-"
    "demo/attacks/engine-probes/revert-429.md|invalid|-"
    "demo/attacks/engine-probes/broadcast-as-whale.md|invalid|-"
    "demo/attacks/engine-probes/prank-raw-selector.md|invalid|-"
    "demo/attacks/engine-probes/hidden-prank-pause-tracing.md|invalid|-"
    # What a program accepts: the same real exploits, in and out of a program's scope.
    "engine/reports/01_templedao_stax.md|valid|-|--scope 1:0xd2869042E12a3506100af1D192b5b04D65137941"
    "engine/reports/02_seneca_chamber.md|valid|-|--scope 1:0x65c210c59B43EB68112b7a4f75C8393C36491F06"
    "engine/reports/01_templedao_stax.md|invalid|-|--scope 1:0x65c210c59B43EB68112b7a4f75C8393C36491F06"
    "engine/reports/01_templedao_stax.md|invalid|-|--scope 8453:0xd2869042E12a3506100af1D192b5b04D65137941"
    "engine/reports/01_templedao_stax.md|invalid|-|--min-block 20000000"
  )
fi

cd "$ROOT"
fail=0
printf '%-55s %-5s %-12s %-12s %s\n' "report" "exit" "outcome" "expected" "result"
for c in "${CASES[@]}"; do
  IFS='|' read -r report expected dup options <<<"$c"
  name=$(basename "$report" .md)
  # shellcheck disable=SC2206
  opts=($options)
  [ -n "$options" ] && name="$name $(printf '%s' "$options" | cut -c3-24)"
  # 01-06 share one duplicate registry, in commit order. The attack and probe reports are
  # checked against an empty registry and not registered, so they are judged on their own
  # (the foreign-fork probe reuses report 01's PoC and would otherwise be its duplicate).
  extra=(--registry "$REGISTRY")
  case "$report" in engine/reports/*) [ -z "$options" ] || extra=(--registry "$OUT/empty-registry.jsonl" --no-register) ;;
    *) extra=(--registry "$OUT/empty-registry.jsonl" --no-register) ;; esac
  for attempt in 1 2 3; do
    python3 -I engine/replay.py check "$report" --quiet "${extra[@]}" ${opts[@]+"${opts[@]}"} \
      --dest "$OUT/$name" >"$OUT/$name.stdout" 2>"$OUT/$name.stderr"
    rc=$?
    [ "$rc" -ne 69 ] && break
    echo "  $name: engine exit 69 (archive RPC unavailable), retry $attempt in 20 s" >&2
    sleep 20
  done
  got=$(python3 -c 'import json,sys
try:
    v=json.load(open(sys.argv[1])); d=(v.get("duplicate") or {})
    print("%s|%s" % (v.get("outcome"), d.get("of") if d.get("status")=="duplicate" else "-"))
except Exception:
    print("none|-")' "$OUT/$name/verdict.json")
  outcome=${got%%|*}; gotdup=${got#*|}
  if [ "$outcome" = "$expected" ] && [ "$gotdup" = "$dup" ]; then res=ok; else res=MISMATCH; fail=1; fi
  label=$expected; [ "$dup" != "-" ] && label="$expected of $dup"
  shown=$outcome; [ "$gotdup" != "-" ] && shown="$outcome of $gotdup"
  printf '%-55s %-5s %-12s %-12s %s\n' "$name" "$rc" "$shown" "$label" "$res"
done
echo
echo "verdicts and logs: $OUT/<report>/ (verdict.json, summary.md, forge-test.json)"
[ "$fail" -eq 0 ] && echo "ALL OUTCOMES AS EXPECTED" || echo "SOME OUTCOMES DIFFER"
exit "$fail"
