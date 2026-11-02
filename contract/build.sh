#!/usr/bin/env bash
# Privacy-safe wasm build of the ReplayCourt contract.
#
#   ./build.sh           build, check, print the sha256 and write it to WASM_SHA256
#   ./build.sh --check   build, check, and compare the sha256 with WASM_SHA256 (exit 3 if it differs)
#
# Runs `cargo near build non-reproducible-wasm --locked` with `--remap-path-prefix` for the cargo
# home, the rustup home, the repository and the target directory, so panic messages in the wasm
# carry neutral paths (/cargo/registry/..., /replaycourt/...) instead of machine-specific ones.
# cargo-near takes RUSTFLAGS only through `--env` and appends `--cfg near` itself; the script
# therefore unsets RUSTFLAGS and CARGO_ENCODED_RUSTFLAGS (the latter would make cargo drop
# `--cfg near`).
#
# The build fails if `strings` finds /Users/, /home/ or the current user name in the wasm.
# Output: $CARGO_TARGET_DIR/near/replaycourt.wasm (default target/near/replaycourt.wasm).
# Needs: cargo-near 0.22.0, the toolchain pinned in rust-toolchain.toml, strings, sha256sum or shasum.

set -euo pipefail

MODE=write
case "${1:-}" in
  "") ;;
  --check) MODE=check ;;
  *) echo "usage: $0 [--check]" >&2; exit 64 ;;
esac

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/.." && pwd)
CARGO_HOME_DIR=${CARGO_HOME:-$HOME/.cargo}
RUSTUP_HOME_DIR=${RUSTUP_HOME:-$HOME/.rustup}
TARGET_DIR=${CARGO_TARGET_DIR:-$HERE/target}
mkdir -p "$TARGET_DIR"
TARGET_DIR=$(cd "$TARGET_DIR" && pwd)
OUT_DIR=$TARGET_DIR/near
WASM=$OUT_DIR/replaycourt.wasm

for p in "$CARGO_HOME_DIR" "$RUSTUP_HOME_DIR" "$REPO" "$TARGET_DIR"; do
  case "$p" in
    *" "*) echo "ERROR: path with a space ($p): RUSTFLAGS cannot carry it" >&2; exit 1 ;;
  esac
done

# rustc applies the last matching remapping, so the more specific prefixes come later
# (the target directory usually lies inside the repository).
FLAGS="-C link-arg=-s"
FLAGS="$FLAGS --remap-path-prefix=$REPO=/replaycourt"
FLAGS="$FLAGS --remap-path-prefix=$TARGET_DIR=/target"
FLAGS="$FLAGS --remap-path-prefix=$RUSTUP_HOME_DIR=/rustup"
FLAGS="$FLAGS --remap-path-prefix=$CARGO_HOME_DIR=/cargo"

unset RUSTFLAGS CARGO_ENCODED_RUSTFLAGS
cd "$HERE"
export CARGO_TARGET_DIR=$TARGET_DIR
cargo near build non-reproducible-wasm --locked --env "RUSTFLAGS=$FLAGS" --out-dir "$OUT_DIR" >&2

[ -f "$WASM" ] || { echo "ERROR: $WASM was not built" >&2; exit 1; }

# Privacy check: no machine-specific path or user name may remain in the wasm.
USER_NAME=${USER:-$(id -un)}
PATTERN='/Users/|/home/'
if [ -n "$USER_NAME" ]; then PATTERN="$PATTERN|$USER_NAME"; fi
LEAKS=$(strings -a "$WASM" | grep -E "$PATTERN" || true)
if [ -n "$LEAKS" ]; then
  echo "ERROR: the wasm contains machine-specific strings:" >&2
  printf '%s\n' "$LEAKS" | head -20 >&2
  exit 2
fi
echo "privacy check: no /Users/, /home/ or user name in $(basename "$WASM")" >&2

if command -v sha256sum >/dev/null 2>&1; then
  HASH=$(sha256sum "$WASM" | awk '{print $1}')
else
  HASH=$(shasum -a 256 "$WASM" | awk '{print $1}')
fi
echo "sha256 $HASH  $(basename "$WASM") ($(wc -c <"$WASM" | tr -d ' ') bytes)" >&2

if [ "$MODE" = write ]; then
  printf '%s\n' "$HASH" >"$HERE/WASM_SHA256"
  echo "wrote WASM_SHA256" >&2
else
  EXPECTED=$(tr -d '[:space:]' <"$HERE/WASM_SHA256")
  if [ "$HASH" != "$EXPECTED" ]; then
    echo "MISMATCH: WASM_SHA256 says $EXPECTED" >&2
    exit 3
  fi
  echo "matches WASM_SHA256" >&2
fi
echo "$WASM"
