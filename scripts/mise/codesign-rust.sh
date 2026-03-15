#!/usr/bin/env bash
set -euo pipefail

load_dotenv() {
  local f="$1"
  if [[ -f "$f" ]]; then
    set -a
    # shellcheck disable=SC1090
    source "$f"
    set +a
  fi
}

load_dotenv ".env"
load_dotenv ".env.local"

if [[ "$(uname)" != "Darwin" ]]; then
  echo "codesign is macOS-only" >&2
  exit 0
fi

: "${KAGE_CODESIGN_IDENTITY:?set KAGE_CODESIGN_IDENTITY in .env.local (see .env.example)}"
: "${KAGE_CODESIGN_TIMESTAMP:=0}"

echo "Using codesign identity: ${KAGE_CODESIGN_IDENTITY}" >&2

bins=(
  "target/release/kage"
  "target/release/age-plugin-kage"
  "target/release/kaged"
)

expected_team="${KAGE_DEVELOPMENT_TEAM:-}"

timestamp_flag="--timestamp=none"
if [[ "${KAGE_CODESIGN_TIMESTAMP}" == "1" ]]; then
  timestamp_flag="--timestamp"
fi

for b in "${bins[@]}"; do
  if [[ ! -x "$b" ]]; then
    echo "missing binary: $b (run: mise run build-rust)" >&2
    exit 1
  fi
  codesign --force "${timestamp_flag}" --options runtime --sign "$KAGE_CODESIGN_IDENTITY" "$b"
done

fail=0
for b in "${bins[@]}"; do
  echo "$b:"
  team="$(codesign -dv --verbose=4 "$b" 2>&1 | sed -n 's/^TeamIdentifier=//p' | head -n 1 || true)"
  codesign -dv --verbose=4 "$b" 2>&1 | grep -E "Identifier=|TeamIdentifier=" || true
  if [[ -n "$expected_team" && -n "$team" && "$team" != "$expected_team" ]]; then
    echo "ERROR: $b TeamIdentifier mismatch (expected=$expected_team got=$team)." >&2
    echo "Tip: set KAGE_CODESIGN_IDENTITY to the SHA-1 from: security find-identity -v -p codesigning" >&2
    fail=1
  fi
done

exit "$fail"
