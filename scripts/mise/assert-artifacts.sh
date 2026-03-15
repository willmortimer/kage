#!/usr/bin/env bash
set -euo pipefail

require_exec() {
  local p="$1"
  if [[ ! -x "$p" ]]; then
    echo "missing or not executable: $p" >&2
    exit 1
  fi
}

require_file() {
  local p="$1"
  if [[ ! -f "$p" ]]; then
    echo "missing file: $p" >&2
    exit 1
  fi
}

require_exec target/release/kage
require_exec target/release/kaged
require_exec target/release/age-plugin-kage

if [[ "$(uname)" == "Darwin" ]]; then
  require_exec target/release/KageHelper.app/Contents/MacOS/KageHelper
else
  require_file .mise-cache/build-mac.noop
fi

echo "ok"
