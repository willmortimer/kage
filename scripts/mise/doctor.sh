#!/usr/bin/env bash
set -euo pipefail

say() { printf '%s\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

say "mise: $(mise -v 2>/dev/null || echo 'missing')"

for tool in rustc cargo; do
  if have "$tool"; then
    say "$tool: $("$tool" -V)"
  else
    say "$tool: missing"
    exit 1
  fi
done

if have sops; then
  say "sops: $(sops --version | head -n 1)"
else
  say "sops: missing (run: mise install)"
  exit 1
fi

if have age; then
  say "age: $(age --version | head -n 1)"
else
  say "age: missing (run: mise install)"
  exit 1
fi

if [[ "$(uname)" == "Darwin" ]]; then
  if have xcodebuild; then
    say "xcodebuild:"
    xcodebuild -version
  else
    say "xcodebuild: missing (install Xcode)"
    exit 1
  fi
fi

if ! have op; then
  say "op: missing (required for kage setup)"
fi

say "ok"
