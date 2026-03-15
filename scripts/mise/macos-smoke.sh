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
  echo "macos-smoke: skipping (not Darwin)"
  exit 0
fi

: "${KAGE_SMOKE_SIGNED:=0}"
: "${KAGE_SMOKE_ENV:=}"
: "${KAGE_SMOKE_UNLOCK_SECONDS:=60}"

cleanup() {
  if [[ -n "${TMP_FILE:-}" ]]; then
    rm -f "${TMP_FILE}"
  fi
  if [[ -n "${tmp_kage:-}" ]]; then
    rm -f "${tmp_kage}"
  fi
}
trap cleanup EXIT

if [[ "${KAGE_SMOKE_SIGNED}" == "1" ]]; then
  : "${KAGE_DEVELOPMENT_TEAM:?set KAGE_DEVELOPMENT_TEAM in .env.local (see .env.example)}"
  : "${KAGE_CODESIGN_IDENTITY:?set KAGE_CODESIGN_IDENTITY in .env.local (see .env.example)}"
fi

APP_SRC="target/release/KageHelper.app"
APP_DST="/Applications/KageHelper.app"
PLIST_SRC="kage-mac-helper/LaunchAgents/com.kage.daemon.plist"
PLIST_DST="${HOME}/Library/LaunchAgents/com.kage.daemon.plist"
JOB="gui/$(id -u)/com.kage.daemon"

if [[ ! -d "${APP_SRC}" ]]; then
  echo "missing ${APP_SRC} (run: mise run build-mac)" >&2
  exit 1
fi

mkdir -p "${HOME}/Library/LaunchAgents"
cp "${PLIST_SRC}" "${PLIST_DST}"

if [[ -n "${KAGE_V2_DIR:-}" ]]; then
  launchctl setenv KAGE_V2_DIR "${KAGE_V2_DIR}"
else
  launchctl unsetenv KAGE_V2_DIR 2>/dev/null || true
fi

if [[ "${KAGE_SMOKE_SIGNED}" == "1" ]]; then
  launchctl unsetenv KAGE_LOCAL_DEV 2>/dev/null || true
else
  launchctl setenv KAGE_LOCAL_DEV 1
fi

echo "Installing ${APP_SRC} -> ${APP_DST} (requires sudo)..." >&2
sudo rm -rf "${APP_DST}"
sudo cp -R "${APP_SRC}" "${APP_DST}"

if [[ "${KAGE_SMOKE_SIGNED}" == "1" ]]; then
  app_team="$(codesign -dv --verbose=4 "${APP_DST}" 2>&1 | sed -n 's/^TeamIdentifier=//p' | head -n 1 || true)"
  if [[ -z "${app_team}" ]]; then
    echo "Smoke(signed): helper app has no TeamIdentifier (is it signed?)" >&2
    exit 1
  fi
  if [[ "${app_team}" != "${KAGE_DEVELOPMENT_TEAM}" ]]; then
    echo "Smoke(signed): helper TeamIdentifier mismatch (expected=${KAGE_DEVELOPMENT_TEAM} got=${app_team})" >&2
    exit 1
  fi
fi

echo "Starting LaunchAgent ${JOB}..." >&2
launchctl bootstrap "gui/$(id -u)" "${PLIST_DST}" 2>/dev/null || true
launchctl kickstart -k "${JOB}"

echo "Smoke: kage doctor" >&2
./target/release/kage doctor

V2_DIR="${KAGE_V2_DIR:-${HOME}/.kage/v2}"
CONFIG_PATH="${V2_DIR}/config.toml"

if [[ ! -f "${CONFIG_PATH}" ]]; then
  echo "Smoke: missing config at ${CONFIG_PATH}" >&2
  echo "Run: ./target/release/kage setup --org <org> --env <env> --1p-vault <vault>" >&2
  exit 1
fi

if [[ -z "${KAGE_SMOKE_ENV}" ]]; then
  if ./target/release/kage list | awk '$1=="prod"{found=1} END{exit !found}' >/dev/null 2>&1; then
    KAGE_SMOKE_ENV="prod"
  else
    KAGE_SMOKE_ENV="$("./target/release/kage" list | awk 'NR==1 {print $1}')"
  fi
fi

RECIPIENT="$("./target/release/kage" list | awk -v env="${KAGE_SMOKE_ENV}" '$1==env {print $2; exit}')"
POLICY="$("./target/release/kage" list | awk -v env="${KAGE_SMOKE_ENV}" '$1==env {print $3; exit}')"
if [[ -z "${RECIPIENT}" ]]; then
  echo "Smoke: no recipient found for env=${KAGE_SMOKE_ENV} (did you run kage setup?)" >&2
  exit 1
fi

export PATH="${PWD}/target/release:${PATH}"
export SOPS_AGE_KEY_CMD="${PWD}/target/release/kage identity"

if [[ "${KAGE_SMOKE_SIGNED}" == "1" ]]; then
  # Signed-mode contract: unsigned clients must be rejected.
  tmp_kage="$(mktemp -t kage-unsigned.XXXXXX)"
  cp ./target/release/kage "${tmp_kage}"
  codesign --remove-signature "${tmp_kage}" 2>/dev/null || true
  if "${tmp_kage}" doctor >/dev/null 2>&1; then
    echo "Smoke(signed): expected unsigned client to be rejected, but it succeeded" >&2
    exit 1
  fi
fi

TMP_FILE="$(mktemp -t kage-sops.XXXXXX)"

if [[ "${POLICY}" == "strong" ]]; then
  echo "Smoke: kage unlock env=${KAGE_SMOKE_ENV} for ${KAGE_SMOKE_UNLOCK_SECONDS}s" >&2
  ./target/release/kage unlock --env "${KAGE_SMOKE_ENV}" --duration "${KAGE_SMOKE_UNLOCK_SECONDS}"
fi

echo "Smoke: sops encrypt/decrypt env=${KAGE_SMOKE_ENV} recipient=${RECIPIENT} policy=${POLICY}" >&2
printf "secret\n" | sops -e --age "${RECIPIENT}" /dev/stdin > "${TMP_FILE}"
sops -d "${TMP_FILE}"
