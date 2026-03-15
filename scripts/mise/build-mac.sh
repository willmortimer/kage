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

mkdir -p .mise-cache

: "${KAGE_MAC_BUILD_VARIANT:=}"
: "${KAGE_MACOS_DEPLOYMENT_TARGET:=26.0}"

signed_stamp=".mise-cache/build-mac.signed"
unsigned_stamp=".mise-cache/build-mac.unsigned"

rm -f "${signed_stamp}" "${unsigned_stamp}"

variant_stamp() {
  case "${KAGE_MAC_BUILD_VARIANT}" in
    signed) echo "${signed_stamp}" ;;
    unsigned) echo "${unsigned_stamp}" ;;
    *)
      if [[ "${KAGE_CODESIGN:-auto}" == "0" ]]; then
        echo "${unsigned_stamp}"
      else
        echo "${signed_stamp}"
      fi
      ;;
  esac
}

if [[ "$(uname)" != "Darwin" ]]; then
  echo "not-darwin" > .mise-cache/build-mac.noop
  mkdir -p target/release/KageHelper.app/Contents/MacOS
  cat > target/release/KageHelper.app/Contents/MacOS/KageHelper <<'EOF'
KageHelper.app is only built on macOS.
EOF
  echo "noop" > "$(variant_stamp)"
  echo "Skipping macOS helper build (not Darwin)"
  exit 0
fi

arch="$(uname -m)"
if [[ "${arch}" != "arm64" ]]; then
  echo "error: KageHelper.app targets Apple silicon (arm64) only (got ${arch})" >&2
  exit 1
fi

echo "darwin" > .mise-cache/build-mac.noop

: "${KAGE_CODESIGN:=auto}"
if [[ "${KAGE_MAC_BUILD_VARIANT}" == "unsigned" ]]; then
  KAGE_CODESIGN=0
fi
if [[ "${KAGE_CODESIGN}" == "auto" ]]; then
  if [[ -n "${KAGE_DEVELOPMENT_TEAM:-}" ]]; then
    KAGE_CODESIGN=1
  else
    KAGE_CODESIGN=0
  fi
fi

: "${KAGE_XCODE_ALLOW_PROVISIONING_UPDATES:=1}"
: "${KAGE_XCODE_CODE_SIGN_STYLE:=}"
: "${KAGE_XCODE_CODE_SIGN_IDENTITY:=}"
: "${KAGE_XCODE_PROVISIONING_PROFILE_SPECIFIER:=}"
: "${KAGE_XCODE_PROVISIONING_PROFILE:=}"

# Ensure the Rust static library uses the same deployment target as the Xcode build,
# otherwise the link step can warn about version mismatches.
MACOSX_DEPLOYMENT_TARGET="${KAGE_MACOS_DEPLOYMENT_TARGET}" cargo build -p kage-comm --features ffi --release
mkdir -p target/release

XCODE_ARGS=(
  -destination "platform=macOS,arch=arm64"
  -project kage-mac-helper/KageHelper/KageHelper.xcodeproj
  -scheme KageHelper
  -configuration Release
  -derivedDataPath kage-mac-helper/.xcodebuild
  "MACOSX_DEPLOYMENT_TARGET=${KAGE_MACOS_DEPLOYMENT_TARGET}"
  "LIBRARY_SEARCH_PATHS=$(pwd)/target/release"
  "OTHER_LDFLAGS=-lkage_comm"
  "ARCHS=arm64"
)

if [[ "$KAGE_CODESIGN" == "0" ]]; then
  XCODE_ARGS+=(CODE_SIGNING_ALLOWED=NO "CODE_SIGN_IDENTITY=")
elif [[ -n "${KAGE_DEVELOPMENT_TEAM:-}" ]]; then
  XCODE_ARGS+=("DEVELOPMENT_TEAM=${KAGE_DEVELOPMENT_TEAM}")
  if [[ -n "${KAGE_XCODE_CODE_SIGN_STYLE}" ]]; then
    XCODE_ARGS+=("CODE_SIGN_STYLE=${KAGE_XCODE_CODE_SIGN_STYLE}")
  fi
  if [[ -n "${KAGE_XCODE_CODE_SIGN_IDENTITY}" ]]; then
    XCODE_ARGS+=("CODE_SIGN_IDENTITY=${KAGE_XCODE_CODE_SIGN_IDENTITY}")
  fi
  if [[ "${KAGE_XCODE_CODE_SIGN_STYLE}" == "Manual" ]]; then
    XCODE_ARGS+=(
      "PROVISIONING_PROFILE_SPECIFIER=${KAGE_XCODE_PROVISIONING_PROFILE_SPECIFIER}"
      "PROVISIONING_PROFILE=${KAGE_XCODE_PROVISIONING_PROFILE}"
    )
  fi
  if [[ "${KAGE_XCODE_ALLOW_PROVISIONING_UPDATES}" == "1" ]]; then
    XCODE_ARGS+=(-allowProvisioningUpdates -allowProvisioningDeviceRegistration)
  fi
fi

if [[ -n "${KAGE_BUNDLE_IDENTIFIER:-}" ]]; then
  XCODE_ARGS+=("PRODUCT_BUNDLE_IDENTIFIER=${KAGE_BUNDLE_IDENTIFIER}")
fi

xcodebuild "${XCODE_ARGS[@]}"

rm -rf target/release/KageHelper.app
rm -f target/release/kage-mac-helper
cp -R kage-mac-helper/.xcodebuild/Build/Products/Release/KageHelper.app target/release/

app_team="$(codesign -dv --verbose=4 target/release/KageHelper.app 2>&1 | sed -n 's/^TeamIdentifier=//p' | head -n 1 || true)"
printf '%s\n' "${app_team:-not set}" > "$(variant_stamp)"
