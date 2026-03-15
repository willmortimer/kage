#!/usr/bin/env bash
set -euo pipefail

die() { echo "error: $*" >&2; exit 1; }

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "notarize-macos: skipping (not Darwin)" >&2
  exit 0
fi

: "${AC_NOTARY_KEY_ID:?set AC_NOTARY_KEY_ID (App Store Connect API key id)}"
: "${AC_NOTARY_ISSUER_ID:?set AC_NOTARY_ISSUER_ID (App Store Connect issuer id)}"
: "${AC_NOTARY_PRIVATE_KEY_BASE64:?set AC_NOTARY_PRIVATE_KEY_BASE64 (base64 .p8)}"

app_path="target/release/KageHelper.app"
[[ -d "${app_path}" ]] || die "missing ${app_path} (run: mise run build-mac)"

authority="$(codesign -dv --verbose=4 "${app_path}" 2>&1 | sed -n 's/^Authority=//p' | head -n 1 || true)"
team="$(codesign -dv --verbose=4 "${app_path}" 2>&1 | sed -n 's/^TeamIdentifier=//p' | head -n 1 || true)"
if [[ -z "${team}" ]]; then
  die "helper app has no TeamIdentifier (is it signed?)"
fi
if ! codesign -dv --verbose=4 "${app_path}" 2>&1 | grep -q '^Authority=Developer ID Application'; then
  die "helper app is not signed with Developer ID Application (first authority: ${authority:-unknown})"
fi

tmpdir="$(mktemp -d -t kage-notary.XXXXXX)"
cleanup() { rm -rf "${tmpdir}"; }
trap cleanup EXIT

key_path="${tmpdir}/AuthKey.p8"
python3 - <<PY
import base64, os, pathlib
path = pathlib.Path("${key_path}")
path.write_bytes(base64.b64decode(os.environ["AC_NOTARY_PRIVATE_KEY_BASE64"]))
PY
chmod 600 "${key_path}"

zip_path="${tmpdir}/KageHelper.notary.zip"
ditto -c -k --sequesterRsrc --keepParent "${app_path}" "${zip_path}"

echo "notarize: submitting ${zip_path}" >&2
xcrun notarytool submit "${zip_path}" \
  --key "${key_path}" \
  --key-id "${AC_NOTARY_KEY_ID}" \
  --issuer "${AC_NOTARY_ISSUER_ID}" \
  --wait

echo "notarize: stapling ${app_path}" >&2
xcrun stapler staple "${app_path}"
xcrun stapler validate "${app_path}" || true

echo "notarize: ok" >&2
