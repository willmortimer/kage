#!/usr/bin/env bash
set -euo pipefail

die() { echo "error: $*" >&2; exit 1; }

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

version="${KAGE_VERSION:-}"
if [[ -z "${version}" ]]; then
  if git describe --tags --exact-match >/dev/null 2>&1; then
    version="$(git describe --tags --exact-match)"
  else
    version="dev-$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
  fi
fi
version="${version#v}"

os="$(uname -s)"
case "${os}" in
  Darwin) os="macos" ;;
  Linux) os="linux" ;;
  *) os="$(echo "${os}" | tr '[:upper:]' '[:lower:]')" ;;
esac

arch="$(uname -m)"
case "${arch}" in
  x86_64|amd64) arch="x86_64" ;;
  arm64|aarch64) arch="arm64" ;;
esac

dist_dir="dist"
mkdir -p "${dist_dir}"

require_exec() { [[ -x "$1" ]] || die "missing or not executable: $1 (run: mise run build-rust)"; }

require_exec "target/release/kage"
require_exec "target/release/age-plugin-kage"
require_exec "target/release/kaged"

if [[ "${os}" == "macos" && "${arch}" != "arm64" ]]; then
  die "macOS x86_64 is not supported (Apple silicon only)"
fi

assert_arm64_only() {
  local p="$1"
  if command -v lipo >/dev/null 2>&1; then
    local info
    info="$(lipo -info "${p}" 2>&1 || true)"
    if echo "${info}" | grep -q 'x86_64'; then
      die "unexpected x86_64 slice in ${p}: ${info}"
    fi
    if ! echo "${info}" | grep -q 'arm64'; then
      die "expected arm64 binary ${p}, got: ${info}"
    fi
  elif command -v file >/dev/null 2>&1; then
    local info
    info="$(file "${p}" 2>&1 || true)"
    if echo "${info}" | grep -q 'x86_64'; then
      die "unexpected x86_64 slice in ${p}: ${info}"
    fi
    if ! echo "${info}" | grep -q 'arm64'; then
      die "expected arm64 binary ${p}, got: ${info}"
    fi
  fi
}

if [[ "${os}" == "macos" ]]; then
  assert_arm64_only "target/release/kage"
  assert_arm64_only "target/release/age-plugin-kage"
  assert_arm64_only "target/release/kaged"
  if [[ -x "target/release/KageHelper.app/Contents/MacOS/KageHelper" ]]; then
    assert_arm64_only "target/release/KageHelper.app/Contents/MacOS/KageHelper"
  fi
fi

tmpdir="$(mktemp -d -t kage-dist.XXXXXX)"
cleanup() { rm -rf "${tmpdir}"; }
trap cleanup EXIT

tar_name="kage-${version}-${os}-${arch}.tar.gz"
tar_path="${dist_dir}/${tar_name}"

cp target/release/kage "${tmpdir}/kage"
cp target/release/age-plugin-kage "${tmpdir}/age-plugin-kage"
cp target/release/kaged "${tmpdir}/kaged"

tar -C "${tmpdir}" -czf "${tar_path}" kage age-plugin-kage kaged
echo "wrote ${tar_path}" >&2

if [[ "${os}" == "macos" ]]; then
  app_src="target/release/KageHelper.app"
  plist_src="kage-mac-helper/LaunchAgents/com.kage.daemon.plist"
  if [[ -d "${app_src}" && -f "${plist_src}" ]]; then
    helper_name="kagehelper-${version}-${os}-${arch}.zip"
    helper_path="${dist_dir}/${helper_name}"

    stage="${tmpdir}/kagehelper"
    mkdir -p "${stage}"
    cp -R "${app_src}" "${stage}/KageHelper.app"
    cp "${plist_src}" "${stage}/com.kage.daemon.plist"

    # Zip layout is root-level `KageHelper.app` + `com.kage.daemon.plist` to match Homebrew cask expectations.
    ditto -c -k --sequesterRsrc "${stage}" "${helper_path}"
    echo "wrote ${helper_path}" >&2
  else
    echo "warning: skipping helper package (missing ${app_src} or ${plist_src})" >&2
  fi
fi

checksum_file="${dist_dir}/SHA256SUMS-${os}-${arch}.txt"
rm -f "${checksum_file}"

files=()
while IFS= read -r -d '' f; do files+=("$f"); done < <(find "${dist_dir}" -maxdepth 1 -type f ! -name 'SHA256SUMS-*.txt' -print0)
if [[ "${#files[@]}" -eq 0 ]]; then
  die "no dist files found to checksum"
fi

pushd "${dist_dir}" >/dev/null
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "${files[@]##${dist_dir}/}" > "$(basename "${checksum_file}")"
else
  shasum -a 256 "${files[@]##${dist_dir}/}" > "$(basename "${checksum_file}")"
fi
popd >/dev/null

echo "wrote ${checksum_file}" >&2
