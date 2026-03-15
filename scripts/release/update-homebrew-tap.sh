#!/usr/bin/env bash
set -euo pipefail

die() { echo "error: $*" >&2; exit 1; }

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

: "${HOMEBREW_TAP_TOKEN:?set HOMEBREW_TAP_TOKEN (PAT with write access to the tap repo)}"
: "${HOMEBREW_TAP_REPO:?set HOMEBREW_TAP_REPO (e.g. willmortimer/homebrew-kage)}"

tap_branch="${HOMEBREW_TAP_BRANCH:-main}"

tag="${KAGE_VERSION:-${GITHUB_REF_NAME:-}}"
[[ -n "${tag}" ]] || die "set KAGE_VERSION (e.g. v2.0.0)"
version="${tag#v}"

dist_dir="${repo_root}/dist"
[[ -d "${dist_dir}" ]] || die "missing dist/ (run release workflow or scripts/release/package.sh)"

want_macos_tar="kage-${version}-macos-arm64.tar.gz"
want_linux_tar="kage-${version}-linux-x86_64.tar.gz"
want_helper_zip="kagehelper-${version}-macos-arm64.zip"

sha_for() {
  local fname="$1"
  local sha
  local sum_files=()
  if [[ -f "${dist_dir}/SHA256SUMS.txt" ]]; then
    sum_files+=("${dist_dir}/SHA256SUMS.txt")
  else
    sum_files+=("${dist_dir}"/SHA256SUMS-*.txt)
  fi
  sha="$(awk -v f="${fname}" '$2==f {print $1; exit}' "${sum_files[@]}" 2>/dev/null || true)"
  [[ -n "${sha}" ]] || die "missing checksum entry for ${fname} (expected in dist/SHA256SUMS*.txt)"
  echo "${sha}"
}

sha_macos="$(sha_for "${want_macos_tar}")"
sha_linux="$(sha_for "${want_linux_tar}")"
sha_helper="$(sha_for "${want_helper_zip}")"

tmpdir="$(mktemp -d -t kage-tap.XXXXXX)"
cleanup() { rm -rf "${tmpdir}"; }
trap cleanup EXIT

git clone --depth 1 --branch "${tap_branch}" "https://github.com/${HOMEBREW_TAP_REPO}.git" "${tmpdir}/tap" >/dev/null 2>&1 \
  || die "failed to clone tap repo https://github.com/${HOMEBREW_TAP_REPO}.git"

mkdir -p "${tmpdir}/tap/Formula" "${tmpdir}/tap/Casks"
cp "${repo_root}/Formula/kage.rb" "${tmpdir}/tap/Formula/kage.rb"
cp "${repo_root}/Casks/kage-helper.rb" "${tmpdir}/tap/Casks/kage-helper.rb"

KAGE_TAP_VERSION="${version}" \
KAGE_TAP_SHA_MACOS="${sha_macos}" \
KAGE_TAP_SHA_LINUX="${sha_linux}" \
KAGE_TAP_SHA_HELPER="${sha_helper}" \
KAGE_TAP_FORMULA_PATH="${tmpdir}/tap/Formula/kage.rb" \
KAGE_TAP_CASK_PATH="${tmpdir}/tap/Casks/kage-helper.rb" \
python3 - <<'PY'
import os
import pathlib
import re

version = os.environ["KAGE_TAP_VERSION"]
sha_macos = os.environ["KAGE_TAP_SHA_MACOS"]
sha_linux = os.environ["KAGE_TAP_SHA_LINUX"]
sha_helper = os.environ["KAGE_TAP_SHA_HELPER"]

formula = pathlib.Path(os.environ["KAGE_TAP_FORMULA_PATH"])
cask = pathlib.Path(os.environ["KAGE_TAP_CASK_PATH"])


def replace_file(path: pathlib.Path, replacements: list[tuple[re.Pattern, str]]):
    text = path.read_text(encoding="utf-8")
    for pat, repl in replacements:
        new_text, n = pat.subn(repl, text, count=1)
        if n != 1:
            raise SystemExit(f"patch failed for {path} pattern={pat.pattern!r} matches={n}")
        text = new_text
    path.write_text(text, encoding="utf-8")


replace_file(
    formula,
    [
        (re.compile(r'version\s+"[^"]+"'), f'version "{version}"'),
        (
            re.compile(
                r'(url\s+"[^"]*kage-#\{version\}-macos-arm64\.tar\.gz"\s*\n\s*sha256\s+)"[^"]+"'
            ),
            f'\\1"{sha_macos}"',
        ),
        (
            re.compile(
                r'(url\s+"[^"]*kage-#\{version\}-linux-x86_64\.tar\.gz"\s*\n\s*sha256\s+)"[^"]+"'
            ),
            f'\\1"{sha_linux}"',
        ),
    ],
)

replace_file(
    cask,
    [
        (re.compile(r'version\s+"[^"]+"'), f'version "{version}"'),
        (re.compile(r'sha256\s+"[^"]+"'), f'sha256 "{sha_helper}"'),
    ],
)
PY

pushd "${tmpdir}/tap" >/dev/null

if [[ -z "$(git status --porcelain)" ]]; then
  echo "tap: no changes to commit" >&2
  exit 0
fi

git config user.email "github-actions[bot]@users.noreply.github.com"
git config user.name "github-actions[bot]"

git add Formula/kage.rb Casks/kage-helper.rb
git commit -m "kage ${version}" >/dev/null

git remote set-url origin "https://x-access-token:${HOMEBREW_TAP_TOKEN}@github.com/${HOMEBREW_TAP_REPO}.git"
git push origin "HEAD:${tap_branch}" >/dev/null

echo "tap: updated ${HOMEBREW_TAP_REPO}@${tap_branch} to ${version}" >&2

popd >/dev/null
