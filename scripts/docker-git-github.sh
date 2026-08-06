#!/usr/bin/env bash
# Authenticated GitHub smoke under kh (Linux aarch64 Docker / Colima).
#
# Requires on the **host** (not inside the image):
#   - OpenSSH key that GitHub accepts (mounted → /root/.ssh)
#   - `gh` CLI logged in with `repo` scope (creates a throwaway private repo)
#
# Flow:
#   1) host gh ensures a private repo exists (create or reuse)
#   2) Docker: force-push seed over SSH (git@github.com:…)
#   3) Docker: ls-remote / clone private over HTTPS with token userinfo
#   4) optional host delete if token has `delete_repo` scope
#
# Clean-room: host OpenSSH + freestanding HTTPS Basic from URL userinfo.
# Tokens are passed via env; never echoed.
#
# Usage:
#   ./scripts/docker-git-github.sh
#
# Env:
#   KH_GITHUB_OWNER     default: gh api user -q .login
#   KH_GITHUB_REPO      default: kh-kakehashi-smoke (reused; force-push)
#   KH_DELETE_REPO=1    try to delete private repo after smoke (needs delete_repo)
#   (+ same as docker-git.sh: KAKEHASHI_*, KH_EXTRA_CARGO_ARGS, image)

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if ! command -v gh >/dev/null 2>&1; then
  echo "error: host needs GitHub CLI (gh) with repo scope" >&2
  exit 1
fi
if ! gh auth status >/dev/null 2>&1; then
  echo "error: gh not authenticated (gh auth login)" >&2
  exit 1
fi
if [[ ! -d "${HOME}/.ssh" ]]; then
  echo "error: need ~/.ssh with a key registered on GitHub" >&2
  exit 1
fi

OWNER="${KH_GITHUB_OWNER:-$(gh api user -q .login)}"
# Fixed default name: reuse + force-push (avoids needing delete_repo scope).
REPO_NAME="${KH_GITHUB_REPO:-kh-kakehashi-smoke}"
FULL="${OWNER}/${REPO_NAME}"
TOKEN="$(gh auth token)"
if [[ -z "$TOKEN" ]]; then
  echo "error: empty gh auth token" >&2
  exit 1
fi

IMAGE="${KAKEHASHI_SMOKE_IMAGE:-kakehashi:dev}"
KH_OUT="${KH_OUT:-$ROOT/.tmp/kh-out}"
if [ "${KH_EXTRA_CARGO_ARGS+set}" != "set" ]; then
  KH_EXTRA_CARGO_ARGS=--release
fi

mkdir -p "$KH_OUT" "$ROOT/.kh"

if [[ -f target/aarch64-apple-darwin/release/libkh_libsystem.dylib ]] \
  || [[ -f target/release/libkh_libsystem.dylib ]]; then
  ./scripts/stage-libsystem.sh
elif [[ -f crates/kh-runtime/resources/libSystem.B.dylib ]]; then
  echo "note: using crates/kh-runtime/resources/libSystem.B.dylib"
else
  echo "error: no guest libSystem (need resources/ embed or a built dylib)." >&2
  exit 1
fi

if ! docker image inspect "${IMAGE}" >/dev/null 2>&1; then
  echo "==> docker build ${IMAGE}"
  docker build -t "${IMAGE}" -f Dockerfile.dev .
fi

if gh repo view "${FULL}" >/dev/null 2>&1; then
  echo "==> reuse private repo ${FULL}"
else
  echo "==> create private repo ${FULL} (host gh)"
  gh repo create "${FULL}" --private --description "kakehashi docker auth smoke (reused)" >/dev/null
fi

cleanup_repo() {
  if [[ "${KH_DELETE_REPO:-}" != "1" ]]; then
    echo "note: leaving ${FULL} (set KH_DELETE_REPO=1 + delete_repo scope to remove)"
    return
  fi
  echo "==> delete private repo ${FULL}"
  if ! gh repo delete "${FULL}" --yes 2>/tmp/kh-gh-del.err; then
    echo "warn: delete failed (need: gh auth refresh -h github.com -s delete_repo)" >&2
    tail -3 /tmp/kh-gh-del.err 2>/dev/null || true
  fi
}
trap cleanup_repo EXIT

echo "==> GitHub auth smoke (SSH push + HTTPS private ls-remote/clone)"
echo "==> durable /out: ${KH_OUT}"

set +e
docker run --rm \
  -v "${ROOT}:/src" \
  -v kh-target-cache:/src/target \
  -v "${KH_OUT}:/out" \
  -v "${HOME}/.ssh:/root/.ssh:ro" \
  -w /src \
  -e KAKEHASHI_CONFIG_DIR=/src/.kh/config \
  -e KAKEHASHI_DATA_DIR=/src/.kh/data \
  -e CARGO_TARGET_DIR=/src/target \
  -e "KH_EXTRA_CARGO_ARGS=${KH_EXTRA_CARGO_ARGS}" \
  -e "KH_GH_OWNER=${OWNER}" \
  -e "KH_GH_REPO=${REPO_NAME}" \
  -e "KH_GH_TOKEN=${TOKEN}" \
  "${IMAGE}" \
  bash -c '
set -euo pipefail

if ! command -v ssh >/dev/null 2>&1; then
  echo "error: openssh-client missing in image" >&2
  exit 1
fi

# Host ~/.ssh is bind-mounted ro (keys). Never chmod the mount; use a
# writable known_hosts for github.com host keys under BatchMode.
KNOWN=/tmp/kh-github-known_hosts
ssh-keyscan -t ed25519,rsa,ecdsa github.com >"$KNOWN" 2>/dev/null
export GIT_SSH_COMMAND="ssh -o UserKnownHostsFile=$KNOWN -o StrictHostKeyChecking=yes -o BatchMode=yes -o IdentitiesOnly=yes"

cargo build -p kakehashi ${KH_EXTRA_CARGO_ARGS:-}
if [[ "${KH_EXTRA_CARGO_ARGS:-}" == *"--release"* ]]; then
  KH=/src/target/release/kh
else
  KH=/src/target/debug/kh
fi
"$KH" bottle ensure
"$KH" install xcode-tools

"$KH" run git -- config --global user.email "kh@test.io"
"$KH" run git -- config --global user.name "Vladislav"
"$KH" run git -- config --global protocol.version 2
"$KH" run git -- config --global init.defaultBranch main
# Host ~/.gitconfig may set credential.helper=osxkeychain (missing under Linux).
"$KH" run git -- config --global --unset-all credential.helper 2>/dev/null || true
"$KH" run git -- config --global credential.helper ""

SSH_REMOTE="git@github.com:${KH_GH_OWNER}/${KH_GH_REPO}.git"
# userinfo Basic for freestanding path B (token never printed)
HTTPS_REMOTE="https://x-access-token:${KH_GH_TOKEN}@github.com/${KH_GH_OWNER}/${KH_GH_REPO}.git"
HTTPS_SAFE="https://github.com/${KH_GH_OWNER}/${KH_GH_REPO}.git"

echo "==> 1) SSH: init + push private ${SSH_REMOTE}"
rm -rf /out/gh-ssh-push
mkdir -p /out/gh-ssh-push
(
  cd /out/gh-ssh-push
  "$KH" run git -- init -b main
  printf "github-auth-smoke\n" > README
  "$KH" run git -- add README
  "$KH" run git -- commit -m "kh github smoke"
  "$KH" run git -- remote add origin "$SSH_REMOTE"
  # Force: smoke reuses a fixed private repo name across runs.
  "$KH" run git -- push -u --force origin main
)

echo "==> 2) SSH: ls-remote private"
"$KH" run git -- ls-remote "$SSH_REMOTE" | tee /tmp/gh-ssh-ls.txt
grep -q refs/heads/main /tmp/gh-ssh-ls.txt

echo "==> 3) HTTPS: ls-remote private (Basic userinfo)"
"$KH" run git -- ls-remote "$HTTPS_REMOTE" | tee /tmp/gh-https-ls.txt
grep -q refs/heads/main /tmp/gh-https-ls.txt

echo "==> 4) HTTPS: clone private → /Volumes/linux/out/gh-https-clone"
rm -rf /out/gh-https-clone
"$KH" run git -- clone --progress "$HTTPS_REMOTE" /Volumes/linux/out/gh-https-clone
test -f /out/gh-https-clone/README
grep -q github-auth-smoke /out/gh-https-clone/README

echo "==> GITHUB AUTH SMOKE OK"
echo "    private remote (safe): ${HTTPS_SAFE}"
'
rc=$?
set -e
if [[ $rc -ne 0 ]]; then
  echo "error: github auth smoke failed (rc=$rc)" >&2
  exit "$rc"
fi
echo "==> host cleanup via trap"
exit 0
