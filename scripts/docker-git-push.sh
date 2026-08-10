#!/usr/bin/env bash
# Git push smoke under kh (Linux aarch64 Docker / Colima).
#
# Proves: private bare remote (SSH-only, mode 0700), branch create/checkout,
# push -u, fast-forward push, merge + push main — all with Apple CLT git under kh.
#
# Clean-room: host OpenSSH bridge only (same as docker-git-ssh.sh); no freestanding
# SSH stack. Local bare repo — no GitHub account/token required.
#
# Usage:
#   ./scripts/docker-git-push.sh
#
# Env: same as docker-kh.sh git (KAKEHASHI_*, KH_EXTRA_CARGO_ARGS, image name).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

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

DOCKER_ENVS=()
for e in KAKEHASHI_XCODE_TOOLS_VERSION KAKEHASHI_FORCE_DOWNLOAD \
  KAKEHASHI_BOUNDARY_STATS KAKEHASHI_FUTEX_STATS KAKEHASHI_HEAP_STATS; do
  if [[ -n "${!e:-}" ]]; then
    DOCKER_ENVS+=(-e "${e}=${!e}")
  fi
done

echo "==> git push smoke (private bare + branches + push over SSH)"
echo "==> durable /out: ${KH_OUT}"

set +e
docker run --rm \
  -v "${ROOT}:/src" \
  -v kh-target-cache:/src/target \
  -v "${KH_OUT}:/out" \
  "${DOCKER_ENVS[@]+"${DOCKER_ENVS[@]}"}" \
  -w /src \
  -e KAKEHASHI_CONFIG_DIR=/src/.kh/config \
  -e KAKEHASHI_DATA_DIR=/src/.kh/data \
  -e CARGO_TARGET_DIR=/src/target \
  -e "KH_EXTRA_CARGO_ARGS=${KH_EXTRA_CARGO_ARGS}" \
  "${IMAGE}" \
  bash -c '
set -euo pipefail

need_pkg() {
  if ! command -v "$1" >/dev/null 2>&1; then
    return 0
  fi
  return 1
}
if need_pkg ssh || need_pkg sshd || need_pkg ssh-keygen; then
  echo "==> installing openssh-client/server (image missing packages)"
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
    openssh-client openssh-server >/dev/null
fi

cargo build -p kakehashi ${KH_EXTRA_CARGO_ARGS:-}
# Absolute path: subshells `cd` into the clone worktree.
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

# ── Private bare remote (host seed; SSH-only, mode 0700) ───────────────────
# No GitHub token: local bare + pubkey auth stands in for a private remote.
WORK=/tmp/kh-git-push-$$
rm -rf "$WORK"
mkdir -p "$WORK/ssh" "$WORK/bare" "$WORK/seed"

git -C "$WORK/seed" init -q -b main
printf "push-smoke-seed\n" >"$WORK/seed/README"
git -C "$WORK/seed" config user.email "kh@test.io"
git -C "$WORK/seed" config user.name "Vladislav"
git -C "$WORK/seed" add README
git -C "$WORK/seed" commit -q -m "seed"
git -C "$WORK/seed" clone --bare -q . "$WORK/bare/private.git"
chmod 700 "$WORK/bare" "$WORK/bare/private.git"
git -C "$WORK/bare/private.git" config receive.denyNonFastForwards false

HOST_KEY="$WORK/ssh/host_ed25519"
CLIENT_KEY="$WORK/ssh/id_ed25519"
ssh-keygen -t ed25519 -N "" -f "$HOST_KEY" -q
ssh-keygen -t ed25519 -N "" -f "$CLIENT_KEY" -q
mkdir -p /root/.ssh
chmod 700 /root/.ssh
cp "$CLIENT_KEY" /root/.ssh/id_ed25519
cp "${CLIENT_KEY}.pub" /root/.ssh/id_ed25519.pub
cat "${CLIENT_KEY}.pub" >/root/.ssh/authorized_keys
chmod 600 /root/.ssh/id_ed25519 /root/.ssh/authorized_keys

SSHD_CONFIG="$WORK/ssh/sshd_config"
cat >"$SSHD_CONFIG" <<EOF
Port 2222
ListenAddress 127.0.0.1
HostKey $HOST_KEY
PidFile $WORK/ssh/sshd.pid
AuthorizedKeysFile /root/.ssh/authorized_keys
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PermitRootLogin prohibit-password
StrictModes no
UsePAM no
Subsystem sftp internal-sftp
EOF
mkdir -p /run/sshd
/usr/sbin/sshd -f "$SSHD_CONFIG"
cleanup() {
  if [[ -f "$WORK/ssh/sshd.pid" ]]; then
    kill "$(cat "$WORK/ssh/sshd.pid")" 2>/dev/null || true
  fi
}
trap cleanup EXIT

KNOWN="$WORK/ssh/known_hosts"
ssh-keyscan -p 2222 -H 127.0.0.1 >"$KNOWN" 2>/dev/null
export GIT_SSH_COMMAND="ssh -i /root/.ssh/id_ed25519 -o IdentitiesOnly=yes -o UserKnownHostsFile=$KNOWN -o StrictHostKeyChecking=yes -o BatchMode=yes"

REMOTE="ssh://root@127.0.0.1:2222$WORK/bare/private.git"
CLONE=/Volumes/linux/out/push-smoke
rm -rf /out/push-smoke

echo "==> 1) clone private bare → $CLONE"
"$KH" run git -- clone --progress "$REMOTE" "$CLONE"
test -f /out/push-smoke/README

echo "==> 2) branch feature/push-test + commit"
(
  cd /out/push-smoke
  "$KH" run git -- checkout -b feature/push-test
  printf "branch-line\n" >> README
  "$KH" run git -- add README
  "$KH" run git -- commit -m "feature commit on branch"
  "$KH" run git -- branch -vv
  "$KH" run git -- log --oneline --all --decorate | head -20
)

echo "==> 3) push -u origin feature/push-test"
(
  cd /out/push-smoke
  set +e
  "$KH" run git -- push -u origin feature/push-test 2>&1 | tee /tmp/push-out.txt
  rc=${PIPESTATUS[0]}
  set -e
  echo "==> push exit=$rc"
  if [[ $rc -ne 0 ]]; then
    echo "==> PUSH FAILED; last 50 lines of output:"
    tail -50 /tmp/push-out.txt || true
    exit "$rc"
  fi
)

echo "==> 4) verify remote has feature branch"
(
  cd /out/push-smoke
  "$KH" run git -- ls-remote --heads origin
)
git -C "$WORK/bare/private.git" show-ref | grep -q "refs/heads/feature/push-test"
git -C "$WORK/bare/private.git" log --oneline --all | head -10

echo "==> 5) second commit + push (fast-forward)"
(
  cd /out/push-smoke
  printf "second\n" >> README
  "$KH" run git -- add README
  "$KH" run git -- commit -m "second on feature"
  "$KH" run git -- push origin feature/push-test
)

echo "==> 6) checkout main, merge, push main"
(
  cd /out/push-smoke
  "$KH" run git -- checkout main
  "$KH" run git -- merge --ff-only feature/push-test
  "$KH" run git -- push origin main
)

echo "==> 7) remote main tip"
git -C "$WORK/bare/private.git" log --oneline main | head -5
git -C "$WORK/bare/private.git" show-ref | grep -E "refs/heads/(main|feature/push-test)"

echo "==> PUSH SMOKE OK (private bare + branches + push)"
'
rc=$?
set -e
exit "$rc"
