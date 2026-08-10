#!/usr/bin/env bash
# Git SSH smoke under kh (Linux aarch64 Docker / Colima).
#
# CLT does not ship OpenSSH. Bottle bridges guest `/usr/bin/ssh` → host
# OpenSSH; this script proves the full path:
#   Apple git → execvp(ssh) → host ssh → local sshd → git-upload-pack
#
# Clean-room: host client only (no freestanding SSH protocol stack).
#
# Usage:
#   ./scripts/docker-git-ssh.sh
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

# Image must include openssh-client (+ server for this smoke). Rebuild if old.
if ! docker image inspect "${IMAGE}" >/dev/null 2>&1; then
  echo "==> docker build ${IMAGE}"
  docker build -t "${IMAGE}" -f Dockerfile.dev .
else
  # Stale images pre-SSH deps: install inside the run if missing.
  :
fi

DOCKER_ENVS=()
for e in KAKEHASHI_XCODE_TOOLS_VERSION KAKEHASHI_FORCE_DOWNLOAD \
  KAKEHASHI_BOUNDARY_STATS KAKEHASHI_FUTEX_STATS KAKEHASHI_HEAP_STATS; do
  if [[ -n "${!e:-}" ]]; then
    DOCKER_ENVS+=(-e "${e}=${!e}")
  fi
done

echo "==> git SSH smoke (local sshd + kh clone)"
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
if [[ "${KH_EXTRA_CARGO_ARGS:-}" == *"--release"* ]]; then
  KH=./target/release/kh
else
  KH=./target/debug/kh
fi
"$KH" bottle ensure
"$KH" install xcode-tools

# ── local bare repo + sshd (host tools; not under kh) ──────────────────────
WORK=/tmp/kh-git-ssh-$$
rm -rf "$WORK"
mkdir -p "$WORK/ssh" "$WORK/bare" "$WORK/seed"

# Seed a tiny repo, push to bare
git -C "$WORK/seed" init -q -b main
printf "ssh-smoke\n" >"$WORK/seed/README"
git -C "$WORK/seed" config user.email "kh@test.io"
git -C "$WORK/seed" config user.name "Vladislav"
git -C "$WORK/seed" add README
git -C "$WORK/seed" commit -q -m "ssh smoke"
git -C "$WORK/seed" clone --bare -q . "$WORK/bare/repo.git"

# Ephemeral host key + client key (root home in this image)
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

# Debian OpenSSH expects this even when PrivilegeSeparation is off by default.
mkdir -p /run/sshd
/usr/sbin/sshd -f "$SSHD_CONFIG"
cleanup() {
  if [[ -f "$WORK/ssh/sshd.pid" ]]; then
    kill "$(cat "$WORK/ssh/sshd.pid")" 2>/dev/null || true
  fi
}
trap cleanup EXIT

# Trust local host key for this run only
KNOWN="$WORK/ssh/known_hosts"
ssh-keyscan -p 2222 -H 127.0.0.1 >"$KNOWN" 2>/dev/null

export GIT_SSH_COMMAND="ssh -i /root/.ssh/id_ed25519 -o IdentitiesOnly=yes -o UserKnownHostsFile=$KNOWN -o StrictHostKeyChecking=yes -o BatchMode=yes"

"$KH" run git -- config --global user.email "kh@test.io"
"$KH" run git -- config --global user.name "Vladislav"
"$KH" run git -- config --global protocol.version 2

# 1) ls-remote over SSH
echo "==> ls-remote ssh://root@127.0.0.1:2222$WORK/bare/repo.git"
"$KH" run git -- ls-remote "ssh://root@127.0.0.1:2222$WORK/bare/repo.git"
# expect a line with refs/heads/main

# 2) clone over SSH into durable /out
rm -rf /out/ssh-smoke
echo "==> clone → /Volumes/linux/out/ssh-smoke"
"$KH" run git -- clone --progress \
  "ssh://root@127.0.0.1:2222$WORK/bare/repo.git" \
  /Volumes/linux/out/ssh-smoke

test -f /out/ssh-smoke/README
grep -q ssh-smoke /out/ssh-smoke/README
echo "==> SSH smoke OK (ls-remote + clone, README present)"
'
rc=$?
set -e
exit "$rc"
