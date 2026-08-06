#!/usr/bin/env bash
# Git plain HTTP smoke under kh (Linux aarch64 Docker / Colima).
#
# Proves freestanding libcurl path B for http:// (TLS_FLAG_PLAIN TCP guest FD):
#   ls-remote + clone + push to a local smart-HTTP bare remote.
#
# Clean-room: same HTTP/1.1 streamer as https://; host TCP only (no rustls).
# No GitHub account. Binds 127.0.0.1 only.
#
# Usage:
#   ./scripts/docker-git-http.sh
#
# Env: same as docker-git.sh (KAKEHASHI_*, KH_EXTRA_CARGO_ARGS, image name).

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

echo "==> git plain HTTP smoke (smart HTTP on 127.0.0.1)"
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

# Host git + python for git-http-backend CGI (not under kh).
if ! command -v git >/dev/null 2>&1 || ! command -v python3 >/dev/null 2>&1; then
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
    git python3 >/dev/null
fi

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

WORK=/tmp/kh-git-http-$$
rm -rf "$WORK"
mkdir -p "$WORK/bare" "$WORK/seed"

git -C "$WORK/seed" init -q -b main
printf "http-smoke-seed\n" >"$WORK/seed/README"
git -C "$WORK/seed" config user.email "kh@test.io"
git -C "$WORK/seed" config user.name "Vladislav"
git -C "$WORK/seed" add README
git -C "$WORK/seed" commit -q -m "seed"
git -C "$WORK/seed" clone --bare -q . "$WORK/bare/repo.git"
git -C "$WORK/bare/repo.git" config http.receivepack true
git -C "$WORK/bare/repo.git" config http.uploadpack true
git -C "$WORK/bare/repo.git" update-server-info

BACKEND=""
for c in /usr/lib/git-core/git-http-backend /usr/libexec/git-core/git-http-backend; do
  if [[ -x "$c" ]]; then BACKEND=$c; break; fi
done
if [[ -z "$BACKEND" ]]; then
  BACKEND=$(command -v git-http-backend || true)
fi
test -n "$BACKEND" && test -x "$BACKEND"
echo "==> git-http-backend: $BACKEND"

PORT=9419
# Minimal CGI front for git-http-backend (PATH_INFO = request path).
export GIT_PROJECT_ROOT="$WORK/bare"
export GIT_HTTP_EXPORT_ALL=1
export KH_GIT_BACKEND="$BACKEND"
python3 - "$PORT" <<'"'"'PY'"'"' &
import os, subprocess, sys, urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

BACKEND = os.environ["KH_GIT_BACKEND"]
ROOT = os.environ["GIT_PROJECT_ROOT"]
PORT = int(sys.argv[1])


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self._cgi()

    def do_POST(self):
        self._cgi()

    def _cgi(self):
        parsed = urllib.parse.urlparse(self.path)
        env = os.environ.copy()
        env["GIT_PROJECT_ROOT"] = ROOT
        env["GIT_HTTP_EXPORT_ALL"] = "1"
        env["PATH_INFO"] = parsed.path
        env["REQUEST_METHOD"] = self.command
        env["QUERY_STRING"] = parsed.query or ""
        env["CONTENT_TYPE"] = self.headers.get("Content-Type", "")
        env["CONTENT_LENGTH"] = self.headers.get("Content-Length") or "0"
        env["REMOTE_ADDR"] = self.client_address[0]
        env["SERVER_PROTOCOL"] = "HTTP/1.1"
        env["REQUEST_URI"] = self.path
        env["SCRIPT_NAME"] = ""
        cl = int(env["CONTENT_LENGTH"] or "0")
        body = self.rfile.read(cl) if cl > 0 else b""
        proc = subprocess.Popen(
            [BACKEND],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        out, err = proc.communicate(body)
        if proc.returncode != 0 and err:
            sys.stderr.write(err.decode(errors="replace"))
        if b"\r\n\r\n" in out:
            head, resp_body = out.split(b"\r\n\r\n", 1)
        elif b"\n\n" in out:
            head, resp_body = out.split(b"\n\n", 1)
        else:
            head, resp_body = b"Status: 500 Internal Server Error\nContent-Type: text/plain", out
        status = 200
        headers = []
        for line in head.replace(b"\r\n", b"\n").split(b"\n"):
            if not line:
                continue
            if line.lower().startswith(b"status:"):
                try:
                    status = int(line.split(b":", 1)[1].strip().split()[0])
                except Exception:
                    status = 200
            else:
                k, _, v = line.partition(b":")
                headers.append((k.decode(), v.strip().decode()))
        self.send_response(status)
        for k, v in headers:
            if k.lower() != "status":
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(resp_body)

    def log_message(self, fmt, *args):
        return


HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
PY
HTTP_PID=$!
cleanup() {
  kill "$HTTP_PID" 2>/dev/null || true
}
trap cleanup EXIT
sleep 0.4
if ! kill -0 "$HTTP_PID" 2>/dev/null; then
  echo "error: HTTP server failed to start" >&2
  exit 1
fi

REMOTE="http://127.0.0.1:${PORT}/repo.git"

echo "==> 1) ls-remote $REMOTE"
"$KH" run git -- ls-remote "$REMOTE" | tee /tmp/http-ls-remote.txt
grep -q refs/heads/main /tmp/http-ls-remote.txt

echo "==> 2) clone → /Volumes/linux/out/http-smoke"
rm -rf /out/http-smoke
"$KH" run git -- clone --progress "$REMOTE" /Volumes/linux/out/http-smoke
test -f /out/http-smoke/README
grep -q http-smoke-seed /out/http-smoke/README

echo "==> 3) branch + push over plain HTTP"
(
  cd /out/http-smoke
  "$KH" run git -- checkout -b feature/http-push
  printf "pushed-over-http\n" >> README
  "$KH" run git -- add README
  "$KH" run git -- commit -m "http push commit"
  "$KH" run git -- push -u origin feature/http-push
)

git -C "$WORK/bare/repo.git" show-ref | grep -q "refs/heads/feature/http-push"
echo "==> remote refs:"
git -C "$WORK/bare/repo.git" show-ref

echo "==> PLAIN HTTP SMOKE OK (ls-remote + clone + push)"
'
rc=$?
set -e
exit "$rc"
