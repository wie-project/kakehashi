#!/usr/bin/env bash
# Profile a large monorepo clone (default: wine) under kh with:
#   - KAKEHASHI_BOUNDARY_STATS=ns on the main clone
#   - live monitor: phase (receive / index-pack / checkout), CPU, pack I/O, worktree
#
# Artifacts: .tmp/kh-wine-profile/
#   monitor.tsv, monitor.log, clone.stdout, clone.stderr, stats*.txt, summary.md
#
# Usage:
#   ./scripts/profile-git-wine.sh
#   WINE_URL=https://github.com/wine-mirror/wine.git ./scripts/profile-git-wine.sh
#   KH_WINE_TIMEOUT_S=7200 ./scripts/profile-git-wine.sh   # hard kill after N seconds (0=off)
#
# Docker gets SYS_PTRACE so a stuck index-pack can be strace'd if needed.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

IMAGE="${KAKEHASHI_SMOKE_IMAGE:-kakehashi:dev}"
ART="${KH_WINE_PROFILE_DIR:-$ROOT/.tmp/kh-wine-profile}"
KH_OUT="${KH_OUT:-$ROOT/.tmp/kh-out}"
URL="${WINE_URL:-https://gitlab.winehq.org/wine/wine.git}"
DEST_NAME="${WINE_DEST:-wine}"
if [ "${KH_EXTRA_CARGO_ARGS+set}" != "set" ]; then
  KH_EXTRA_CARGO_ARGS=--release
fi
export KAKEHASHI_BOUNDARY_STATS="${KAKEHASHI_BOUNDARY_STATS:-ns}"
# 0 = no hard timeout; default 3h
TIMEOUT_S="${KH_WINE_TIMEOUT_S:-10800}"
# flag pure-userspace burn longer than this after pack EOF as suspicious
BURN_WARN_S="${KH_WINE_BURN_WARN_S:-600}"

mkdir -p "$ART" "$KH_OUT" "$ROOT/.kh"
rm -rf "$ART"/*
rm -rf "${KH_OUT}/${DEST_NAME}"

if [[ -f target/aarch64-apple-darwin/release/libkh_libsystem.dylib ]] \
  || [[ -f target/release/libkh_libsystem.dylib ]]; then
  ./scripts/stage-libsystem.sh
elif [[ -f crates/kh-runtime/resources/libSystem.B.dylib ]]; then
  echo "note: using crates/kh-runtime/resources/libSystem.B.dylib"
else
  echo "error: no guest libSystem" >&2
  exit 1
fi

if ! docker image inspect "${IMAGE}" >/dev/null 2>&1; then
  echo "==> docker build ${IMAGE}"
  docker build -t "${IMAGE}" -f Dockerfile.dev .
fi

echo "==> profile dir: $ART"
echo "==> url: $URL"
echo "==> dest: $KH_OUT/$DEST_NAME"
echo "==> KAKEHASHI_BOUNDARY_STATS=$KAKEHASHI_BOUNDARY_STATS"
echo "==> TIMEOUT_S=$TIMEOUT_S  BURN_WARN_S=$BURN_WARN_S"

# Host-side live monitor (bind-mount sees /out)
MON_PID=""
cleanup() {
  if [[ -n "${MON_PID}" ]] && kill -0 "$MON_PID" 2>/dev/null; then
    kill "$MON_PID" 2>/dev/null || true
    wait "$MON_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

(
  OUT="${KH_OUT}/${DEST_NAME}"
  TSV="$ART/monitor.tsv"
  LOG="$ART/monitor.log"
  echo -e "t_s\tphase\tpack_mib\tpack_pos\thas_idx\twt_files\tdu_mib\tcpu_s\trchar\twchar\tvol\trss_kib\tnote" >"$TSV"
  t0=$(date +%s)
  burn_start=""
  last_note=""
  while true; do
    now=$(date +%s)
    t=$((now - t0))
    phase="init"
    pack_mib="0"
    pack_pos="-"
    has_idx="0"
    wt_files="0"
    du_mib="0"
    cpu_s="-"
    rchar="-"
    wchar="-"
    vol="-"
    rss="-"
    note=""

    if [[ -d "$OUT/.git" ]]; then
      if [[ -d "$OUT/.git/objects/pack" ]]; then
        # sum pack-ish sizes
        pk=$(find "$OUT/.git/objects/pack" -type f \( -name 'tmp_pack_*' -o -name 'pack-*.pack' \) -exec stat -f%z {} + 2>/dev/null | awk '{s+=$1} END{print s+0}')
        pack_mib=$(awk -v b="${pk:-0}" 'BEGIN{printf "%.1f", b/1048576}')
        if ls "$OUT/.git/objects/pack"/pack-*.idx >/dev/null 2>&1; then
          has_idx="1"
        fi
        if ls "$OUT/.git/objects/pack"/tmp_pack_* >/dev/null 2>&1; then
          phase="index-pack"
        elif [[ "$has_idx" == "1" ]]; then
          phase="post-pack"
        else
          phase="receive?"
        fi
      fi
      wt_files=$(find "$OUT" -type f ! -path '*/.git/*' 2>/dev/null | wc -l | tr -d ' ')
      if [[ "${wt_files:-0}" -gt 5 ]]; then
        phase="checkout"
      fi
      duk=$(du -sk "$OUT" 2>/dev/null | awk '{print $1}')
      du_mib=$(awk -v k="${duk:-0}" 'BEGIN{printf "%.1f", k/1024}')
    fi

    # Sample busiest kh/git inside docker if container known
    # Written by main script to ART/container.id
    if [[ -f "$ART/container.id" ]]; then
      cid=$(cat "$ART/container.id")
      if [[ -n "$cid" ]]; then
        sample=$(docker exec "$cid" python3 -c '
import os,re,glob
best=None
for p in glob.glob("/proc/[0-9]*"):
    try:
        cmd=open(p+"/cmdline","rb").read().replace(b"\0",b" ").decode("utf-8","replace")
    except Exception:
        continue
    if "index-pack" in cmd or ("kh run" in cmd and "git" in cmd):
        pid=int(os.path.basename(p))
        st=open(p+"/stat").read()
        m=re.match(r"^\d+ \(.*?\) (.*)$", st)
        if not m: continue
        f=m.group(1).split()
        ut=int(f[11]); stt=int(f[12])
        try:
            io=dict(x.split(": ") for x in open(p+"/io").read().strip().splitlines())
            rchar=int(io.get("rchar",0)); wchar=int(io.get("wchar",0))
        except Exception:
            rchar=wchar=0
        try:
            rss=int([l for l in open(p+"/status") if l.startswith("VmRSS")][0].split()[1])
            vol=int([l for l in open(p+"/status") if l.startswith("voluntary_ctxt")][0].split()[1])
        except Exception:
            rss=vol=0
        pos="-"
        for fd in os.listdir(p+"/fd"):
            try:
                tgt=os.readlink(p+"/fd/"+fd)
            except Exception:
                continue
            if "tmp_pack" in tgt or tgt.endswith(".pack"):
                try:
                    pos=open(p+"/fdinfo/"+fd).read().splitlines()[0].split()[1]
                except Exception:
                    pass
        score=ut+stt
        if "index-pack" in cmd:
            score+=10**12
        row=(score, ut+stt, rchar, wchar, vol, rss, pos, "index-pack" if "index-pack" in cmd else "kh/git")
        if best is None or row[0]>best[0]:
            best=row
if best:
    _,cpu,rchar,wchar,vol,rss,pos,kind=best
    print(f"{cpu/100.0:.1f}\t{rchar}\t{wchar}\t{vol}\t{rss}\t{pos}\t{kind}")
else:
    print("-\t-\t-\t-\t-\t-\tnone")
' 2>/dev/null || echo "-	-	-	-	-	-	err")
        IFS=$'\t' read -r cpu_s rchar wchar vol rss pack_pos kind <<<"$sample"
        if [[ "$kind" == "index-pack" ]]; then
          phase="index-pack"
        fi
        # pure burn detection: index-pack, pack pos stable at EOF-ish, no rchar growth
        if [[ "$phase" == "index-pack" && "$has_idx" == "0" && "$cpu_s" != "-" ]]; then
          if [[ -z "$burn_start" ]]; then
            burn_start=$now
            echo "$t last_rchar=$rchar last_pos=$pack_pos" >"$ART/burn_state.txt"
          else
            # shell-level compare via files
            prev_r=$(awk '{for(i=1;i<=NF;i++) if($i ~ /^last_rchar=/){split($i,a,"="); print a[2]}}' "$ART/burn_state.txt" 2>/dev/null || true)
            prev_p=$(awk '{for(i=1;i<=NF;i++) if($i ~ /^last_pos=/){split($i,a,"="); print a[2]}}' "$ART/burn_state.txt" 2>/dev/null || true)
            if [[ "$rchar" == "$prev_r" && "$pack_pos" == "$prev_p" && "$pack_pos" != "-" ]]; then
              burn_for=$((now - burn_start))
              if [[ $burn_for -ge $BURN_WARN_S ]]; then
                note="SUSPECT_PURE_BURN_${burn_for}s"
              else
                note="pure_burn_${burn_for}s"
              fi
            else
              burn_start=$now
              echo "$t last_rchar=$rchar last_pos=$pack_pos" >"$ART/burn_state.txt"
              note="io_moved"
            fi
          fi
        else
          burn_start=""
        fi
      fi
    fi

    line=$(printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$t" "$phase" "$pack_mib" "$pack_pos" "$has_idx" "$wt_files" "$du_mib" \
      "$cpu_s" "$rchar" "$wchar" "$vol" "$rss" "$note")
    echo "$line" >>"$TSV"
    if [[ "$note" != "$last_note" && -n "$note" ]]; then
      echo "[$t s] phase=$phase $note pack_mib=$pack_mib wt=$wt_files cpu_s=$cpu_s" | tee -a "$LOG"
      last_note="$note"
    elif (( t % 30 == 0 )); then
      echo "[$t s] phase=$phase pack_mib=$pack_mib idx=$has_idx wt=$wt_files du_mib=$du_mib cpu_s=$cpu_s pos=$pack_pos $note" | tee -a "$LOG"
    fi
    sleep 5
  done
) &
MON_PID=$!
echo "$MON_PID" >"$ART/monitor.pid"

# Run clone in docker with ptrace + stats
# Write container id via docker run -d then docker wait, so monitor can docker exec
set +e
start=$(date +%s%N)
cid=$(docker run -d \
  --cap-add=SYS_PTRACE \
  --security-opt seccomp=unconfined \
  -v "${ROOT}:/src" \
  -v kh-target-cache:/src/target \
  -v "${KH_OUT}:/out" \
  -v "${ART}:/report" \
  -w /src \
  -e KAKEHASHI_CONFIG_DIR=/src/.kh/config \
  -e KAKEHASHI_DATA_DIR=/src/.kh/data \
  -e CARGO_TARGET_DIR=/src/target \
  -e "KH_EXTRA_CARGO_ARGS=${KH_EXTRA_CARGO_ARGS}" \
  -e "KAKEHASHI_BOUNDARY_STATS=${KAKEHASHI_BOUNDARY_STATS}" \
  -e "CLONE_URL=${URL}" \
  -e "CLONE_DEST=${DEST_NAME}" \
  "${IMAGE}" \
  bash -c '
set -euo pipefail
cargo build -p kakehashi ${KH_EXTRA_CARGO_ARGS:-} 2>&1 | tee /report/build.log | tail -5
if [[ "${KH_EXTRA_CARGO_ARGS:-}" == *"--release"* ]]; then
  KH=./target/release/kh
else
  KH=./target/debug/kh
fi
"$KH" bottle ensure
"$KH" install xcode-tools >/dev/null
"$KH" run git -- config --global user.email "kh@test.io"
"$KH" run git -- config --global user.name "kh-wine-profile"
"$KH" run git -- config --global protocol.version 2
"$KH" run git -- config --global http.postBuffer 524288000

rm -rf "/out/${CLONE_DEST}"
echo "START $(date -Is)" | tee /report/clone.meta
set +e
# max-syscalls huge for monorepo
"$KH" run --max-syscalls 2000000000 git -- \
  clone --progress "${CLONE_URL}" "/Volumes/linux/out/${CLONE_DEST}" \
  >/report/clone.stdout 2>/report/clone.stderr
rc=$?
set -e
echo "END $(date -Is) rc=$rc" | tee -a /report/clone.meta
echo "$rc" >/report/exit.txt
# extract all boundary dumps (parent + nested helpers)
grep -E "kh boundary stats:|^[[:space:]]*host_dispatch|^[[:space:]]*rank |^[[:space:]]*[0-9]+ +[0-9]+" \
  /report/clone.stderr > /report/stats.all.txt || true
# split dumps: each "kh boundary stats" starts a block
awk "
  /kh boundary stats:/ { n++; f=sprintf(\"/report/stats.%02d.txt\", n); print > f; next }
  n { print > f }
" /report/clone.stderr || true
# worktree summary
if [[ -d "/out/${CLONE_DEST}" ]]; then
  du -sh "/out/${CLONE_DEST}" | tee /report/du.txt
  find "/out/${CLONE_DEST}" -type f ! -path "*/.git/*" | wc -l | tee /report/wt_files.txt
  ls -la "/out/${CLONE_DEST}/.git/objects/pack" 2>/dev/null | tee /report/pack.ls.txt || true
fi
exit "$rc"
')
set -e
echo "$cid" | tee "$ART/container.id"
echo "==> container $cid"

# Wait with optional timeout; on timeout strace index-pack then stop.
docker wait "$cid" >"$ART/docker.wait.rc" 2>"$ART/docker.wait.err" &
wait_pid=$!
waited=0
while kill -0 "$wait_pid" 2>/dev/null; do
  if [[ "${TIMEOUT_S}" != "0" && $waited -ge $TIMEOUT_S ]]; then
    echo "==> TIMEOUT ${TIMEOUT_S}s — snapshot + strace + stop" | tee -a "$ART/monitor.log"
    docker exec "$cid" ps aux --sort=-%cpu 2>/dev/null | head -20 | tee "$ART/timeout.ps.txt" || true
    ipid=$(docker exec "$cid" sh -c "ps -eo pid,cmd | awk '/index-pack/ && !/awk/{print \$1; exit}'" 2>/dev/null || true)
    if [[ -n "${ipid:-}" ]]; then
      echo "strace index-pack pid=$ipid" | tee -a "$ART/monitor.log"
      docker exec "$cid" timeout 10 strace -p "$ipid" -c 2>"$ART/timeout.strace_c.txt" || true
      docker exec "$cid" timeout 4 strace -p "$ipid" -f 2>"$ART/timeout.strace_raw.txt" || true
      head -80 "$ART/timeout.strace_raw.txt" 2>/dev/null | tee -a "$ART/monitor.log" || true
    fi
    docker stop -t 20 "$cid" >/dev/null 2>&1 || true
    break
  fi
  sleep 10
  waited=$((waited + 10))
done
wait "$wait_pid" 2>/dev/null || true
rc=$(cat "$ART/docker.wait.rc" 2>/dev/null || echo 137)
# docker stop → often 137
if [[ ! -f "$ART/exit.txt" ]]; then
  echo "$rc" >"$ART/exit.txt"
fi

end=$(date +%s%N)
wall_s=$(awk -v a="$start" -v b="$end" 'BEGIN{printf "%.3f", (b-a)/1e9}')
echo "$wall_s" >"$ART/wall_s.txt"
echo "$rc" >"$ART/docker.exit.txt"

# Ensure logs flushed from container filesystem (already bind-mounted ART)
docker logs "$cid" >"$ART/docker.logs.txt" 2>&1 || true
docker rm -f "$cid" >/dev/null 2>&1 || true
: >"$ART/container.id"

cleanup
MON_PID=""

# Summary
python3 - <<PY
from pathlib import Path
import re, csv

art = Path("$ART")
wall = (art / "wall_s.txt").read_text().strip() if (art / "wall_s.txt").exists() else "?"
rc = (art / "exit.txt").read_text().strip() if (art / "exit.txt").exists() else (
    (art / "docker.exit.txt").read_text().strip() if (art / "docker.exit.txt").exists() else "?"
)
wt = (art / "wt_files.txt").read_text().strip() if (art / "wt_files.txt").exists() else "?"
du = (art / "du.txt").read_text().strip() if (art / "du.txt").exists() else "?"

lines = []
lines.append("# Wine clone profile")
lines.append("")
lines.append(f"- url: \`$URL\`")
lines.append(f"- wall_s: **{wall}**")
lines.append(f"- exit: **{rc}**")
lines.append(f"- worktree files: {wt}")
lines.append(f"- du: {du}")
lines.append(f"- KAKEHASHI_BOUNDARY_STATS={Path('$ART').joinpath('..') and '$KAKEHASHI_BOUNDARY_STATS'}")
lines.append("")

# monitor phase timeline
mon = art / "monitor.tsv"
if mon.exists():
    rows = list(csv.DictReader(mon.open(), delimiter="\t"))
    lines.append("## Phase timeline (sampled ~5s)")
    lines.append("")
    # compress consecutive same phase
    if rows:
        cur = rows[0]["phase"]
        t0 = rows[0]["t_s"]
        last = rows[0]
        for r in rows[1:]:
            if r["phase"] != cur:
                lines.append(f"- t={t0}–{last['t_s']}s **{cur}** pack_mib={last.get('pack_mib')} idx={last.get('has_idx')} wt={last.get('wt_files')} note={last.get('note')}")
                cur = r["phase"]
                t0 = r["t_s"]
            last = r
        lines.append(f"- t={t0}–{last['t_s']}s **{cur}** pack_mib={last.get('pack_mib')} idx={last.get('has_idx')} wt={last.get('wt_files')} note={last.get('note')}")
    suspects = [r for r in rows if r.get("note","").startswith("SUSPECT")]
    if suspects:
        lines.append("")
        lines.append(f"**Pure-burn warnings:** {len(suspects)} samples (I/O frozen while index-pack CPU-bound ≥ warn threshold).")
    lines.append("")

# boundary stats blocks
stats = sorted(art.glob("stats.[0-9]*.txt"))
if not stats and (art / "stats.all.txt").exists():
    stats = [art / "stats.all.txt"]
lines.append("## Boundary stats dumps")
lines.append("")
for p in stats:
    text = p.read_text(errors="replace")
    m = re.search(r"total=(\d+)", text)
    total = m.group(1) if m else "?"
    # top line
    top = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[0].isdigit() and parts[1].isdigit():
            # rank count ns avg name
            name = parts[4] if len(parts) > 4 else "?"
            top.append(f"{name}:{parts[1]}")
            if len(top) >= 5:
                break
    lines.append(f"- `{p.name}` total={total} top={', '.join(top)}")
lines.append("")

# stderr tail
err = art / "clone.stderr"
if err.exists():
    tail = err.read_text(errors="replace").splitlines()[-40:]
    lines.append("## clone.stderr (tail)")
    lines.append("```")
    lines.extend(tail)
    lines.append("```")

out = "\n".join(lines) + "\n"
(art / "summary.md").write_text(out)
print(out)
print(f"==> done: {art}")
PY

exit "${rc:-1}"
