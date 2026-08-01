#!/usr/bin/env bash
# Tiered Darwin curl option smoke under kh (Docker/Colima aarch64).
#
# One container: build kh once → bottle → install curl → run a matrix of
# flags. Artifacts + summary under host .tmp/kh-curl-options/.
#
# Usage:
#   ./scripts/docker-curl-options.sh              # tier1
#   ./scripts/docker-curl-options.sh tier2
#   ./scripts/docker-curl-options.sh tier3-6      # run tiers 3..6
#   ./scripts/docker-curl-options.sh tier7-8
#   ./scripts/docker-curl-options.sh tier9-10
#   ./scripts/docker-curl-options.sh all          # tier1..10
#   ./scripts/docker-curl-options.sh tier3 tier9  # explicit list
#
# Tiers (large blocks):
#   1  core HTTP/HTTPS polish (GET/HEAD/POST/fail/redirect basics)
#   2  cookies, compressed, range, http2, json, retry
#   3  output / FS / trace / write-out / url helpers
#   4  transfer control (redirects, keepalive, size, http versions)
#   5  TLS surface (versions, ciphers, CA, sessions)
#   6  auth soft + proxy/socks negative + noproxy
#   7  multi-URL / parallel / resolve / connect-to / rate / DNS knobs
#   8  HTTP/3, DoH, unix-socket negatives, HSTS/alt-svc, misc network
#   9  other protocols (file/ftp/ssh/smtp soft) + upload + manual
#  10 live micro-proxy + unix HTTP + auth/DNS leftovers + client-cert soft
#
# Env: same as docker-curl.sh (KAKEHASHI_SMOKE_IMAGE, KAKEHASHI_CURL, …).
#
# Philosophy: pass = exit 0 (or expected non-zero) + no missing-symbol crash.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Expand tier args: tier3-6 → 3 4 5 6; all → 1..10; bare tierN → N
expand_tiers() {
  local out=()
  if [[ $# -eq 0 ]]; then
    out=(1)
  else
    for a in "$@"; do
      case "$a" in
        all)
          out+=(1 2 3 4 5 6 7 8 9 10)
          ;;
        tier1[0]|tier[1-9])
          out+=("${a#tier}")
          ;;
        tier[1-9]-*|tier10-*|tier*-10)
          local lo="${a#tier}"
          local hi="${lo#*-}"
          lo="${lo%-*}"
          local i
          for ((i = lo; i <= hi; i++)); do
            out+=("$i")
          done
          ;;
        1[0]|[1-9])
          out+=("$a")
          ;;
        *)
          echo "error: unknown tier spec '$a' (use tier1..tier10, tier9-10, all)" >&2
          exit 2
          ;;
      esac
    done
  fi
  # uniq sort
  printf '%s\n' "${out[@]}" | sort -n | uniq | tr '\n' ' '
}

TIER_LIST="$(expand_tiers "$@")"
IMAGE="${KAKEHASHI_SMOKE_IMAGE:-kakehashi:dev}"
KH_OUT="${KH_OUT:-$ROOT/.tmp/kh-out}"
REPORT_DIR="${KH_CURL_OPTIONS_DIR:-$ROOT/.tmp/kh-curl-options}"

mkdir -p "$KH_OUT" "$REPORT_DIR"

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

DOCKER_VOLS=(
  -v "${ROOT}:/src"
  -v kh-target-cache:/src/target
  -v "${KH_OUT}:/out"
  -v "${REPORT_DIR}:/report"
)

DOCKER_ENVS=()
if [[ -n "${KAKEHASHI_CURL:-}" && -f "${KAKEHASHI_CURL}" ]]; then
  DOCKER_VOLS+=(-v "${KAKEHASHI_CURL}:/host-curl:ro")
  DOCKER_ENVS+=(-e KAKEHASHI_CURL=/host-curl)
fi

echo "==> curl option smoke tiers=[${TIER_LIST}]"
echo "==> report → ${REPORT_DIR}"

docker run --rm \
  "${DOCKER_VOLS[@]}" \
  "${DOCKER_ENVS[@]+"${DOCKER_ENVS[@]}"}" \
  -w /src \
  -e KAKEHASHI_CONFIG_DIR=/src/.kh/config \
  -e KAKEHASHI_DATA_DIR=/src/.kh/data \
  -e CARGO_TARGET_DIR=/src/target \
  -e "KAKEHASHI_HYPERCALL=${KAKEHASHI_HYPERCALL:-}" \
  -e "KH_EXTRA_CARGO_ARGS=${KH_EXTRA_CARGO_ARGS:-}" \
  -e "KH_CURL_TIERS=${TIER_LIST}" \
  "${IMAGE}" \
  bash -c '
set -euo pipefail

cargo build -p kakehashi ${KH_EXTRA_CARGO_ARGS:-}
if [[ "${KH_EXTRA_CARGO_ARGS:-}" == *"--release"* ]]; then
  KH=./target/release/kh
else
  KH=./target/debug/kh
fi

"$KH" bottle ensure
if [[ -f /etc/resolv.conf ]]; then
  mkdir -p "${KAKEHASHI_DATA_DIR}/bottle/private/etc"
  cp /etc/resolv.conf "${KAKEHASHI_DATA_DIR}/bottle/private/etc/resolv.conf" || true
fi
"$KH" install curl >/dev/null

# Seed CA path used by some --cacert cases (bottle layout).
BOTTLE="${KAKEHASHI_DATA_DIR}/bottle"
CA_PEM=""
if [[ -f "${BOTTLE}/private/etc/ssl/cert.pem" ]]; then
  CA_PEM="/private/etc/ssl/cert.pem"
elif [[ -f "${BOTTLE}/etc/ssl/cert.pem" ]]; then
  CA_PEM="/etc/ssl/cert.pem"
fi

SUMMARY=/report/summary.txt
DETAIL=/report/detail.log
: >"$SUMMARY"
: >"$DETAIL"

pass=0
fail=0
skip=0

want_tier() {
  local t="$1"
  for x in ${KH_CURL_TIERS}; do
    [[ "$x" == "$t" ]] && return 0
  done
  return 1
}

# run_case NAME EXPECT_RC -- curl args…
# EXPECT_RC: integer exit code, or "nonzero"
run_case() {
  local name="$1"
  local expect="$2"
  shift 2
  local out_f="/report/${name}.stdout"
  local err_f="/report/${name}.stderr"
  local rc_f="/report/${name}.exit"
  set +e
  "$KH" run curl -- "$@" >"$out_f" 2>"$err_f"
  local rc=$?
  set -e
  echo "$rc" >"$rc_f"

  local ok=0
  if [[ "$expect" == "nonzero" ]]; then
    [[ "$rc" -ne 0 ]] && ok=1
  else
    [[ "$rc" -eq "$expect" ]] && ok=1
  fi

  if grep -q "missing symbol called:" "$err_f" 2>/dev/null; then
    ok=0
    echo "  !! missing symbol in $name" | tee -a "$DETAIL"
    grep "missing symbol called:" "$err_f" | head -5 | tee -a "$DETAIL" || true
  fi
  if grep -q "unknown BSD syscall #" "$err_f" 2>/dev/null; then
    echo "  note: unknown BSD in $name:" | tee -a "$DETAIL"
    grep "unknown BSD syscall #" "$err_f" | head -5 | tee -a "$DETAIL" || true
  fi

  if [[ "$ok" -eq 1 ]]; then
    echo "PASS  $name  (rc=$rc expect=$expect)" | tee -a "$SUMMARY"
    pass=$((pass + 1))
  else
    echo "FAIL  $name  (rc=$rc expect=$expect)" | tee -a "$SUMMARY"
    echo "---- $name stderr (tail) ----" >>"$DETAIL"
    tail -n 60 "$err_f" >>"$DETAIL" || true
    fail=$((fail + 1))
  fi
}

echo "==> tiers: ${KH_CURL_TIERS}"

# ── meta (always, once) ────────────────────────────────────────────────────
run_case version 0 --version
run_case help 0 --help
run_case help_all 0 --help all

# ── tier1: core HTTP/HTTPS polish ──────────────────────────────────────────
if want_tier 1; then
  echo "---- tier1 ----" | tee -a "$SUMMARY"
  run_case t1_http_get_o 0 -sS -o /Volumes/linux/out/t1-http.html http://example.com/
  run_case t1_https_get_o 0 -sS -o /Volumes/linux/out/t1-https.html https://example.com/
  run_case t1_head_http 0 -sS -I -o /Volumes/linux/out/t1-head.txt http://example.com/
  run_case t1_head_https 0 -sS -I -o /Volumes/linux/out/t1-head-https.txt https://example.com/
  run_case t1_user_agent 0 -sS -A "kh-curl-options/1" -o /Volumes/linux/out/t1-ua.html http://example.com/
  run_case t1_custom_header 0 -sS -H "X-Kh-Test: 1" -o /Volumes/linux/out/t1-hdr.html http://example.com/
  run_case t1_dump_header 0 -sS -D /Volumes/linux/out/t1-dump-hdr.txt -o /Volumes/linux/out/t1-dump-body.html http://example.com/
  run_case t1_show_headers 0 -sS -i -o /Volumes/linux/out/t1-i.html http://example.com/
  run_case t1_request_get 0 -sS -X GET -o /Volumes/linux/out/t1-xget.html http://example.com/
  run_case t1_post_data 0 -sS -d "hello=kh" -o /Volumes/linux/out/t1-post.html http://example.com/
  run_case t1_get_with_data 0 -sS -G -d "q=kh" -o /Volumes/linux/out/t1-g.html "http://example.com/"
  run_case t1_write_out 0 -sS -o /dev/null -w "%{http_code}" http://example.com/
  run_case t1_max_time 0 -sS -m 30 -o /Volumes/linux/out/t1-m.html http://example.com/
  run_case t1_connect_timeout 0 -sS --connect-timeout 30 -o /Volumes/linux/out/t1-ct.html http://example.com/
  run_case t1_http11 0 -sS --http1.1 -o /Volumes/linux/out/t1-11.html http://example.com/
  run_case t1_ipv4 0 -sS -4 -o /Volumes/linux/out/t1-v4.html http://example.com/
  run_case t1_insecure 0 -sS -k -o /Volumes/linux/out/t1-k.html https://example.com/
  run_case t1_create_dirs 0 -sS --create-dirs -o /Volumes/linux/out/t1-nested/dir/body.html http://example.com/
  run_case t1_location 0 -sS -L -o /Volumes/linux/out/t1-L.html http://example.com/
  run_case t1_fail_404 nonzero -sS -f -o /dev/null http://example.com/no-such-kh-path-404
  run_case t1_badssl_noskip nonzero -sS -o /dev/null https://self-signed.badssl.com/
  run_case t1_verbose 0 -sS -v -o /Volumes/linux/out/t1-v.html http://example.com/
fi

# ── tier2: cookies / compression / http2 / retry ───────────────────────────
if want_tier 2; then
  echo "---- tier2 ----" | tee -a "$SUMMARY"
  run_case t2_compressed 0 -sS --compressed -o /Volumes/linux/out/t2-z.html http://example.com/
  run_case t2_cookie_jar 0 -sS -c /Volumes/linux/out/t2-cj.txt -b /Volumes/linux/out/t2-cj.txt -o /Volumes/linux/out/t2-ck.html http://example.com/
  run_case t2_range 0 -sS -r 0-100 -o /Volumes/linux/out/t2-range.bin http://example.com/
  run_case t2_referer 0 -sS -e "http://example.com/" -o /Volumes/linux/out/t2-ref.html http://example.com/
  run_case t2_retry 0 -sS --retry 2 --retry-delay 0 -o /Volumes/linux/out/t2-retry.html http://example.com/
  run_case t2_json_post 0 -sS --json "{\"k\":1}" -o /Volumes/linux/out/t2-json.html http://example.com/
  run_case t2_http2 0 -sS --http2 -o /Volumes/linux/out/t2-h2.html https://example.com/
  run_case t2_proto_http 0 -sS --proto "=http" -o /Volumes/linux/out/t2-proto.html http://example.com/
  run_case t2_remote_name 0 -sS -O --output-dir /Volumes/linux/out http://example.com/
  run_case t2_limit_rate 0 -sS --limit-rate 1M -o /Volumes/linux/out/t2-rate.html http://example.com/
  run_case t2_no_progress 0 -sS --no-progress-meter -o /Volumes/linux/out/t2-np.html http://example.com/
  run_case t2_etag_save 0 -sS --etag-save /Volumes/linux/out/t2-etag.txt -o /Volumes/linux/out/t2-etag-body.html http://example.com/
fi

# ── tier3: output / FS / url helpers / trace ───────────────────────────────
if want_tier 3; then
  echo "---- tier3 ----" | tee -a "$SUMMARY"
  run_case t3_out_null 0 -sS --out-null http://example.com/
  run_case t3_url_flag 0 -sS --url http://example.com/ -o /Volumes/linux/out/t3-url.html
  run_case t3_url_query 0 -sS --url-query "kh=1" -o /Volumes/linux/out/t3-uq.html http://example.com/
  run_case t3_remote_time 0 -sS -R -o /Volumes/linux/out/t3-rt.html http://example.com/
  run_case t3_create_file_mode 0 -sS --create-file-mode 0644 -o /Volumes/linux/out/t3-mode.html http://example.com/
  # --no-clobber + -o: if the target exists, curl does NOT fail — it writes
  # "name.1", "name.2", … (see curl man). O_EXCL on the original name must
  # return EEXIST (not ENOENT) so curl can pick the next suffix.
  rm -f /out/t3-noclobber-new.html /out/t3-noclobber-new.html.[0-9]*
  run_case t3_no_clobber_new 0 -sS --no-clobber \
    -o /Volumes/linux/out/t3-noclobber-new.html http://example.com/
  # Existing target: original stays "seed", body lands in t3-exist.html.1
  echo seed >/out/t3-exist.html
  rm -f /out/t3-exist.html.[0-9]*
  run_case t3_no_clobber_exists 0 -sS --no-clobber \
    -o /Volumes/linux/out/t3-exist.html http://example.com/
  # Soft check that seed was preserved (non-fatal if layout differs).
  if [[ -f /out/t3-exist.html ]] && ! grep -q seed /out/t3-exist.html 2>/dev/null; then
    echo "FAIL  t3_no_clobber_seed  (original overwritten)" | tee -a "$SUMMARY"
    fail=$((fail + 1))
  else
    echo "PASS  t3_no_clobber_seed  (original kept or .N written)" | tee -a "$SUMMARY"
    pass=$((pass + 1))
  fi
  run_case t3_skip_existing 0 -sS --skip-existing -o /Volumes/linux/out/t3-exist.html http://example.com/
  run_case t3_continue_at 0 -sS -C - -o /Volumes/linux/out/t3-cont.html http://example.com/
  run_case t3_remove_on_error nonzero -sS --remove-on-error -f -o /Volumes/linux/out/t3-roe.html http://example.com/no-such-kh-404
  run_case t3_stderr 0 -sS --stderr /Volumes/linux/out/t3-stderr.txt -o /Volumes/linux/out/t3-stderr-body.html http://example.com/
  run_case t3_write_out_rich 0 -sS -o /dev/null -w "code=%{http_code} size=%{size_download}\n" http://example.com/
  run_case t3_trace 0 -sS --trace /Volumes/linux/out/t3-trace.txt -o /Volumes/linux/out/t3-trace-body.html http://example.com/
  run_case t3_trace_ascii 0 -sS --trace-ascii /Volumes/linux/out/t3-trace-a.txt -o /Volumes/linux/out/t3-trace-a-body.html http://example.com/
  run_case t3_trace_time 0 -sS --trace-time -o /Volumes/linux/out/t3-tt.html http://example.com/
  run_case t3_trace_ids 0 -sS --trace-ids -v -o /Volumes/linux/out/t3-ti.html http://example.com/
  run_case t3_variable 0 -sS --variable "ua=kh-var" -A "{{ua}}" -o /Volumes/linux/out/t3-var.html http://example.com/
  run_case t3_data_urlencode 0 -sS --data-urlencode "q=hello world" -o /Volumes/linux/out/t3-due.html http://example.com/
  run_case t3_data_raw 0 -sS --data-raw "a=1" -o /Volumes/linux/out/t3-dr.html http://example.com/
  run_case t3_data_binary 0 -sS --data-binary "bin=1" -o /Volumes/linux/out/t3-db.html http://example.com/
  run_case t3_form_string 0 -sS --form-string "name=kh" -o /Volumes/linux/out/t3-fs.html http://example.com/
  run_case t3_junk_session 0 -sS -j -b /Volumes/linux/out/t2-cj.txt -o /Volumes/linux/out/t3-js.html http://example.com/
  run_case t3_globoff 0 -sS -g -o /Volumes/linux/out/t3-g.html "http://example.com/"
  run_case t3_styled 0 -sS --styled-output -i -o /Volumes/linux/out/t3-styled.html http://example.com/
  run_case t3_progress_bar 0 -sS -# -o /Volumes/linux/out/t3-bar.html http://example.com/
fi

# ── tier4: transfer control ────────────────────────────────────────────────
if want_tier 4; then
  echo "---- tier4 ----" | tee -a "$SUMMARY"
  run_case t4_max_redirs 0 -sS -L --max-redirs 5 -o /Volumes/linux/out/t4-mr.html http://example.com/
  run_case t4_post301 0 -sS -L --post301 -d x=1 -o /Volumes/linux/out/t4-p301.html http://example.com/
  run_case t4_post302 0 -sS -L --post302 -d x=1 -o /Volumes/linux/out/t4-p302.html http://example.com/
  run_case t4_post303 0 -sS -L --post303 -d x=1 -o /Volumes/linux/out/t4-p303.html http://example.com/
  run_case t4_proto_redir 0 -sS -L --proto-redir "=http,https" -o /Volumes/linux/out/t4-pr.html http://example.com/
  run_case t4_path_as_is 0 -sS --path-as-is -o /Volumes/linux/out/t4-pai.html "http://example.com/./"
  run_case t4_raw 0 -sS --raw -o /Volumes/linux/out/t4-raw.html http://example.com/
  run_case t4_ignore_cl 0 -sS --ignore-content-length -o /Volumes/linux/out/t4-icl.html http://example.com/
  run_case t4_fail_with_body nonzero -sS --fail-with-body -o /Volumes/linux/out/t4-fwb.html http://example.com/no-such-kh-404
  run_case t4_fail_early 0 -sS --fail-early -o /Volumes/linux/out/t4-fe.html http://example.com/
  run_case t4_follow 0 -sS --follow -o /Volumes/linux/out/t4-follow.html http://example.com/
  run_case t4_http10 0 -sS --http1.0 -o /Volumes/linux/out/t4-10.html http://example.com/
  run_case t4_http09 0 -sS --http0.9 -o /Volumes/linux/out/t4-09.html http://example.com/
  run_case t4_tr_encoding 0 -sS --tr-encoding -o /Volumes/linux/out/t4-tr.html http://example.com/
  run_case t4_keepalive 0 -sS --keepalive-time 30 -o /Volumes/linux/out/t4-ka.html http://example.com/
  run_case t4_no_keepalive 0 -sS --no-keepalive -o /Volumes/linux/out/t4-nka.html http://example.com/
  run_case t4_tcp_nodelay 0 -sS --tcp-nodelay -o /Volumes/linux/out/t4-nd.html http://example.com/
  run_case t4_speed 0 -sS -Y 1 -y 30 -o /Volumes/linux/out/t4-sp.html http://example.com/
  run_case t4_max_filesize 0 -sS --max-filesize 10M -o /Volumes/linux/out/t4-mf.html http://example.com/
  run_case t4_happy_eyeballs 0 -sS --happy-eyeballs-timeout-ms 200 -o /Volumes/linux/out/t4-he.html http://example.com/
  run_case t4_disallow_user 0 -sS --disallow-username-in-url -o /Volumes/linux/out/t4-du.html http://example.com/
  run_case t4_request_target 0 -sS --request-target / -o /Volumes/linux/out/t4-rtgt.html http://example.com/
  run_case t4_proto_default 0 -sS --proto-default http -o /Volumes/linux/out/t4-pd.html example.com
  run_case t4_retry_all 0 -sS --retry 1 --retry-all-errors --retry-delay 0 -o /Volumes/linux/out/t4-ra.html http://example.com/
  run_case t4_retry_max_time 0 -sS --retry 1 --retry-max-time 5 -o /Volumes/linux/out/t4-rmt.html http://example.com/
  run_case t4_expect100 0 -sS --expect100-timeout 1 -d "x=1" -o /Volumes/linux/out/t4-e100.html http://example.com/
  run_case t4_keepalive_cnt 0 -sS --keepalive-cnt 3 -o /Volumes/linux/out/t4-kac.html http://example.com/
  run_case t4_no_buffer 0 -sS -N -o /Volumes/linux/out/t4-nb.html http://example.com/
fi

# ── tier5: TLS surface ─────────────────────────────────────────────────────
if want_tier 5; then
  echo "---- tier5 ----" | tee -a "$SUMMARY"
  run_case t5_tls12 0 -sS --tlsv1.2 -o /Volumes/linux/out/t5-12.html https://example.com/
  run_case t5_tls13 0 -sS --tlsv1.3 -o /Volumes/linux/out/t5-13.html https://example.com/
  run_case t5_tls_max 0 -sS --tls-max 1.3 -o /Volumes/linux/out/t5-max.html https://example.com/
  run_case t5_tlsv1 0 -sS -1 -o /Volumes/linux/out/t5-1.html https://example.com/
  run_case t5_ssl_reqd 0 -sS --ssl-reqd -o /Volumes/linux/out/t5-reqd.html https://example.com/
  run_case t5_no_alpn 0 -sS --no-alpn -o /Volumes/linux/out/t5-alpn.html https://example.com/
  run_case t5_ssl_allow_beast 0 -sS --ssl-allow-beast -o /Volumes/linux/out/t5-beast.html https://example.com/
  run_case t5_tls13_ciphers 0 -sS --tls13-ciphers "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256" -o /Volumes/linux/out/t5-c13.html https://example.com/
  run_case t5_curves 0 -sS --curves "X25519:P-256" -o /Volumes/linux/out/t5-curves.html https://example.com/
  run_case t5_ssl_sessions 0 -sS --ssl-sessions /Volumes/linux/out/t5-sess.db -o /Volumes/linux/out/t5-sess.html https://example.com/
  if [[ -n "${CA_PEM}" ]]; then
    run_case t5_cacert 0 -sS --cacert "${CA_PEM}" -o /Volumes/linux/out/t5-ca.html https://example.com/
  else
    echo "SKIP  t5_cacert  (no bottle CA)" | tee -a "$SUMMARY"
    skip=$((skip + 1))
  fi
  # Wrong pin must fail verify
  run_case t5_pinned_bad nonzero -sS --pinnedpubkey "sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" -o /dev/null https://example.com/
  run_case t5_tls_earlydata 0 -sS --tls-earlydata -o /Volumes/linux/out/t5-ed.html https://example.com/
  run_case t5_http2_prior 0 -sS --http2-prior-knowledge -o /Volumes/linux/out/t5-h2p.html https://example.com/
  # cert-status (OCSP staple) — may fail on sites without staple; allow either success or clean non-zero
  # Prefer success; if site has no OCSP staple curl may exit 91/35 — accept nonzero without missing-symbol.
  set +e
  "$KH" run curl -- -sS --cert-status -o /Volumes/linux/out/t5-ocsp.html https://example.com/ >/report/t5_cert_status.stdout 2>/report/t5_cert_status.stderr
  ocrc=$?
  set -e
  echo "$ocrc" >/report/t5_cert_status.exit
  if grep -q "missing symbol called:" /report/t5_cert_status.stderr 2>/dev/null; then
    echo "FAIL  t5_cert_status  (missing symbol)" | tee -a "$SUMMARY"
    fail=$((fail + 1))
  else
    echo "PASS  t5_cert_status  (rc=$ocrc soft)" | tee -a "$SUMMARY"
    pass=$((pass + 1))
  fi
fi

# ── tier6: auth soft + proxy negatives ─────────────────────────────────────
if want_tier 6; then
  echo "---- tier6 ----" | tee -a "$SUMMARY"
  # Server ignores Authorization → still 200
  run_case t6_user 0 -sS -u "kh:pass" -o /Volumes/linux/out/t6-u.html http://example.com/
  run_case t6_basic 0 -sS --basic -u "kh:pass" -o /Volumes/linux/out/t6-basic.html http://example.com/
  run_case t6_digest 0 -sS --digest -u "kh:pass" -o /Volumes/linux/out/t6-digest.html http://example.com/
  run_case t6_anyauth 0 -sS --anyauth -u "kh:pass" -o /Volumes/linux/out/t6-any.html http://example.com/
  run_case t6_oauth 0 -sS --oauth2-bearer "kh-token" -o /Volumes/linux/out/t6-oauth.html http://example.com/
  run_case t6_ntlm 0 -sS --ntlm -u "kh:pass" -o /Volumes/linux/out/t6-ntlm.html http://example.com/
  run_case t6_noproxy 0 -sS --noproxy "*" -o /Volumes/linux/out/t6-np.html http://example.com/
  # Dead proxy / socks → must fail cleanly (no crash)
  run_case t6_proxy_dead nonzero -sS -x "http://127.0.0.1:1" --connect-timeout 2 -o /dev/null http://example.com/
  run_case t6_socks5_dead nonzero -sS --socks5 "127.0.0.1:1" --connect-timeout 2 -o /dev/null http://example.com/
  run_case t6_socks4_dead nonzero -sS --socks4 "127.0.0.1:1" --connect-timeout 2 -o /dev/null http://example.com/
  run_case t6_socks5h_dead nonzero -sS --socks5-hostname "127.0.0.1:1" --connect-timeout 2 -o /dev/null http://example.com/
  run_case t6_proxy10_dead nonzero -sS --proxy1.0 "127.0.0.1:1" --connect-timeout 2 -o /dev/null http://example.com/
  run_case t6_proxy_basic nonzero -sS -x "http://127.0.0.1:1" --proxy-basic -U "u:p" --connect-timeout 2 -o /dev/null http://example.com/
  run_case t6_proxytunnel nonzero -sS -x "http://127.0.0.1:1" -p --connect-timeout 2 -o /dev/null http://example.com/
  run_case t6_netrc_optional 0 -sS --netrc-optional -o /Volumes/linux/out/t6-netrc.html http://example.com/
  run_case t6_location_trusted 0 -sS -L --location-trusted -o /Volumes/linux/out/t6-lt.html http://example.com/
  run_case t6_sasl_ir 0 -sS --sasl-ir -u "kh:pass" -o /Volumes/linux/out/t6-sasl.html http://example.com/
fi

# Soft case: any exit code is OK unless missing-symbol / crash.
run_soft() {
  local name="$1"
  shift
  local out_f="/report/${name}.stdout"
  local err_f="/report/${name}.stderr"
  local rc_f="/report/${name}.exit"
  set +e
  "$KH" run curl -- "$@" >"$out_f" 2>"$err_f"
  local rc=$?
  set -e
  echo "$rc" >"$rc_f"
  if grep -q "missing symbol called:" "$err_f" 2>/dev/null; then
    echo "FAIL  $name  (missing symbol rc=$rc)" | tee -a "$SUMMARY"
    grep "missing symbol called:" "$err_f" | head -5 | tee -a "$DETAIL" || true
    fail=$((fail + 1))
    return
  fi
  if grep -q "unknown BSD syscall #" "$err_f" 2>/dev/null; then
    echo "  note: unknown BSD in $name:" | tee -a "$DETAIL"
    grep "unknown BSD syscall #" "$err_f" | head -5 | tee -a "$DETAIL" || true
  fi
  echo "PASS  $name  (rc=$rc soft)" | tee -a "$SUMMARY"
  pass=$((pass + 1))
}

# ── tier7: multi-URL / parallel / resolve / connect-to / DNS ───────────────
if want_tier 7; then
  echo "---- tier7 ----" | tee -a "$SUMMARY"

  # Resolve example.com → IPv4 for --resolve (host-side; guest uses the pin).
  EX_IP=""
  if command -v getent >/dev/null 2>&1; then
    EX_IP="$(getent ahostsv4 example.com 2>/dev/null | awk "/STREAM/ {print \$1; exit}")"
  fi
  if [[ -z "${EX_IP}" ]] && command -v python3 >/dev/null 2>&1; then
    EX_IP="$(python3 - <<'PY'
import socket
try:
    print(socket.getaddrinfo("example.com", 80, socket.AF_INET)[0][4][0])
except Exception:
    pass
PY
)"
  fi
  if [[ -z "${EX_IP}" ]]; then
    EX_IP="93.184.216.34" # historical example.com; may be stale — soft if fail
  fi
  echo "note: example.com IPv4 pin=${EX_IP}" | tee -a "$DETAIL"

  # Serial multi-URL with --next
  run_case t7_next 0 -sS \
    -o /Volumes/linux/out/t7-next-a.html http://example.com/ \
    --next \
    -o /Volumes/linux/out/t7-next-b.html https://example.com/

  # Parallel transfers
  run_case t7_parallel 0 -sS -Z --parallel-max 2 \
    -o /Volumes/linux/out/t7-par-a.html http://example.com/ \
    -o /Volumes/linux/out/t7-par-b.html https://example.com/

  run_case t7_parallel_immediate 0 -sS -Z --parallel-immediate --parallel-max 2 \
    -o /Volumes/linux/out/t7-pi-a.html http://example.com/ \
    -o /Volumes/linux/out/t7-pi-b.html http://example.com/

  run_case t7_parallel_max_host 0 -sS -Z --parallel-max-host 2 \
    -o /Volumes/linux/out/t7-pmh-a.html http://example.com/ \
    -o /Volumes/linux/out/t7-pmh-b.html https://example.com/

  # --resolve pin host:port:addr
  run_case t7_resolve 0 -sS --resolve "example.com:80:${EX_IP}" \
    -o /Volumes/linux/out/t7-resolve.html http://example.com/

  run_case t7_resolve_https 0 -sS --resolve "example.com:443:${EX_IP}" \
    -o /Volumes/linux/out/t7-resolve-s.html https://example.com/

  # --connect-to HOST1:PORT1:HOST2:PORT2 (same host redirect of connect)
  run_case t7_connect_to 0 -sS --connect-to "example.com:80:example.com:80" \
    -o /Volumes/linux/out/t7-cto.html http://example.com/

  run_case t7_connect_to_https 0 -sS --connect-to "example.com:443:example.com:443" \
    -o /Volumes/linux/out/t7-cto-s.html https://example.com/

  # Rate / multiple URLs serial
  run_case t7_rate 0 -sS --rate 10/s \
    -o /Volumes/linux/out/t7-rate-a.html http://example.com/ \
    --next -o /Volumes/linux/out/t7-rate-b.html http://example.com/

  # DNS / interface knobs (c-ares paths)
  run_case t7_dns_ipv4_addr 0 -sS --dns-ipv4-addr "${EX_IP}" \
    -o /Volumes/linux/out/t7-dns4.html http://example.com/

  # local-port range (any free port)
  run_case t7_local_port 0 -sS --local-port 40000-50000 \
    -o /Volumes/linux/out/t7-lp.html http://example.com/

  # dual URLs without -Z (serial)
  run_case t7_two_urls 0 -sS \
    -o /Volumes/linux/out/t7-two-#1.html \
    http://example.com/ https://example.com/

  # remote-name-all: need a path segment (bare "/" yields empty name → guest SEGV)
  run_case t7_remote_name_all 0 -sS --remote-name-all --output-dir /Volumes/linux/out \
    http://example.com/index.html

  # config from file
  cat >/out/t7-curlrc.txt <<EOF
silent
show-error
output = /Volumes/linux/out/t7-config.html
url = http://example.com/
EOF
  run_case t7_config 0 -K /Volumes/linux/out/t7-curlrc.txt

  # --disable (.curlrc ignore) still works
  run_case t7_disable 0 -q -sS -o /Volumes/linux/out/t7-dis.html http://example.com/

  # IP-TOS (numeric DSCP; soft if host rejects)
  run_soft t7_ip_tos -sS --ip-tos 0 -o /Volumes/linux/out/t7-tos.html http://example.com/

  # --path-as-is already in t4; --proto already t2
  run_case t7_list_only 0 -sS -l -o /Volumes/linux/out/t7-lo.txt http://example.com/

  # multiple -H
  run_case t7_multi_header 0 -sS \
    -H "X-A: 1" -H "X-B: 2" -H "Accept: text/html" \
    -o /Volumes/linux/out/t7-mh.html http://example.com/
fi

# ── tier8: HTTP/3, DoH, unix sockets, HSTS/alt-svc, misc ───────────────────
if want_tier 8; then
  echo "---- tier8 ----" | tee -a "$SUMMARY"

  # HTTP/3 — binary has ngtcp2; may work or clean-fail depending on path/UDP.
  run_soft t8_http3 -sS --http3 --connect-timeout 15 \
    -o /Volumes/linux/out/t8-h3.html https://example.com/
  run_soft t8_http3_only -sS --http3-only --connect-timeout 15 \
    -o /Volumes/linux/out/t8-h3o.html https://example.com/

  # DoH
  run_soft t8_doh -sS --doh-url "https://cloudflare-dns.com/dns-query" --connect-timeout 20 \
    -o /Volumes/linux/out/t8-doh.html https://example.com/
  run_case t8_doh_insecure 0 -sS --doh-insecure --doh-url "https://cloudflare-dns.com/dns-query" \
    --connect-timeout 20 -o /Volumes/linux/out/t8-doh-k.html http://example.com/

  # Dead unix domain socket — clean non-zero
  run_case t8_unix_dead nonzero -sS --unix-socket /Volumes/linux/out/no-such-kh.sock \
    --connect-timeout 2 -o /dev/null http://localhost/
  run_case t8_abstract_unix_dead nonzero -sS --abstract-unix-socket kh-no-such-sock \
    --connect-timeout 2 -o /dev/null http://localhost/

  # HSTS / alt-svc cache files
  run_case t8_hsts 0 -sS --hsts /Volumes/linux/out/t8-hsts.txt \
    -o /Volumes/linux/out/t8-hsts-body.html https://example.com/
  run_case t8_alt_svc 0 -sS --alt-svc /Volumes/linux/out/t8-alt-svc.txt \
    -o /Volumes/linux/out/t8-alt.html https://example.com/

  # IPv6 preference (may still use v4 if only v4 available — soft)
  run_soft t8_ipv6 -sS -6 --connect-timeout 10 \
    -o /Volumes/linux/out/t8-v6.html http://example.com/

  # interface (often fails without named iface — soft)
  run_soft t8_interface -sS --interface lo --connect-timeout 5 \
    -o /Volumes/linux/out/t8-if.html http://example.com/

  # compressed-ssh N/A for http; dump-ca-embed
  run_case t8_dump_ca 0 -sS --dump-ca-embed -o /Volumes/linux/out/t8-ca-embed.pem

  # ECH config "false" / soft
  run_soft t8_ech -sS --ech false -o /Volumes/linux/out/t8-ech.html https://example.com/

  # --tcp-fastopen (uses connectx → connect fallback)
  run_soft t8_tcp_fastopen -sS --tcp-fastopen -o /Volumes/linux/out/t8-tfo.html http://example.com/

  # --mptcp soft
  run_soft t8_mptcp -sS --mptcp -o /Volumes/linux/out/t8-mptcp.html http://example.com/

  # --xattr (extended attrs — soft; may need fsetxattr)
  run_soft t8_xattr -sS --xattr -o /Volumes/linux/out/t8-xattr.html http://example.com/

  # --libcurl code gen
  run_case t8_libcurl 0 -sS --libcurl /Volumes/linux/out/t8-libcurl.c \
    -o /Volumes/linux/out/t8-lc.html http://example.com/

  # --engine list (OpenSSL engines) — often empty/error soft
  run_soft t8_engine -sS --engine list -o /dev/null http://example.com/

  # suppress-connect-headers with dead proxy
  run_case t8_suppress_connect nonzero -sS -x "http://127.0.0.1:1" -p \
    --suppress-connect-headers --connect-timeout 2 -o /dev/null http://example.com/

  # --proxy-http2 / --proxy-insecure on dead proxy
  run_case t8_proxy_http2 nonzero -sS -x "http://127.0.0.1:1" --proxy-http2 \
    --connect-timeout 2 -o /dev/null http://example.com/

  # --negotiate soft (no SPNEGO server)
  run_soft t8_negotiate -sS --negotiate -u : -o /Volumes/linux/out/t8-neg.html http://example.com/

  # --aws-sigv4 soft (no real AWS)
  run_soft t8_aws -sS --aws-sigv4 "aws:amz:us-east-1:s3" -u "AKID:SECRET" \
    -o /Volumes/linux/out/t8-aws.html http://example.com/

  # --krb soft
  run_soft t8_krb -sS --krb clear -o /Volumes/linux/out/t8-krb.html http://example.com/

  # --use-ascii
  run_case t8_use_ascii 0 -sS -B -o /Volumes/linux/out/t8-ascii.html http://example.com/

  # --crlf with POST body (avoid bash $'...' inside outer single-quoted docker -c)
  printf "a\nb" >/out/t8-crlf-body.txt
  run_case t8_crlf 0 -sS --crlf -d @/Volumes/linux/out/t8-crlf-body.txt \
    -o /Volumes/linux/out/t8-crlf.html http://example.com/

  # --metalink: may reject non-metalink URL (soft)
  run_soft t8_metalink -sS --metalink -o /Volumes/linux/out/t8-ml.html http://example.com/
fi

# ── tier9: other protocols + upload + manual ───────────────────────────────
if want_tier 9; then
  echo "---- tier9 ----" | tee -a "$SUMMARY"

  # file:// against bottle/host path
  echo "kh-file-body" >/out/t9-src.txt
  run_case t9_file 0 -sS -o /Volumes/linux/out/t9-file-out.txt \
    file:///Volumes/linux/out/t9-src.txt

  # upload local file as POST body
  run_case t9_upload 0 -sS -T /Volumes/linux/out/t9-src.txt \
    -o /Volumes/linux/out/t9-up.html http://example.com/

  # FTP / FTPS / SFTP / SCP / SMTP / TELNET / TFTP / GOPHER / DICT — soft
  run_soft t9_ftp -sS --connect-timeout 8 -o /Volumes/linux/out/t9-ftp.bin \
    ftp://ftp.gnu.org/README
  run_soft t9_ftps -sS --connect-timeout 8 -k -o /dev/null \
    ftps://ftp.gnu.org/README
  run_soft t9_sftp -sS --connect-timeout 5 -o /dev/null \
    sftp://127.0.0.1/tmp/no-such-kh
  run_soft t9_scp -sS --connect-timeout 5 -o /dev/null \
    scp://127.0.0.1/tmp/no-such-kh
  run_soft t9_smtp -sS --connect-timeout 5 \
    --mail-from me@example.com --mail-rcpt you@example.com \
    -T /Volumes/linux/out/t9-src.txt smtp://127.0.0.1:1/
  run_soft t9_telnet -sS --connect-timeout 3 telnet://127.0.0.1:1
  run_soft t9_tftp -sS --connect-timeout 3 -o /dev/null tftp://127.0.0.1/x
  run_soft t9_gopher -sS --connect-timeout 5 -o /dev/null gopher://gopher.floodgap.com/
  run_soft t9_dict -sS --connect-timeout 5 -o /dev/null dict://dict.org/d:hello

  # websocket schemes (soft)
  run_soft t9_ws -sS --connect-timeout 5 -o /dev/null ws://echo.websocket.events/
  run_soft t9_wss -sS --connect-timeout 8 -o /dev/null wss://echo.websocket.events/

  # --manual is large; just prove it exits without missing-symbol
  run_soft t9_manual --manual

  # --proto enable list / disable exotic
  run_case t9_proto_all 0 -sS --proto "=http,https,file" \
    -o /Volumes/linux/out/t9-proto.html http://example.com/

  # --quote / --ftp-* soft against dead FTP
  run_soft t9_ftp_quote -sS --connect-timeout 5 -Q PWD ftp://127.0.0.1:1/
  run_soft t9_ftp_pasv -sS --connect-timeout 5 --ftp-pasv ftp://127.0.0.1:1/
  run_soft t9_ftp_create -sS --connect-timeout 5 --ftp-create-dirs \
    -T /Volumes/linux/out/t9-src.txt ftp://127.0.0.1:1/nope/x

  # --tftp-blksize / --tftp-no-options
  run_soft t9_tftp_opts -sS --connect-timeout 3 --tftp-blksize 512 --tftp-no-options \
    -o /dev/null tftp://127.0.0.1/x

  # IMAP / POP3 soft
  run_soft t9_imap -sS --connect-timeout 3 imap://127.0.0.1:1/
  run_soft t9_pop3 -sS --connect-timeout 3 pop3://127.0.0.1:1/

  # --append upload soft
  run_soft t9_append -sS -a -T /Volumes/linux/out/t9-src.txt \
    --connect-timeout 5 ftp://127.0.0.1:1/x

  # --use-ascii already t8; --crlf t8
  # --globoff already; --path-as-is already
fi

# ── tier10: live micro services + leftovers ────────────────────────────────
if want_tier 10; then
  echo "---- tier10 ----" | tee -a "$SUMMARY"

  # Tiny HTTP server on 127.0.0.1:18080 (python3 from image or skip)
  if command -v python3 >/dev/null 2>&1; then
    mkdir -p /out/t10-www
    echo "<html>kh-t10</html>" >/out/t10-www/index.html
    python3 - <<'PY' >/report/t10-http-server.log 2>&1 &
import http.server, socketserver, os
os.chdir("/out/t10-www")
socketserver.TCPServer.allow_reuse_address = True
with socketserver.TCPServer(("127.0.0.1", 18080), http.server.SimpleHTTPRequestHandler) as httpd:
    httpd.serve_forever()
PY
    HTTP_PID=$!
    sleep 0.4

    # Tiny CONNECT/HTTP proxy on 127.0.0.1:18081
    python3 - <<'PY' >/report/t10-proxy.log 2>&1 &
import socket, threading, select, sys

def handle(c):
    up = None
    try:
        data = c.recv(65536)
        if not data:
            c.close(); return
        line = data.split(b"\r\n", 1)[0].decode("latin1", "replace")
        parts = line.split()
        if len(parts) >= 2 and parts[0].upper() == "CONNECT":
            hostport = parts[1]
            host, _, port = hostport.partition(":")
            port = int(port or "443")
            up = socket.create_connection((host, port), timeout=10)
            c.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            sockets = [c, up]
            while True:
                r, _, x = select.select(sockets, [], sockets, 30)
                if x or not r:
                    break
                for s in r:
                    other = up if s is c else c
                    chunk = s.recv(65536)
                    if not chunk:
                        return
                    other.sendall(chunk)
        else:
            if len(parts) >= 2 and parts[1].startswith("http://"):
                from urllib.parse import urlparse
                u = urlparse(parts[1])
                host = u.hostname or "127.0.0.1"
                port = u.port or 80
                path = u.path or "/"
                if u.query:
                    path += "?" + u.query
                up = socket.create_connection((host, port), timeout=10)
                rest = data.split(b"\r\n", 1)[1] if b"\r\n" in data else b""
                req = f"GET {path} HTTP/1.1\r\n".encode() + rest
                if b"Host:" not in req and b"host:" not in req:
                    req = req.replace(b"\r\n\r\n", f"\r\nHost: {host}\r\n\r\n".encode(), 1)
                up.sendall(req)
                while True:
                    chunk = up.recv(65536)
                    if not chunk:
                        break
                    c.sendall(chunk)
            else:
                c.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
    except Exception:
        try:
            c.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
        except Exception:
            pass
    finally:
        try: c.close()
        except Exception: pass
        if up is not None:
            try: up.close()
            except Exception: pass

srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 18081))
srv.listen(32)
while True:
    c, _ = srv.accept()
    threading.Thread(target=handle, args=(c,), daemon=True).start()
PY
    PROXY_PID=$!
    sleep 0.4

    # Unix domain HTTP server on a short host path (Darwin sun_path + bottle
    # translation grows the buffer; keep guest path short for sa_len).
    rm -f /tmp/kh-t10.sock
    python3 - <<'PY' >/report/t10-unix.log 2>&1 &
import socket, os
path = "/tmp/kh-t10.sock"
try: os.unlink(path)
except FileNotFoundError: pass
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(path)
s.listen(8)
body = b"<html>unix-kh</html>"
resp = b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body
while True:
    c, _ = s.accept()
    try:
        c.recv(65536)
        c.sendall(resp)
    finally:
        c.close()
PY
    UNIX_PID=$!
    sleep 0.3

    run_case t10_local_http 0 -sS -o /Volumes/linux/out/t10-local.html \
      http://127.0.0.1:18080/
    run_case t10_proxy_http 0 -sS -x http://127.0.0.1:18081 \
      -o /Volumes/linux/out/t10-proxy.html http://127.0.0.1:18080/
    run_case t10_proxy_https 0 -sS -x http://127.0.0.1:18081 -p \
      --connect-timeout 15 -o /Volumes/linux/out/t10-proxy-s.html https://example.com/
    # Guest /Volumes/linux/tmp → host /tmp via bottle symlink.
    run_case t10_unix_live 0 -sS --unix-socket /Volumes/linux/tmp/kh-t10.sock \
      -o /Volumes/linux/out/t10-unix.html http://localhost/

    # Basic auth against local server (server ignores → 200 still ok)
    run_case t10_basic_local 0 -sS -u "user:pass" --basic \
      -o /Volumes/linux/out/t10-basic.html http://127.0.0.1:18080/

    kill "$HTTP_PID" "$PROXY_PID" "$UNIX_PID" 2>/dev/null || true
    wait "$HTTP_PID" "$PROXY_PID" "$UNIX_PID" 2>/dev/null || true
  else
    echo "SKIP  t10_local_*  (no python3)" | tee -a "$SUMMARY"
    skip=$((skip + 1))
  fi

  # DNS leftovers
  run_soft t10_dns_servers -sS --dns-servers 1.1.1.1 --connect-timeout 15 \
    -o /Volumes/linux/out/t10-dns.html https://example.com/
  run_soft t10_dns_iface -sS --dns-interface lo --connect-timeout 10 \
    -o /Volumes/linux/out/t10-dnsi.html http://example.com/
  run_soft t10_dns_ipv6 -sS --dns-ipv6-addr ::1 --connect-timeout 5 \
    -o /Volumes/linux/out/t10-dns6.html http://example.com/

  # Client cert soft (missing file → clean fail)
  run_case t10_cert_missing nonzero -sS --cert /Volumes/linux/out/no-cert.pem \
    --connect-timeout 5 -o /dev/null https://example.com/

  # --cacert already; --capath soft
  run_soft t10_capath -sS --capath /Volumes/linux/out --connect-timeout 10 \
    -o /Volumes/linux/out/t10-capath.html https://example.com/

  # --key alone may be ignored without --cert; soft either way
  run_soft t10_key_missing -sS --key /Volumes/linux/out/no-key.pem \
    --connect-timeout 5 -o /Volumes/linux/out/t10-key.html https://example.com/

  # --pinnedpubkey already negative; --cert-status soft already

  # --haproxy-protocol soft
  run_soft t10_haproxy -sS --haproxy-protocol --connect-timeout 5 \
    -o /dev/null http://127.0.0.1:1/

  # --proto-redir already; --location-trusted already

  # --netrc-file missing soft
  run_soft t10_netrc_file -sS --netrc-file /Volumes/linux/out/no-netrc \
    -o /Volumes/linux/out/t10-netrc.html http://example.com/

  # --config already; --disable already

  # --vlan-priority soft
  run_soft t10_vlan -sS --vlan-priority 3 -o /Volumes/linux/out/t10-vlan.html http://example.com/

  # --ipfs-gateway soft
  run_soft t10_ipfs -sS --ipfs-gateway https://example.com/ --connect-timeout 5 \
    -o /dev/null ipfs://QmInvalid

  # --knownhosts soft
  run_soft t10_knownhosts -sS --knownhosts /Volumes/linux/out/t10-kh \
    --connect-timeout 5 -o /dev/null sftp://127.0.0.1/x

  # --hostpubmd5 / sha soft
  run_soft t10_hostpub -sS --hostpubmd5 00000000000000000000000000000000 \
    --connect-timeout 5 -o /dev/null sftp://127.0.0.1/x

  # --proxy-ciphers etc already covered via dead proxy in t6/t8
fi

{
  echo
  echo "==== totals tiers=[${KH_CURL_TIERS}] ===="
  echo "pass=$pass fail=$fail skip=$skip"
} | tee -a "$SUMMARY"

echo "pass=$pass fail=$fail skip=$skip" > /report/totals.env
ls -lah /report | head -n 5 | sed "s/^/  /"
echo "  … (see /report for per-case logs)"
[[ "$fail" -eq 0 ]]
'

rc=$?
echo
echo "==> host report: $REPORT_DIR"
if [[ -f "$REPORT_DIR/summary.txt" ]]; then
  cat "$REPORT_DIR/summary.txt"
fi
if [[ -f "$REPORT_DIR/detail.log" ]] && [[ -s "$REPORT_DIR/detail.log" ]]; then
  echo
  echo "==> detail (failures / notes):"
  cat "$REPORT_DIR/detail.log"
fi
exit "$rc"
