#!/usr/bin/env bash
# Turns the demo container into a fresh, slightly careless Raspberry Pi:
# password SSH and root login on, the default pi account with a password.
# Runs inside the throwaway container only.
set -euo pipefail
mkdir -p /etc/ssh /etc/pisentry/rules.d /var/lib/pisentry /etc/cron.d
cat >/etc/ssh/sshd_config <<'CONF'
Include /etc/ssh/sshd_config.d/*.conf
PermitRootLogin yes
PasswordAuthentication yes
KbdInteractiveAuthentication no
UsePAM yes
CONF
grep -q '^pi:' /etc/passwd || echo 'pi:x:1000:1000:,,,:/home/pi:/bin/bash' >>/etc/passwd
grep -q '^pi:' /etc/shadow || echo 'pi:$y$j9T$demo$notarealhashjustademonstrationvalue:20000:0:99999:7:::' >>/etc/shadow
: >/var/log/auth.log
: >/var/log/kern.log
