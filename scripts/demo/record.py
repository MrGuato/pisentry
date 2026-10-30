#!/usr/bin/env python3
"""Record the README demos as asciicast v2 files.

Every frame is real: this drives an interactive shell inside the demo
container through a pseudo-terminal, types the commands, and records exactly
what the terminal printed and when. render.py turns the .cast files into GIFs.

    make demo                       # builds, records and renders everything
    scripts/demo/record.py ./pisentry out/          # record only

Needs Docker and tmux on the host. The container is the throwaway demo host
from scripts/demo/Dockerfile, so nothing touches the machine you run it on.
"""
import argparse
import json
import os
import pty
import re
import select
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
CONTAINER = "pisentry-demo"
IMAGE = os.environ.get("DEMO_IMAGE", "pisentry-demo")
PS1 = r"\[\e[1;32m\]root@kubepi\[\e[0m\]:\[\e[1;34m\]\w\[\e[0m\]# "
ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[()][0-9A-B]|\x1b[=>]")


class Session:
    """A program running in a pty, with every byte it prints timestamped."""

    def __init__(self, argv, cols, rows, env=None):
        self.cols, self.rows = cols, rows
        self.events = []
        self.text = ""
        self.lock = threading.Lock()
        pid, fd = pty.fork()
        if pid == 0:
            os.environ.update(env or {})
            os.environ["TERM"] = "xterm-256color"
            os.environ["COLUMNS"], os.environ["LINES"] = str(cols), str(rows)
            os.execvp(argv[0], argv)
        self.pid, self.fd = pid, fd
        import fcntl, struct, termios
        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
        self.t0 = time.monotonic()
        self.alive = True
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self):
        while self.alive:
            r, _, _ = select.select([self.fd], [], [], 0.1)
            if not r:
                continue
            try:
                data = os.read(self.fd, 65536)
            except OSError:
                break
            if not data:
                break
            s = data.decode("utf-8", "replace")
            with self.lock:
                self.events.append([round(time.monotonic() - self.t0, 4), "o", s])
                self.text += ANSI.sub("", s)

    def mark(self):
        with self.lock:
            return len(self.text)

    def wait_for(self, pattern, since=0, timeout=120):
        rx = re.compile(pattern)
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            with self.lock:
                if rx.search(self.text, since):
                    return
            time.sleep(0.05)
        raise TimeoutError(f"timed out waiting for {pattern!r}; tail:\n{self.text[-800:]}")

    def send(self, s):
        os.write(self.fd, s.encode())

    def type(self, s, cps=28, enter=True):
        """Type like a person: steady keys, a little slower on spaces."""
        for ch in s:
            self.send(ch)
            time.sleep((1.0 / cps) * (1.8 if ch == " " else 1.0))
        if enter:
            time.sleep(0.35)
            self.send("\r")

    def pause(self, s):
        time.sleep(s)

    def save(self, path, title):
        self.alive = False
        with open(path, "w", encoding="utf-8") as f:
            f.write(json.dumps({"version": 2, "width": self.cols, "height": self.rows,
                                "title": title, "env": {"TERM": "xterm-256color"}}) + "\n")
            with self.lock:
                for ev in self.events:
                    f.write(json.dumps(ev) + "\n")
        try:
            os.kill(self.pid, 9)
            os.waitpid(self.pid, 0)
        except OSError:
            pass


def sh(*args, check=True, **kw):
    return subprocess.run(list(args), check=check, **kw)


def start_host(binary):
    """Start a fresh demo container that looks like a careless Pi."""
    sh("docker", "rm", "-f", CONTAINER, check=False, capture_output=True)
    sh("docker", "run", "-d", "--name", CONTAINER, "--hostname", "kubepi",
       "-v", f"{os.path.abspath(binary)}:/usr/local/bin/pisentry:ro",
       "-v", f"{HERE}:/demo:ro", IMAGE, "sleep", "infinity", capture_output=True)
    sh("docker", "exec", CONTAINER, "bash", "-c",
       "/demo/host-setup.sh && cp /demo/config.json /etc/pisentry/config.json"
       " && cp /demo/attack.sh /demo/stream.jq /root/")


def shell_argv():
    return ["docker", "exec", "-it", "-w", "/root", "-e", f"PS1={PS1}", "-e", "TERM=xterm-256color",
            CONTAINER, "bash", "--norc", "--noprofile"]


def prompt(s, since):
    s.wait_for(r"root@kubepi:\S*# $", since)


def run(s, cmd, wait=None, timeout=120, after=1.2):
    """Type cmd, then wait for its output (a regex) or the next prompt."""
    m = s.mark()
    s.type(cmd)
    if wait:
        s.wait_for(wait, m + len(cmd), timeout)
    else:
        s.wait_for(r"root@kubepi:\S*# $", m + len(cmd), timeout)
    s.pause(after)


def clean_screen(s):
    m = s.mark()
    s.send("clear\r")
    prompt(s, m)
    s.pause(0.3)


# --- scenes ------------------------------------------------------------------

def scene_audit(out):
    """One-shot posture audit of a fresh Pi, then the exit code."""
    s = Session(shell_argv(), 138, 38)
    prompt(s, 0)
    clean_screen(s)
    s.events.clear()
    s.t0 = time.monotonic()
    s.send("\r")
    s.pause(0.8)
    run(s, "pisentry audit", after=3.5)
    run(s, "echo \"exit code $?\"", after=2.5)
    s.save(os.path.join(out, "audit.cast"), "pisentry audit")


def scene_live(out):
    """tmux split: the agent's event stream below, the attacker above,
    then the ranked Top 10."""
    cols, rows = 118, 38
    sock = "pisentry-demo"
    sh("tmux", "-L", sock, "kill-server", check=False, capture_output=True)
    conf = os.path.join(out, "tmux.conf")
    with open(conf, "w") as f:
        f.write("\n".join([
            "set -g default-terminal 'xterm-256color'",
            "set -g status off",
            "set -g pane-border-status top",
            "set -g pane-border-lines heavy",
            "set -g pane-border-style 'fg=colour238'",
            "set -g pane-active-border-style 'fg=colour238'",
            "set -g pane-border-format '#[fg=colour245,bold] #{pane_title} '",
            "set -g escape-time 0",
        ]) + "\n")
    shell = " ".join(f"'{a}'" for a in shell_argv())
    s = Session(["tmux", "-L", sock, "-f", conf, "new-session", "-x", str(cols), "-y", str(rows), shell],
                cols, rows)
    s.wait_for(r"root@kubepi:\S*# $")
    tm = lambda *a: sh("tmux", "-L", sock, *a, capture_output=True)
    tm("split-window", "-v", "-l", "17", shell)
    tm("select-pane", "-t", "0", "-T", "attacker  (top)")
    tm("select-pane", "-t", "1", "-T", "pisentry agent  (bottom): events as JSON, one line each through jq")
    time.sleep(1.5)
    for p in ("0", "1"):
        tm("send-keys", "-t", p, "clear", "Enter")
    time.sleep(0.8)
    s.events.clear()
    s.t0 = time.monotonic()
    s.pause(1.0)

    # Bottom pane: start the agent.
    tm("select-pane", "-t", "1")
    m = s.mark()
    s.type("pisentry run 2>/dev/null | jq -r -f stream.jq")
    s.pause(5.0)  # learning period (3s) and first scans

    # Top pane: attack.
    tm("select-pane", "-t", "0")
    s.pause(0.6)
    m = s.mark()
    s.type("./attack.sh")
    s.wait_for(r"persisting with a cron drop-in", m, 120)
    s.wait_for(r"/etc/cron.d/0hourly-update created", 0, 60)
    # The agent saves state every 30s and the report reads the saved state.
    # Long pauses are collapsed when rendering, so this wait costs nothing.
    s.pause(34.0)

    # Top pane: the report.
    m = s.mark()
    s.type("clear; pisentry report -since 10m | head -13")
    s.wait_for(r"10\s+PS\d\d", m, 60)
    s.pause(6.0)
    s.save(os.path.join(out, "live.cast"), "pisentry: live detection")
    sh("tmux", "-L", sock, "kill-server", check=False, capture_output=True)


def scene_reload(out):
    """Push a local rule, see it fire, push a broken file, see it rejected."""
    s = Session(shell_argv(), 112, 30)
    prompt(s, 0)
    clean_screen(s)
    s.events.clear()
    s.t0 = time.monotonic()
    s.send("\r")
    s.pause(0.8)

    # Agent in the background of this shell: its rule log lines on stderr,
    # its events through jq, both on this terminal.
    m = s.mark()
    s.type("pisentry run 2> >(grep --line-buffered rules >&2) | jq -r -f stream.jq &")
    s.wait_for(r"rules loaded", m, 30)
    s.pause(4.0)
    s.send("\r")
    s.pause(0.8)
    run(s, "jq -c '.rules[0] | {id, level, match}' /demo/rules-local.json", after=2.0)
    m = s.mark()
    s.type("cp /demo/rules-local.json /etc/pisentry/rules.d/ && kill -HUP $(pidof pisentry)")
    s.wait_for(r"rules reloaded", m, 30)
    s.pause(2.0)
    s.send("\r")
    m = s.mark()
    s.type("echo \"$(date '+%b %e %T') kubepi sudo: eve : USER=root ; COMMAND=/usr/sbin/tcpdump -i eth0\" >>/var/log/auth.log")
    s.wait_for(r"LOCAL-SUDO-TCPDUMP\]", m, 30)
    s.pause(2.5)
    s.send("\r")
    m = s.mark()
    s.type("echo '{\"schema_version\": 1, \"rules\": [' >/etc/pisentry/rules.d/rules-local.json && kill -HUP $(pidof pisentry)")
    s.wait_for(r"Rule reload rejected", m, 30)
    s.pause(6.0)
    s.save(os.path.join(out, "reload.cast"), "pisentry: rule hot reload")


SCENES = {"audit": scene_audit, "live": scene_live, "reload": scene_reload}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("binary", help="linux pisentry binary for the container's arch")
    ap.add_argument("out", help="directory for the .cast files")
    ap.add_argument("--scene", action="append", choices=sorted(SCENES), help="record only these")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    for name in a.scene or ["audit", "live", "reload"]:
        print(f"[demo] recording {name}", file=sys.stderr)
        start_host(a.binary)  # every scene starts from a clean host
        try:
            SCENES[name](a.out)
        finally:
            sh("docker", "rm", "-f", CONTAINER, check=False, capture_output=True)
    print(f"[demo] casts in {a.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
