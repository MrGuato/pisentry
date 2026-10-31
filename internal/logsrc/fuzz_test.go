package logsrc

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/MrGuato/pisentry/internal/metrics"
)

// Seeds are the lines the attack simulation writes (scripts/sim-container/sim.sh)
// plus the formats real hosts produce.
var syslogSeeds = []string{
	"Oct 30 02:01:18 pi-sim sshd: Failed password for root from 203.0.113.66 port 41001 ssh2",
	"Oct 30 02:01:18 pi-sim sshd: Accepted password for root from 203.0.113.66 port 41999 ssh2",
	"Oct 30 02:01:18 pi-sim sudo:   mallory : user NOT in sudoers ; TTY=pts/9 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash",
	"Oct 30 02:01:18 pi-sim kernel: [UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.23 DST=192.0.2.10 PROTO=TCP SPT=55555 DPT=22 SYN",
	"2026-10-15T10:00:00.123456-04:00 kubepi sshd[1234]: Invalid user admin from 203.0.113.9 port 50000",
	"Oct  5 09:03:01 kubepi sshd-session[99]: Connection closed by authenticating user root 203.0.113.9 port 2 [preauth]",
	"Oct 30 02:01:18 host sshd[1]:",
	"Oct 30 02:01:18 host \x1b[2Jsshd: \u202eevil",
	"",
}

// FuzzParseSyslog: any line from a log file a local user can write to.
func FuzzParseSyslog(f *testing.F) {
	for _, s := range syslogSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		l, ok := ParseSyslog(s)
		if !ok {
			if l != (Line{}) {
				t.Fatalf("rejected line returned data: %+v", l)
			}
			return
		}
		if l.Ident == "" || strings.ContainsAny(l.Ident, " \t\n[:") {
			t.Fatalf("bad ident %q from %q", l.Ident, s)
		}
		if !strings.HasSuffix(s, l.Msg) {
			t.Fatalf("msg %q is not a suffix of the line %q", l.Msg, s)
		}
		if l.Kernel != (l.Ident == "kernel") || l.UID != -1 {
			t.Fatalf("kernel/uid wrong: %+v", l)
		}
	})
}

// FuzzReadJournal: `journalctl -o json` output. MESSAGE can be any bytes a
// local user logged, as a string or as a byte array.
func FuzzReadJournal(f *testing.F) {
	f.Add([]byte(`{"MESSAGE":"Failed password for root from 203.0.113.66 port 41001 ssh2","SYSLOG_IDENTIFIER":"sshd","_UID":"0","__REALTIME_TIMESTAMP":"1793325958000000"}` + "\n"))
	f.Add([]byte(`{"MESSAGE":[70,97,105,108,255,10],"SYSLOG_IDENTIFIER":"sshd","_UID":"1000"}` + "\n"))
	f.Add([]byte(`{"MESSAGE":"[UFW BLOCK] SRC=198.51.100.23 DPT=22","_TRANSPORT":"kernel"}` + "\n" + `{"MESSAGE":null}` + "\n"))
	f.Add([]byte(`{"MESSAGE":[999999,-1],"_UID":"-5","__REALTIME_TIMESTAMP":"99999999999999999999"}`))
	f.Add([]byte("not json\n{\n}\n\x00\xff"))
	f.Add(bytes.Repeat([]byte("A"), 70*1024))
	f.Fuzz(func(t *testing.T, b []byte) {
		out := make(chan Line)
		done := make(chan struct{})
		var lines []Line
		go func() {
			for l := range out {
				lines = append(lines, l)
			}
			close(done)
		}()
		readJournal(context.Background(), bytes.NewReader(b), out, metrics.NewSet())
		close(out)
		<-done
		if len(lines) > bytes.Count(b, []byte("\n"))+1 {
			t.Fatalf("%d lines from %d input lines", len(lines), bytes.Count(b, []byte("\n"))+1)
		}
		for _, l := range lines {
			if l.Time.IsZero() {
				t.Fatal("zero time")
			}
			if l.Kernel && l.Ident == "" {
				t.Fatal("kernel line without ident")
			}
			if len(l.Msg) > maxLine {
				t.Fatalf("message of %d bytes passed the %d cap", len(l.Msg), maxLine)
			}
			_ = utf8.ValidString(l.Msg) // invalid UTF-8 is allowed here; the engine sanitizes
		}
	})
}
