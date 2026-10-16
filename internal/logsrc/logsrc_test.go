package logsrc

import (
	"encoding/json"
	"testing"
)

func TestParseSyslog(t *testing.T) {
	cases := []struct{ in, ident, msg string }{
		{"Oct 15 10:01:02 kubepi sshd[1234]: Failed password for pi from 1.2.3.4 port 22 ssh2", "sshd", "Failed password for pi from 1.2.3.4 port 22 ssh2"},
		{"2026-10-15T10:01:02.123456-04:00 kubepi sshd-session[99]: Invalid user x from 1.2.3.4 port 5", "sshd-session", "Invalid user x from 1.2.3.4 port 5"},
		{"Oct  5 09:00:00 kubethink kernel: [UFW BLOCK] IN=eth0 SRC=1.2.3.4 DPT=23", "kernel", "[UFW BLOCK] IN=eth0 SRC=1.2.3.4 DPT=23"},
		{"Oct 15 10:01:02 kubepi sudo:      jon : TTY=pts/0 ; COMMAND=/bin/ls", "sudo", "     jon : TTY=pts/0 ; COMMAND=/bin/ls"},
	}
	for _, c := range cases {
		l, ok := ParseSyslog(c.in)
		if !ok || l.Ident != c.ident || l.Msg != c.msg {
			t.Errorf("%q -> %+v ok=%v", c.in, l, ok)
		}
	}
	if l, _ := ParseSyslog(cases[2].in); !l.Kernel {
		t.Error("kernel flag")
	}
}

func TestFromJournal(t *testing.T) {
	var e journalEntry
	_ = json.Unmarshal([]byte(`{"MESSAGE":"Accepted publickey for jon from 10.0.0.5 port 2 ssh2","SYSLOG_IDENTIFIER":"sshd-session","__REALTIME_TIMESTAMP":"1760522400000000"}`), &e)
	l, ok := FromJournal(e)
	if !ok || l.Ident != "sshd-session" || l.Time.Unix() != 1760522400 {
		t.Errorf("%+v", l)
	}
	// Non-UTF-8 messages arrive as byte arrays.
	e = journalEntry{}
	_ = json.Unmarshal([]byte(`{"MESSAGE":[83,82,67,61,49],"_TRANSPORT":"kernel"}`), &e)
	l, ok = FromJournal(e)
	if !ok || l.Msg != "SRC=1" || !l.Kernel || l.Ident != "kernel" {
		t.Errorf("%+v", l)
	}
}
