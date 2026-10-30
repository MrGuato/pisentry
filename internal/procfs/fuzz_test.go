package procfs

import (
	"bytes"
	"strings"
	"testing"
)

// FuzzParseStat: /proc/<pid>/stat. comm is set by the process itself
// (prctl PR_SET_NAME) and can hold spaces and parentheses.
func FuzzParseStat(f *testing.F) {
	f.Add([]byte("1234 (xmrig) S 1 1234 1234 0 -1 4194304 100 0 0 0 5000 100 0 0 20 0 1 0 98112 1000000 100 18446744073709551615 1 1 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0\n"))
	f.Add([]byte("77 (a) b) c (d)) R 1 77 77 0 -1 0 0 0 0 0 1 1 0 0 20 0 1 0 5 0 0\n"))
	f.Add([]byte("5 () Z 0"))
	f.Add([]byte("x (y) S -1 -1 -1 -1 -1 -1 -1 -1 -1 -1 99999999999999999999 -1"))
	f.Add([]byte(")("))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := ParseStat(b)
		if err != nil {
			return
		}
		// comm is everything between the first '(' and the last ')'.
		if i, j := bytes.IndexByte(b, '('), bytes.LastIndexByte(b, ')'); i < 0 || j < i {
			t.Fatalf("accepted stat without (comm): %q -> %+v", b, p)
		}
	})
}

// FuzzParseNet: /proc/<pid>/net/{tcp,tcp6,udp,udp6} read from other
// network namespaces, including containers an attacker controls.
func FuzzParseNet(f *testing.F) {
	hdr := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	f.Add(hdr+"   0: 00000000:7A69 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0\n", "tcp")
	f.Add(hdr+"   1: 0200A8C0:115D 0200A8C0:D2F0 01 00000000:00000000 00:00000000 00000000  1000        0 999 1\n", "tcp")
	f.Add(hdr+"   0: 00000000000000000000000000000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4242 1\n", "tcp6")
	f.Add(hdr+"   0: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   101        0 777 2\n", "udp")
	f.Add(hdr+"   0: ZZZZ:QQ 1:2 GG\n   1:\n", "tcp")
	f.Add("", "udp6")
	f.Fuzz(func(t *testing.T, s, proto string) {
		socks, err := ParseNet(strings.NewReader(s), proto)
		if err != nil {
			return
		}
		if len(socks) > strings.Count(s, "\n")+1 {
			t.Fatalf("%d sockets from %d lines", len(socks), strings.Count(s, "\n")+1)
		}
		for _, k := range socks {
			if !k.Local.IsValid() {
				t.Fatalf("socket with invalid local address accepted: %+v", k)
			}
			_ = k.IsListener()
		}
	})
}
