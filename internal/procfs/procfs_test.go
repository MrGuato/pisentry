package procfs

import (
	"strings"
	"testing"
)

const tcp4 = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 18342 1 0000000000000000 100 0 0 10 0
   1: 0100007F:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000   112        0 22180 1 0000000000000000 100 0 0 10 0
   2: 1501A8C0:0016 0B01A8C0:D431 01 00000000:00000000 02:00085A1F 00000000     0        0 99821 4 0000000000000000 20 4 30 10 -1
`

const tcp6 = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 31337 1 0000000000000000 100 0 0 10 0
   1: 00000000000000000000000001000000:0277 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4242 1 0000000000000000 100 0 0 10 0
   2: 0000000000000000FFFF00001501A8C0:0016 0000000000000000FFFF00000B01A8C0:D431 01 00000000:00000000 00:00000000 00000000     0        0 555 1 0000000000000000 100 0 0 10 0
`

func TestParseNetV4(t *testing.T) {
	s, err := ParseNet(strings.NewReader(tcp4), "tcp")
	if err != nil {
		t.Fatal(err)
	}
	if len(s) != 3 {
		t.Fatalf("got %d sockets", len(s))
	}
	if s[0].Local.String() != "0.0.0.0:22" || !s[0].IsListener() || s[0].Inode != 18342 {
		t.Errorf("row0 = %+v", s[0])
	}
	if s[1].Local.String() != "127.0.0.1:3306" || s[1].UID != 112 {
		t.Errorf("row1 = %+v", s[1])
	}
	if s[2].Local.String() != "192.168.1.21:22" || s[2].Remote.String() != "192.168.1.11:54321" || s[2].State != TCPEstablished {
		t.Errorf("row2 = %+v", s[2])
	}
}

func TestParseNetV6(t *testing.T) {
	s, err := ParseNet(strings.NewReader(tcp6), "tcp6")
	if err != nil {
		t.Fatal(err)
	}
	if s[0].Local.String() != "[::]:8080" {
		t.Errorf("any6 = %s", s[0].Local)
	}
	if !s[1].Local.Addr().IsLoopback() || s[1].Local.Port() != 631 {
		t.Errorf("loopback6 = %s", s[1].Local)
	}
	// v4-mapped addresses are unmapped so allowlists and classify work.
	if s[2].Remote.String() != "192.168.1.11:54321" {
		t.Errorf("mapped = %s", s[2].Remote)
	}
}

func TestUDPListener(t *testing.T) {
	udp := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
  1: 00000000:14E9 00000000:0000 07 00000000:00000000 00:00000000 00000000   108        0 1234 2 0000000000000000 0
  2: 1501A8C0:D2F0 08080808:0035 01 00000000:00000000 00:00000000 00000000     0        0 1235 2 0000000000000000 0
`
	s, err := ParseNet(strings.NewReader(udp), "udp")
	if err != nil {
		t.Fatal(err)
	}
	if !s[0].IsListener() || s[0].Local.Port() != 5353 {
		t.Errorf("mdns should be a listener: %+v", s[0])
	}
	if s[1].IsListener() {
		t.Errorf("connected udp is not a listener")
	}
}

func TestParseStat(t *testing.T) {
	p, err := ParseStat([]byte("4242 (evil (miner) x) R 1 4242 4242 0 -1 4194304 100 0 0 0 1500 250 0 0 20 0 4 0 987654 1000000 200 18446744073709551615"))
	if err != nil {
		t.Fatal(err)
	}
	if p.PID != 4242 || p.Comm != "evil (miner) x" || p.PPID != 1 || p.UTime != 1500 || p.STime != 250 || p.StartTime != 987654 || p.State != 'R' {
		t.Errorf("got %+v", p)
	}
}

func TestSocketLink(t *testing.T) {
	if parseSocketLink("socket:[12345]") != 12345 || parseSocketLink("pipe:[1]") != 0 || parseSocketLink("/dev/null") != 0 {
		t.Error("parseSocketLink")
	}
}
