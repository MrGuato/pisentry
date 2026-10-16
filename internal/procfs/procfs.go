// Package procfs reads the small slice of /proc that pisentry needs.
// It is stdlib-only and works the same on arm64, armv7 and amd64.
package procfs

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// TCP states from include/net/tcp_states.h.
const (
	TCPEstablished = 0x01
	TCPListen      = 0x0A
	UDPUnconn      = 0x07
)

// Socket is one row of /proc/<pid>/net/{tcp,tcp6,udp,udp6}.
type Socket struct {
	Proto  string // tcp, tcp6, udp, udp6
	Local  netip.AddrPort
	Remote netip.AddrPort
	State  uint8
	UID    int
	Inode  uint64
}

// IsListener reports a TCP LISTEN socket or an unconnected bound UDP socket.
func (s Socket) IsListener() bool {
	if strings.HasPrefix(s.Proto, "tcp") {
		return s.State == TCPListen
	}
	return s.State == UDPUnconn && s.Remote.Port() == 0
}

// ReadNet reads all four socket tables for a pid ("1", "self") or, if pid is
// empty, from procRoot/net.
func ReadNet(procRoot, pid string) ([]Socket, error) {
	base := filepath.Join(procRoot, "net")
	if pid != "" {
		base = filepath.Join(procRoot, pid, "net")
	}
	var out []Socket
	var firstErr error
	for _, proto := range []string{"tcp", "tcp6", "udp", "udp6"} {
		f, err := os.Open(filepath.Join(base, proto))
		if err != nil {
			if firstErr == nil && proto == "tcp" {
				firstErr = err
			}
			continue
		}
		socks, err := ParseNet(f, proto)
		f.Close()
		if err != nil {
			return nil, err
		}
		out = append(out, socks...)
	}
	if len(out) == 0 && firstErr != nil {
		return nil, firstErr
	}
	return out, nil
}

// ParseNet parses one /proc/net/{tcp,udp}[6] table.
func ParseNet(r io.Reader, proto string) ([]Socket, error) {
	var out []Socket
	sc := bufio.NewScanner(r)
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue
		}
		f := strings.Fields(sc.Text())
		if len(f) < 10 {
			continue
		}
		local, err := parseHexAddrPort(f[1])
		if err != nil {
			return nil, fmt.Errorf("%s local %q: %w", proto, f[1], err)
		}
		remote, err := parseHexAddrPort(f[2])
		if err != nil {
			return nil, fmt.Errorf("%s remote %q: %w", proto, f[2], err)
		}
		st, err := strconv.ParseUint(f[3], 16, 8)
		if err != nil {
			return nil, err
		}
		uid, _ := strconv.Atoi(f[7])
		inode, _ := strconv.ParseUint(f[9], 10, 64)
		out = append(out, Socket{Proto: proto, Local: local, Remote: remote, State: uint8(st), UID: uid, Inode: inode})
	}
	return out, sc.Err()
}

// parseHexAddrPort decodes "0100007F:1F90" or a 32-hex-digit IPv6 form.
// The kernel prints each 32-bit word of the address in host byte order;
// every architecture pisentry targets is little-endian.
func parseHexAddrPort(s string) (netip.AddrPort, error) {
	i := strings.IndexByte(s, ':')
	if i < 0 {
		return netip.AddrPort{}, fmt.Errorf("no port")
	}
	raw, err := hex.DecodeString(s[:i])
	if err != nil {
		return netip.AddrPort{}, err
	}
	port, err := strconv.ParseUint(s[i+1:], 16, 16)
	if err != nil {
		return netip.AddrPort{}, err
	}
	if len(raw) != 4 && len(raw) != 16 {
		return netip.AddrPort{}, fmt.Errorf("bad address length %d", len(raw))
	}
	for w := 0; w < len(raw); w += 4 {
		raw[w], raw[w+1], raw[w+2], raw[w+3] = raw[w+3], raw[w+2], raw[w+1], raw[w]
	}
	addr, _ := netip.AddrFromSlice(raw)
	return netip.AddrPortFrom(addr.Unmap(), uint16(port)), nil
}

// Proc is the subset of /proc/<pid>/stat pisentry uses.
type Proc struct {
	PID       int
	PPID      int
	Comm      string
	State     byte
	UTime     uint64
	STime     uint64
	StartTime uint64
}

// ListPIDs returns numeric directory names under procRoot.
func ListPIDs(procRoot string) ([]int, error) {
	d, err := os.Open(procRoot)
	if err != nil {
		return nil, err
	}
	defer d.Close()
	names, err := d.Readdirnames(-1)
	if err != nil {
		return nil, err
	}
	pids := make([]int, 0, len(names))
	for _, n := range names {
		if n[0] < '0' || n[0] > '9' {
			continue
		}
		if p, err := strconv.Atoi(n); err == nil {
			pids = append(pids, p)
		}
	}
	return pids, nil
}

// ReadStat parses /proc/<pid>/stat. comm may contain spaces and parens, so we
// split on the last ')'.
func ReadStat(procRoot string, pid int) (Proc, error) {
	b, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "stat"))
	if err != nil {
		return Proc{}, err
	}
	return ParseStat(b)
}

func ParseStat(b []byte) (Proc, error) {
	open := bytes.IndexByte(b, '(')
	cl := bytes.LastIndexByte(b, ')')
	if open < 0 || cl < open {
		return Proc{}, fmt.Errorf("malformed stat")
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b[:open])))
	p := Proc{PID: pid, Comm: string(b[open+1 : cl])}
	f := strings.Fields(string(b[cl+1:]))
	// f[0] is field 3 (state); field N is f[N-3].
	if len(f) < 20 {
		return p, fmt.Errorf("short stat")
	}
	p.State = f[0][0]
	p.PPID, _ = strconv.Atoi(f[1])
	p.UTime, _ = strconv.ParseUint(f[11], 10, 64)
	p.STime, _ = strconv.ParseUint(f[12], 10, 64)
	p.StartTime, _ = strconv.ParseUint(f[19], 10, 64)
	return p, nil
}

// Exe returns the /proc/<pid>/exe link target, "" for kernel threads or on error.
func Exe(procRoot string, pid int) string {
	s, _ := os.Readlink(filepath.Join(procRoot, strconv.Itoa(pid), "exe"))
	return s
}

// Cmdline returns argv joined by spaces, truncated to 512 bytes.
func Cmdline(procRoot string, pid int) string {
	b, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "cmdline"))
	if err != nil {
		return ""
	}
	if len(b) > 512 {
		b = b[:512]
	}
	return strings.TrimSpace(string(bytes.ReplaceAll(b, []byte{0}, []byte{' '})))
}

// UID returns the real uid from /proc/<pid>/status, -1 on error.
func UID(procRoot string, pid int) int {
	f, err := os.Open(filepath.Join(procRoot, strconv.Itoa(pid), "status"))
	if err != nil {
		return -1
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "Uid:") {
			fs := strings.Fields(line)
			if len(fs) > 1 {
				u, _ := strconv.Atoi(fs[1])
				return u
			}
		}
	}
	return -1
}

// NetNS returns the network namespace identity of a pid, e.g. "net:[4026531840]".
func NetNS(procRoot string, pid int) string {
	s, _ := os.Readlink(filepath.Join(procRoot, strconv.Itoa(pid), "ns", "net"))
	return s
}

// SocketInode returns the inode if fd is a socket, else 0.
func SocketInode(procRoot string, pid, fd int) uint64 {
	s, err := os.Readlink(filepath.Join(procRoot, strconv.Itoa(pid), "fd", strconv.Itoa(fd)))
	if err != nil {
		return 0
	}
	return parseSocketLink(s)
}

func parseSocketLink(s string) uint64 {
	if !strings.HasPrefix(s, "socket:[") || !strings.HasSuffix(s, "]") {
		return 0
	}
	n, _ := strconv.ParseUint(s[8:len(s)-1], 10, 64)
	return n
}

// SocketInodes returns every socket inode a process holds.
func SocketInodes(procRoot string, pid int) []uint64 {
	dir := filepath.Join(procRoot, strconv.Itoa(pid), "fd")
	d, err := os.Open(dir)
	if err != nil {
		return nil
	}
	names, _ := d.Readdirnames(-1)
	d.Close()
	var out []uint64
	for _, n := range names {
		s, err := os.Readlink(filepath.Join(dir, n))
		if err != nil {
			continue
		}
		if ino := parseSocketLink(s); ino != 0 {
			out = append(out, ino)
		}
	}
	return out
}

// Owner identifies the process holding a socket.
type Owner struct {
	PID  int
	Comm string
	Exe  string
}

// InodeOwners scans every process's fds and maps the wanted inodes to owners.
// It is O(processes x fds), so callers only use it when something is new.
func InodeOwners(procRoot string, want map[uint64]bool) map[uint64]Owner {
	out := map[uint64]Owner{}
	if len(want) == 0 {
		return out
	}
	pids, _ := ListPIDs(procRoot)
	for _, pid := range pids {
		for _, ino := range SocketInodes(procRoot, pid) {
			if want[ino] {
				if _, done := out[ino]; done {
					continue
				}
				st, _ := ReadStat(procRoot, pid)
				out[ino] = Owner{PID: pid, Comm: st.Comm, Exe: Exe(procRoot, pid)}
			}
		}
		if len(out) == len(want) {
			break
		}
	}
	return out
}

// AnyComm reports whether a process with one of the given comm names is running.
func AnyComm(procRoot string, names ...string) string {
	pids, _ := ListPIDs(procRoot)
	for _, pid := range pids {
		b, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "comm"))
		if err != nil {
			continue
		}
		c := strings.TrimSpace(string(b))
		for _, n := range names {
			if c == n {
				return c
			}
		}
	}
	return ""
}

// NumCPU counts "processor" lines in /proc/cpuinfo (host view, not cgroup).
func NumCPU(procRoot string) int {
	b, err := os.ReadFile(filepath.Join(procRoot, "cpuinfo"))
	if err != nil {
		return 1
	}
	n := bytes.Count(b, []byte("\nprocessor"))
	if bytes.HasPrefix(b, []byte("processor")) {
		n++
	}
	if n < 1 {
		n = 1
	}
	return n
}
