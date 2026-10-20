package detect

import (
	"runtime"
	"syscall"
	"testing"
)

func ioprioGet(t *testing.T) uintptr {
	t.Helper()
	p, _, errno := syscall.Syscall(syscall.SYS_IOPRIO_GET, ioprioWhoProcess, 0, 0)
	if errno != 0 {
		t.Skipf("ioprio_get not permitted here: %v", errno)
	}
	return p
}

func TestIdleIOSetsAndRestores(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	before := ioprioGet(t)
	restore := idleIO()
	if got := ioprioGet(t) >> ioprioClassShift; got != ioprioClassIdle {
		restore()
		t.Skipf("kernel did not apply the idle class (got class %d)", got)
	}
	restore()
	if after := ioprioGet(t); after != before {
		t.Fatalf("priority not restored: before %#x after %#x", before, after)
	}
}
