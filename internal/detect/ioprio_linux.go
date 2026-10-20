package detect

import (
	"runtime"
	"syscall"
)

// ioprio_set(2) constants from linux/ioprio.h.
const (
	ioprioWhoProcess = 1
	ioprioClassShift = 13
	ioprioClassIdle  = 3
)

// idleIO moves the calling goroutine's disk reads to the idle I/O class until
// the returned func runs. I/O priority is per thread on Linux, so the
// goroutine is locked to its thread and the old priority is restored before
// the thread goes back to the scheduler. Best effort: if the kernel refuses,
// the work just runs at normal priority.
func idleIO() (restore func()) {
	runtime.LockOSThread()
	old, _, errno := syscall.Syscall(syscall.SYS_IOPRIO_GET, ioprioWhoProcess, 0, 0)
	if errno != 0 {
		runtime.UnlockOSThread()
		return func() {}
	}
	if _, _, errno := syscall.Syscall(syscall.SYS_IOPRIO_SET, ioprioWhoProcess, 0, ioprioClassIdle<<ioprioClassShift); errno != 0 {
		runtime.UnlockOSThread()
		return func() {}
	}
	return func() {
		_, _, errno := syscall.Syscall(syscall.SYS_IOPRIO_SET, ioprioWhoProcess, 0, old)
		if errno == 0 {
			runtime.UnlockOSThread()
		}
		// If the old priority could not be restored, the thread stays locked
		// and exits with the goroutine instead of carrying idle I/O elsewhere.
	}
}
