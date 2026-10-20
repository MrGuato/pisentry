//go:build !linux

package detect

// idleIO is a no-op where per-thread I/O priority does not exist.
func idleIO() (restore func()) { return func() {} }
