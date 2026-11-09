//go:build linux

package linux

import (
	"fmt"
	"runtime"
	"syscall"
	"unsafe"
)

type sockFprog struct {
	Len    uint16
	_      [6]byte
	Filter *Insn
}

const (
	seccompSetModeFilter = 1
	seccompFlagTsync     = 1
)

func sysSeccomp() (uintptr, error) {
	switch runtime.GOARCH {
	case "amd64":
		return 317, nil
	case "arm64":
		return 277, nil
	}
	return 0, fmt.Errorf("seccomp: Architektur %s nicht unterstützt", runtime.GOARCH)
}

// InstallSeccomp lädt den Filter für alle Threads (TSYNC).
func InstallSeccomp(s *SeccompSpec) error {
	prog, err := BuildFilter(runtime.GOARCH, *s)
	if err != nil {
		return err
	}
	nr, err := sysSeccomp()
	if err != nil {
		return err
	}
	if err := NoNewPrivs(); err != nil {
		return err
	}
	fp := sockFprog{Len: uint16(len(prog)), Filter: &prog[0]}
	if _, _, e := syscall.RawSyscall(nr, seccompSetModeFilter, seccompFlagTsync, uintptr(unsafe.Pointer(&fp))); e != 0 {
		return fmt.Errorf("seccomp: %v", e)
	}
	runtime.KeepAlive(prog)
	return nil
}
