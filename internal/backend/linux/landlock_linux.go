//go:build linux

package linux

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

const (
	sysLandlockCreateRuleset = 444
	sysLandlockAddRule       = 445
	sysLandlockRestrictSelf  = 446

	landlockCreateRulesetVersion = 1
	ruleTypePathBeneath          = 1
	ruleTypeNetPort              = 2

	fsExecute    = 1 << 0
	fsWriteFile  = 1 << 1
	fsReadFile   = 1 << 2
	fsReadDir    = 1 << 3
	fsRemoveDir  = 1 << 4
	fsRemoveFile = 1 << 5
	fsMakeChar   = 1 << 6
	fsMakeDir    = 1 << 7
	fsMakeReg    = 1 << 8
	fsMakeSock   = 1 << 9
	fsMakeFifo   = 1 << 10
	fsMakeBlock  = 1 << 11
	fsMakeSym    = 1 << 12
	fsRefer      = 1 << 13 // ABI 2
	fsTruncate   = 1 << 14 // ABI 3
	fsIoctlDev   = 1 << 15 // ABI 5

	netConnectTCP = 1 << 1

	scopeAbstractUnix = 1 << 0 // ABI 6
	scopeSignal       = 1 << 1 // ABI 6

	prSetNoNewPrivs = 38
	oPath           = 0x200000 // O_PATH (amd64, arm64)
)

// LandlockABI liefert die vom Kernel unterstützte ABI-Version (0 = nicht verfügbar).
func LandlockABI() int {
	r, _, e := syscall.Syscall(sysLandlockCreateRuleset, 0, 0, landlockCreateRulesetVersion)
	if e != 0 {
		return 0
	}
	return int(r)
}

func handledFS(abi int) uint64 {
	v := uint64(fsExecute | fsWriteFile | fsReadFile | fsReadDir | fsRemoveDir | fsRemoveFile |
		fsMakeChar | fsMakeDir | fsMakeReg | fsMakeSock | fsMakeFifo | fsMakeBlock | fsMakeSym)
	if abi >= 2 {
		v |= fsRefer
	}
	if abi >= 3 {
		v |= fsTruncate
	}
	if abi >= 5 {
		v |= fsIoctlDev
	}
	return v
}

const fileRights = fsExecute | fsWriteFile | fsReadFile | fsTruncate | fsIoctlDev
const readRights = fsExecute | fsReadFile | fsReadDir

type rulesetAttr struct {
	FS     uint64
	Net    uint64
	Scoped uint64
}

type pathBeneathAttr struct {
	Allowed  uint64
	ParentFd int32
}

type netPortAttr struct {
	Allowed uint64
	Port    uint64
}

// NoNewPrivs setzt PR_SET_NO_NEW_PRIVS.
func NoNewPrivs() error {
	if _, _, e := syscall.RawSyscall6(syscall.SYS_PRCTL, prSetNoNewPrivs, 1, 0, 0, 0, 0); e != 0 {
		return e
	}
	return nil
}

// ApplyLandlock schränkt den aufrufenden Thread (und nach exec den Prozess) ein.
// Rückgabe: angewandte ABI-Version; 0 heißt, Landlock ist nicht verfügbar.
func ApplyLandlock(spec *LandlockSpec) (int, error) {
	abi := LandlockABI()
	if abi == 0 {
		return 0, nil
	}
	attr := rulesetAttr{FS: handledFS(abi)}
	size := uintptr(8)
	if spec.RestrictNet && abi >= 4 {
		attr.Net = netConnectTCP
		size = 16
	}
	if spec.Scope && abi >= 6 {
		attr.Scoped = scopeAbstractUnix | scopeSignal
		size = 24
	}
	fd, _, e := syscall.Syscall(sysLandlockCreateRuleset, uintptr(unsafe.Pointer(&attr)), size, 0)
	if e != 0 {
		return abi, fmt.Errorf("landlock_create_ruleset: %v", e)
	}
	defer syscall.Close(int(fd))
	all := attr.FS
	add := func(path string, rights uint64) error {
		f, err := os.OpenFile(path, oPath|syscall.O_CLOEXEC, 0)
		if err != nil {
			return nil // nicht vorhandene Pfade überspringen
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil {
			return nil
		}
		r := rights & all
		if !st.IsDir() {
			r &= fileRights
		}
		pb := pathBeneathAttr{Allowed: r, ParentFd: int32(f.Fd())}
		if _, _, e := syscall.Syscall6(sysLandlockAddRule, fd, ruleTypePathBeneath, uintptr(unsafe.Pointer(&pb)), 0, 0, 0); e != 0 {
			return fmt.Errorf("landlock_add_rule %s: %v", path, e)
		}
		return nil
	}
	for _, p := range spec.Read {
		if err := add(p, readRights); err != nil {
			return abi, err
		}
	}
	for _, p := range spec.Write {
		if err := add(p, all); err != nil {
			return abi, err
		}
	}
	for _, p := range spec.ReadWriteFile {
		if err := add(p, readRights|fsWriteFile|fsTruncate); err != nil {
			return abi, err
		}
	}
	if spec.RestrictNet && abi >= 4 {
		for _, port := range spec.ConnectPorts {
			np := netPortAttr{Allowed: netConnectTCP, Port: uint64(port)}
			if _, _, e := syscall.Syscall6(sysLandlockAddRule, fd, ruleTypeNetPort, uintptr(unsafe.Pointer(&np)), 0, 0, 0); e != 0 {
				return abi, fmt.Errorf("landlock_add_rule Port %d: %v", port, e)
			}
		}
	}
	if err := NoNewPrivs(); err != nil {
		return abi, fmt.Errorf("no_new_privs: %v", err)
	}
	if _, _, e := syscall.Syscall(sysLandlockRestrictSelf, fd, 0, 0); e != 0 {
		return abi, fmt.Errorf("landlock_restrict_self: %v", e)
	}
	return abi, nil
}
