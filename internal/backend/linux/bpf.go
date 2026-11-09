package linux

import (
	"encoding/binary"
	"fmt"
	"sort"
)

// BPF-Konstanten (linux/filter.h, linux/seccomp.h).
const (
	bpfLD   = 0x00
	bpfW    = 0x00
	bpfABS  = 0x20
	bpfALU  = 0x04
	bpfAND  = 0x50
	bpfJMP  = 0x05
	bpfJEQ  = 0x10
	bpfJGE  = 0x30
	bpfJSET = 0x40
	bpfK    = 0x00
	bpfRET  = 0x06

	RetKillProcess = 0x80000000
	RetErrno       = 0x00050000
	RetAllow       = 0x7fff0000

	errEPERM        = 1
	errENOSYS       = 38
	errEAFNOSUPPORT = 97

	auditArchX86_64  = 0xC000003E
	auditArchAArch64 = 0xC00000B7

	offNr   = 0
	offArch = 4
)

func offArg(i int) uint32 { return uint32(16 + 8*i) } // untere 32 Bit (little endian)

// Insn ist eine BPF-Instruktion (struct sock_filter).
type Insn struct {
	Code uint16
	Jt   uint8
	Jf   uint8
	K    uint32
}

// SyscallTable enthält die Nummern je Architektur.
type SyscallTable struct {
	Arch    uint32
	X32Base uint32 // 0 = keine x32-ABI
	Nr      map[string]uint32
}

// Tables für die unterstützten Architekturen.
var Tables = map[string]SyscallTable{
	"amd64": {Arch: auditArchX86_64, X32Base: 0x40000000, Nr: map[string]uint32{
		"ioctl": 16, "socket": 41, "clone": 56, "clone3": 435, "ptrace": 101, "unshare": 272, "setns": 308,
		"mount": 165, "umount2": 166, "pivot_root": 155, "chroot": 161, "bpf": 321, "perf_event_open": 298,
		"keyctl": 250, "add_key": 248, "request_key": 249, "init_module": 175, "finit_module": 313,
		"delete_module": 176, "kexec_load": 246, "kexec_file_load": 320, "reboot": 169, "swapon": 167,
		"swapoff": 168, "userfaultfd": 323, "io_uring_setup": 425, "io_uring_enter": 426, "io_uring_register": 427,
		"open_by_handle_at": 304, "name_to_handle_at": 303, "process_vm_readv": 310, "process_vm_writev": 311,
		"personality": 135, "acct": 163, "quotactl": 179, "syslog": 103, "vhangup": 153, "lookup_dcookie": 212,
		"uselib": 134, "fsopen": 430, "fsmount": 432, "move_mount": 429, "open_tree": 428, "fsconfig": 431,
		"mount_setattr": 442,
	}},
	"arm64": {Arch: auditArchAArch64, Nr: map[string]uint32{
		"ioctl": 29, "socket": 198, "clone": 220, "clone3": 435, "ptrace": 117, "unshare": 97, "setns": 268,
		"mount": 40, "umount2": 39, "pivot_root": 41, "chroot": 51, "bpf": 280, "perf_event_open": 241,
		"keyctl": 219, "add_key": 217, "request_key": 218, "init_module": 105, "finit_module": 273,
		"delete_module": 106, "kexec_load": 104, "kexec_file_load": 294, "reboot": 142, "swapon": 224,
		"swapoff": 225, "userfaultfd": 282, "io_uring_setup": 425, "io_uring_enter": 426, "io_uring_register": 427,
		"open_by_handle_at": 265, "name_to_handle_at": 264, "process_vm_readv": 270, "process_vm_writev": 271,
		"personality": 92, "acct": 89, "quotactl": 60, "syslog": 116, "vhangup": 58, "lookup_dcookie": 18,
		"fsopen": 430, "fsmount": 432, "move_mount": 429, "open_tree": 428, "fsconfig": 431, "mount_setattr": 442,
	}},
}

// Ioctl- und Socket-Konstanten.
const (
	TIOCSTI      = 0x5412
	TIOCLINUX    = 0x541C
	afUnix       = 1
	afInet       = 2
	afInet6      = 10
	afNetlink    = 16
	afPacket     = 17
	sockStream   = 1
	sockDgram    = 2
	sockRaw      = 3
	netlinkRoute = 0
	cloneNSFlags = 0x00020000 | 0x02000000 | 0x04000000 | 0x08000000 | 0x10000000 | 0x20000000 | 0x40000000 | 0x00000080
	sockTypeMask = 0xf
)

// SeccompSpec beschreibt das gewünschte Profil.
type SeccompSpec struct {
	Profile     string `json:"profile"` // default | strict
	AllowPtrace bool   `json:"allow_ptrace"`
	BlockInet   bool   `json:"block_inet"` // keine Internet-Sockets (network: none im Landlock-Modus)
	BlockUDP    bool   `json:"block_udp"`  // kein UDP (Landlock-Modus ohne Netzwerk-Namespace)
}

// Blockierte Syscalls (Spec 7.5).
var defaultBlocked = []string{
	"mount", "umount2", "pivot_root", "chroot", "unshare", "setns", "bpf", "perf_event_open",
	"keyctl", "add_key", "request_key", "init_module", "finit_module", "delete_module", "kexec_load",
	"kexec_file_load", "reboot", "swapon", "swapoff", "userfaultfd", "io_uring_setup", "io_uring_enter",
	"io_uring_register", "open_by_handle_at", "name_to_handle_at", "fsopen", "fsmount", "move_mount",
	"open_tree", "fsconfig", "mount_setattr",
}
var ptraceBlocked = []string{"ptrace", "process_vm_readv", "process_vm_writev"}
var strictBlocked = []string{"personality", "acct", "quotactl", "syslog", "vhangup", "lookup_dcookie", "uselib"}

// asm ist ein Assembler mit Sprungmarken.
type asm struct {
	insns  []Insn
	labels map[string]int
	fix    []fixup
}

type fixup struct {
	at     int
	jt, jf string
}

func (a *asm) emit(code uint16, k uint32) { a.insns = append(a.insns, Insn{Code: code, K: k}) }
func (a *asm) ldAbs(off uint32)           { a.emit(bpfLD|bpfW|bpfABS, off) }
func (a *asm) ret(v uint32)               { a.emit(bpfRET|bpfK, v) }
func (a *asm) and(v uint32)               { a.emit(bpfALU|bpfAND|bpfK, v) }
func (a *asm) label(name string)          { a.labels[name] = len(a.insns) }

// jump fügt einen bedingten Sprung ein; "" bedeutet nächste Instruktion.
func (a *asm) jump(op uint16, k uint32, jt, jf string) {
	a.fix = append(a.fix, fixup{at: len(a.insns), jt: jt, jf: jf})
	a.emit(bpfJMP|op|bpfK, k)
}

func (a *asm) assemble() ([]Insn, error) {
	for _, f := range a.fix {
		for _, side := range []struct {
			name string
			dst  *uint8
		}{{f.jt, &a.insns[f.at].Jt}, {f.jf, &a.insns[f.at].Jf}} {
			if side.name == "" {
				continue
			}
			target, ok := a.labels[side.name]
			if !ok {
				return nil, fmt.Errorf("Marke %s fehlt", side.name)
			}
			off := target - f.at - 1
			if off < 0 || off > 255 {
				return nil, fmt.Errorf("Sprung zu %s außerhalb des Bereichs (%d)", side.name, off)
			}
			*side.dst = uint8(off)
		}
	}
	return a.insns, nil
}

// BuildFilter erzeugt das seccomp-Programm für eine Architektur.
func BuildFilter(arch string, s SeccompSpec) ([]Insn, error) {
	t, ok := Tables[arch]
	if !ok {
		return nil, fmt.Errorf("seccomp: Architektur %s nicht unterstützt", arch)
	}
	a := &asm{labels: map[string]int{}}
	a.ldAbs(offArch)
	a.jump(bpfJEQ, t.Arch, "nr", "")
	a.ret(RetKillProcess)
	a.label("nr")
	a.ldAbs(offNr)
	if t.X32Base != 0 {
		a.jump(bpfJGE, t.X32Base, "eperm", "")
	}
	blocked := append([]string{}, defaultBlocked...)
	if !s.AllowPtrace {
		blocked = append(blocked, ptraceBlocked...)
	}
	if s.Profile == "strict" {
		blocked = append(blocked, strictBlocked...)
	}
	nrs := map[uint32]bool{}
	for _, name := range blocked {
		if nr, ok := t.Nr[name]; ok {
			nrs[nr] = true
		}
	}
	sorted := make([]int, 0, len(nrs))
	for nr := range nrs {
		sorted = append(sorted, int(nr))
	}
	sort.Ints(sorted)
	for _, nr := range sorted {
		a.jump(bpfJEQ, uint32(nr), "eperm", "")
	}
	a.jump(bpfJEQ, t.Nr["clone3"], "enosys", "")
	a.jump(bpfJEQ, t.Nr["ioctl"], "ioctl", "")
	a.jump(bpfJEQ, t.Nr["socket"], "socket", "")
	a.jump(bpfJEQ, t.Nr["clone"], "clone", "")
	a.ret(RetAllow)

	a.label("ioctl")
	a.ldAbs(offArg(1))
	a.jump(bpfJEQ, TIOCSTI, "eperm", "")
	a.jump(bpfJEQ, TIOCLINUX, "eperm", "")
	a.ret(RetAllow)

	a.label("clone")
	a.ldAbs(offArg(0))
	a.jump(bpfJSET, cloneNSFlags, "eperm", "")
	a.ret(RetAllow)

	a.label("socket")
	a.ldAbs(offArg(0))
	a.jump(bpfJEQ, afPacket, "eperm", "")
	a.jump(bpfJEQ, afNetlink, "netlink", "")
	a.jump(bpfJEQ, afInet, "inet", "")
	a.jump(bpfJEQ, afInet6, "inet", "")
	if s.Profile == "strict" {
		a.jump(bpfJEQ, afUnix, "allow", "")
		a.ret(RetErrno | errEAFNOSUPPORT)
	} else {
		a.ret(RetAllow)
	}
	a.label("netlink")
	a.ldAbs(offArg(2))
	a.jump(bpfJEQ, netlinkRoute, "allow", "eperm")
	a.label("inet")
	if s.BlockInet {
		a.ret(RetErrno | errEAFNOSUPPORT)
	} else {
		a.ldAbs(offArg(1))
		a.and(sockTypeMask)
		a.jump(bpfJEQ, sockRaw, "eperm", "")
		if s.BlockUDP {
			a.jump(bpfJEQ, sockDgram, "eperm", "")
		}
		if s.Profile == "strict" {
			a.jump(bpfJEQ, sockStream, "allow", "eperm")
		}
		a.ret(RetAllow)
	}
	a.label("allow")
	a.ret(RetAllow)
	a.label("enosys")
	a.ret(RetErrno | errENOSYS)
	a.label("eperm")
	a.ret(RetErrno | errEPERM)
	return a.assemble()
}

// Data simuliert struct seccomp_data für den Interpreter.
type Data struct {
	Nr   uint32
	Arch uint32
	Args [6]uint64
}

func (d Data) bytes() []byte {
	b := make([]byte, 64)
	binary.LittleEndian.PutUint32(b[0:], d.Nr)
	binary.LittleEndian.PutUint32(b[4:], d.Arch)
	for i, a := range d.Args {
		binary.LittleEndian.PutUint64(b[16+8*i:], a)
	}
	return b
}

// Run interpretiert ein Programm (nur die genutzten Instruktionen) – für Tests.
func Run(prog []Insn, d Data) (uint32, error) {
	mem := d.bytes()
	var acc uint32
	for pc := 0; pc < len(prog); pc++ {
		in := prog[pc]
		switch in.Code {
		case bpfLD | bpfW | bpfABS:
			acc = binary.LittleEndian.Uint32(mem[in.K:])
		case bpfALU | bpfAND | bpfK:
			acc &= in.K
		case bpfJMP | bpfJEQ | bpfK:
			if acc == in.K {
				pc += int(in.Jt)
			} else {
				pc += int(in.Jf)
			}
		case bpfJMP | bpfJGE | bpfK:
			if acc >= in.K {
				pc += int(in.Jt)
			} else {
				pc += int(in.Jf)
			}
		case bpfJMP | bpfJSET | bpfK:
			if acc&in.K != 0 {
				pc += int(in.Jt)
			} else {
				pc += int(in.Jf)
			}
		case bpfRET | bpfK:
			return in.K, nil
		default:
			return 0, fmt.Errorf("unbekannte Instruktion %#x", in.Code)
		}
	}
	return 0, fmt.Errorf("Programmende ohne Rückgabe")
}
