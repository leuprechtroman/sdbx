package linux

import "testing"

func eval(t *testing.T, arch string, s SeccompSpec, name string, args ...uint64) uint32 {
	t.Helper()
	prog, err := BuildFilter(arch, s)
	if err != nil {
		t.Fatal(err)
	}
	tbl := Tables[arch]
	nr, ok := tbl.Nr[name]
	if !ok {
		t.Fatalf("%s unbekannt", name)
	}
	d := Data{Nr: nr, Arch: tbl.Arch}
	copy(d.Args[:], args)
	v, err := Run(prog, d)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

const (
	eperm  = RetErrno | errEPERM
	enosys = RetErrno | errENOSYS
	eafno  = RetErrno | errEAFNOSUPPORT
)

func TestSeccompDefault(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64"} {
		s := SeccompSpec{Profile: "default"}
		cases := []struct {
			name string
			args []uint64
			want uint32
		}{
			{"mount", nil, eperm},
			{"unshare", nil, eperm},
			{"bpf", nil, eperm},
			{"io_uring_setup", nil, eperm},
			{"ptrace", nil, eperm},
			{"process_vm_readv", nil, eperm},
			{"ioctl", []uint64{0, TIOCSTI}, eperm},
			{"ioctl", []uint64{0, 0xffffffff00000000 | TIOCSTI}, eperm},
			{"ioctl", []uint64{0, TIOCLINUX}, eperm},
			{"ioctl", []uint64{0, 0x5401}, RetAllow}, // TCGETS
			{"socket", []uint64{afPacket, sockRaw, 0}, eperm},
			{"socket", []uint64{afInet, sockStream, 0}, RetAllow},
			{"socket", []uint64{afInet, sockStream | 0x80000, 0}, RetAllow}, // SOCK_CLOEXEC
			{"socket", []uint64{afInet, sockRaw, 1}, eperm},
			{"socket", []uint64{afInet6, sockDgram, 0}, RetAllow},
			{"socket", []uint64{afUnix, sockStream, 0}, RetAllow},
			{"socket", []uint64{afNetlink, sockRaw, netlinkRoute}, RetAllow},
			{"socket", []uint64{afNetlink, sockRaw, 9}, eperm}, // NETLINK_AUDIT
			{"clone", []uint64{0x01200011}, RetAllow},          // fork-ähnlich
			{"clone", []uint64{0x10000000}, eperm},             // CLONE_NEWUSER
			{"clone", []uint64{0x40000000}, eperm},             // CLONE_NEWNET
			{"clone3", nil, enosys},
		}
		for _, c := range cases {
			if got := eval(t, arch, s, c.name, c.args...); got != c.want {
				t.Errorf("%s %s%v: %#x, erwartet %#x", arch, c.name, c.args, got, c.want)
			}
		}
	}
}

func TestSeccompArchAndX32(t *testing.T) {
	prog, _ := BuildFilter("amd64", SeccompSpec{})
	if v, _ := Run(prog, Data{Nr: 1, Arch: auditArchAArch64}); v != RetKillProcess {
		t.Errorf("fremde Architektur: %#x", v)
	}
	if v, _ := Run(prog, Data{Nr: 0x40000000 + 1, Arch: auditArchX86_64}); v != eperm {
		t.Errorf("x32-ABI: %#x", v)
	}
	if v, _ := Run(prog, Data{Nr: 0, Arch: auditArchX86_64}); v != RetAllow {
		t.Errorf("read: %#x", v)
	}
}

func TestSeccompVariants(t *testing.T) {
	if got := eval(t, "amd64", SeccompSpec{AllowPtrace: true}, "ptrace"); got != RetAllow {
		t.Errorf("allow_ptrace: %#x", got)
	}
	if got := eval(t, "amd64", SeccompSpec{BlockUDP: true}, "socket", afInet, sockDgram, 0); got != eperm {
		t.Errorf("BlockUDP: %#x", got)
	}
	if got := eval(t, "amd64", SeccompSpec{BlockUDP: true}, "socket", afUnix, sockDgram, 0); got != RetAllow {
		t.Errorf("BlockUDP darf Unix-Datagramme nicht treffen: %#x", got)
	}
	if got := eval(t, "amd64", SeccompSpec{BlockInet: true}, "socket", afInet, sockStream, 0); got != eafno {
		t.Errorf("BlockInet: %#x", got)
	}
	strict := SeccompSpec{Profile: "strict"}
	if got := eval(t, "amd64", strict, "personality"); got != eperm {
		t.Errorf("strict personality: %#x", got)
	}
	if got := eval(t, "amd64", strict, "socket", afInet6, sockDgram, 0); got != eperm {
		t.Errorf("strict UDP: %#x", got)
	}
	if got := eval(t, "amd64", strict, "socket", 38, 1, 0); got != eafno { // AF_ALG
		t.Errorf("strict fremde Familie: %#x", got)
	}
	if got := eval(t, "amd64", strict, "socket", afUnix, sockStream, 0); got != RetAllow {
		t.Errorf("strict Unix: %#x", got)
	}
}

func TestUnknownArch(t *testing.T) {
	if _, err := BuildFilter("mips", SeccompSpec{}); err == nil {
		t.Fatal("unbekannte Architektur")
	}
}
