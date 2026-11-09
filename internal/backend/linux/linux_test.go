package linux

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sdbx/internal/backend"
	"sdbx/internal/config"
	"sdbx/internal/netmatch"
	"sdbx/internal/policy"
)

// Bekannte Socket-Orte können Dateien sein (docker.sock): Sie dürfen nicht als Verzeichnis maskiert werden,
// sonst scheitert bwrap mit "Can't mkdir … Not a directory".
func TestHostFactsKnownSocketFiles(t *testing.T) {
	home, err := os.MkdirTemp("/tmp", "h") // kurz genug für Unix-Socket-Pfade
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(home)
	home, _ = filepath.EvalSymlinks(home)
	l, err := net.Listen("unix", filepath.Join(home, ".colima"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	os.MkdirAll(filepath.Join(home, ".gnupg"), 0o700)
	p := &policy.Policy{Platform: "linux", Workspace: filepath.Join(home, "proj"), Home: home, UID: os.Getuid(), PrivateTmp: true}
	f := HostFacts(p, &backend.Runtime{SdbxTmp: filepath.Join(home, "tmp")})
	sock, gnupg := filepath.Join(home, ".colima"), filepath.Join(home, ".gnupg")
	if !strings.Contains(strings.Join(f.Sockets, "\n")+"\n", sock+"\n") || strings.Contains(strings.Join(f.MaskDirs, "\n")+"\n", sock+"\n") {
		t.Errorf("Socket-Datei %s: Sockets=%v MaskDirs=%v", sock, f.Sockets, f.MaskDirs)
	}
	if !strings.Contains(strings.Join(f.MaskDirs, "\n")+"\n", gnupg+"\n") {
		t.Errorf("Verzeichnis %s fehlt in MaskDirs: %v", gnupg, f.MaskDirs)
	}
}

func basePolicy() *policy.Policy {
	o := config.Origin{Source: "test"}
	return &policy.Policy{
		Platform: "linux", Workspace: "/home/u/proj", Home: "/home/u", UID: 1000, SdbxTmp: "/tmp/sdbx-abc",
		FSDefault: "read", PrivateTmp: true, IsolatePids: true,
		Rules: []policy.Rule{
			{Kind: policy.KindWrite, Path: "/home/u/proj", Exists: true, IsDir: true, Origin: o},
			{Kind: policy.KindWrite, Path: "/tmp/sdbx-abc", Exists: true, IsDir: true, Origin: o},
			{Kind: policy.KindWrite, Path: "/tmp", Exists: true, IsDir: true, Origin: o},
			{Kind: policy.KindWrite, Path: "/home/u/.cache/x", Exists: true, IsDir: true, Origin: o},
			{Kind: policy.KindProtected, Path: "/home/u/proj/.git/hooks", Exists: true, IsDir: true, Origin: o},
			{Kind: policy.KindProtected, Path: "/home/u/proj/.envrc", Origin: o},
			{Kind: policy.KindDeny, Path: "/home/u/.ssh", Exists: true, IsDir: true, Except: []string{"/home/u/.ssh/known_hosts"}, Origin: o},
			{Kind: policy.KindDeny, Path: "/home/u/.netrc", Exists: true, Origin: o},
			{Kind: policy.KindDeny, Glob: "/home/u/proj/**/.env", Origin: o},
		},
		Net:     policy.NetPolicy{Mode: "proxy", Matcher: &netmatch.Matcher{}, Local: []int{5432}},
		Sockets: []policy.SocketRule{{Path: "/run/user/1000/allowed.sock"}},
		Linux:   policy.LinuxPolicy{Backend: "bwrap", Landlock: "auto", Seccomp: "default"},
	}
}

func fakeFacts() Facts {
	existing := map[string]bool{ // Pfad → Verzeichnis
		"/home/u/proj": true, "/home/u/.cache/x": true, "/home/u/proj/.git/hooks": true, "/home/u/.ssh": true,
		"/home/u/.netrc": false, "/home/u/.ssh/known_hosts": false, "/run/user/1000": true, "/run/user/1000/allowed.sock": false,
	}
	return Facts{
		Stat: func(p string) (bool, bool) { d, ok := existing[p]; return ok, d },
		ExpandGlob: func(g string) []string {
			if strings.HasSuffix(g, ".env") {
				return []string{"/home/u/proj/a/.env"}
			}
			return nil
		},
		Sockets:  []string{"/home/u/.docker/run/docker.sock"},
		MaskDirs: []string{"/run/user/1000"},
	}
}

func rt() *backend.Runtime {
	return &backend.Runtime{RunDir: "/tmp/sdbx-abc/.sdbx", SdbxTmp: "/tmp/sdbx-abc", SdbxExe: "/usr/local/bin/sdbx", Cwd: "/home/u/proj", ProxyPort: 3128, Argv: []string{"sh"}}
}

func indexOf(a []string, seq ...string) int {
outer:
	for i := 0; i+len(seq) <= len(a); i++ {
		for j, s := range seq {
			if a[i+j] != s {
				continue outer
			}
		}
		return i
	}
	return -1
}

func TestBuildArgs(t *testing.T) {
	p, r := basePolicy(), rt()
	l := NewLayout(p, r)
	args, _ := BuildArgs(p, r, fakeFacts(), l)
	must := [][]string{
		{"--unshare-net"}, {"--unshare-pid"}, {"--cap-drop", "ALL"}, {"--ro-bind", "/", "/"}, {"--dev", "/dev"}, {"--proc", "/proc"},
		{"--bind", "/tmp/sdbx-abc", "/tmp"},
		{"--bind", "/home/u/proj", "/home/u/proj"},
		{"--bind", "/home/u/.cache/x", "/home/u/.cache/x"},
		{"--ro-bind", "/home/u/proj/.git/hooks", "/home/u/proj/.git/hooks"},
		{"--tmpfs", "/home/u/.ssh"}, {"--ro-bind", "/home/u/.ssh/known_hosts", "/home/u/.ssh/known_hosts"}, {"--remount-ro", "/home/u/.ssh"},
		{"--ro-bind", "/dev/null", "/home/u/.netrc"},
		{"--ro-bind", "/dev/null", "/home/u/proj/a/.env"},
		{"--tmpfs", "/run/user/1000"}, {"--bind", "/run/user/1000/allowed.sock", "/run/user/1000/allowed.sock"},
		{"--ro-bind", "/dev/null", "/home/u/.docker/run/docker.sock"},
		{"--ro-bind", "/tmp/sdbx-abc/.sdbx", "/tmp/.sdbx"},
		{"--ro-bind", "/usr/local/bin/sdbx", "/tmp/.sdbx/sdbx"},
		{"--chdir", "/home/u/proj"},
		{"--", "/tmp/.sdbx/sdbx", "__init", "/tmp/.sdbx/init.json"},
	}
	for _, m := range must {
		if indexOf(args, m...) < 0 {
			t.Errorf("fehlt: %v\n%v", m, args)
		}
	}
	if indexOf(args, "--ro-bind", "/home/u/proj/.envrc", "/home/u/proj/.envrc") >= 0 {
		t.Error("nicht existierende geschützte Pfade dürfen nicht gebunden werden")
	}
	// Reihenfolge: Schreiben < Schutz < Sperren < Laufzeit
	iw := indexOf(args, "--bind", "/home/u/proj", "/home/u/proj")
	ip := indexOf(args, "--ro-bind", "/home/u/proj/.git/hooks", "/home/u/proj/.git/hooks")
	id := indexOf(args, "--tmpfs", "/home/u/.ssh")
	ir := indexOf(args, "--ro-bind", "/tmp/sdbx-abc/.sdbx", "/tmp/.sdbx")
	if !(iw < ip && ip < id && id < ir) {
		t.Errorf("Reihenfolge falsch: %d %d %d %d", iw, ip, id, ir)
	}
	if indexOf(args, "--bind", "/tmp", "/tmp") >= 0 {
		t.Error("privates /tmp darf das geteilte nicht einbinden")
	}
}

func TestBuildArgsVariants(t *testing.T) {
	p, r := basePolicy(), rt()
	p.PrivateTmp, p.IsolatePids, p.Net.Mode, p.FSDefault = false, false, "host", "deny"
	p.Rules = append(p.Rules, policy.Rule{Kind: policy.KindSystem, Path: "/usr", Exists: true, IsDir: true})
	l := NewLayout(p, r)
	args, _ := BuildArgs(p, r, fakeFacts(), l)
	for _, bad := range [][]string{{"--unshare-net"}, {"--unshare-pid"}, {"--ro-bind", "/", "/"}, {"--proc", "/proc"}} {
		if indexOf(args, bad...) >= 0 {
			t.Errorf("unerwartet: %v", bad)
		}
	}
	for _, m := range [][]string{{"--tmpfs", "/"}, {"--ro-bind-try", "/usr", "/usr"}, {"--ro-bind", "/proc", "/proc"}, {"--bind", "/tmp", "/tmp"},
		{"--ro-bind", "/tmp/sdbx-abc/.sdbx", "/tmp/sdbx-abc/.sdbx"}} {
		if indexOf(args, m...) < 0 {
			t.Errorf("fehlt: %v", m)
		}
	}
}

func TestInitSpec(t *testing.T) {
	p, r := basePolicy(), rt()
	p.Limits = policy.Limits{MaxOpenFiles: 256, MaxFileSize: 1 << 20, CPUTime: time.Minute, MaxProcesses: 100}
	l := NewLayout(p, r)
	s := BuildInitSpec(p, r, l, false, false)
	if len(s.Rlimits) != 4 {
		t.Errorf("Rlimits: %+v", s.Rlimits)
	}
	if s.Landlock == nil || s.Landlock.Read[0] != "/" || s.Landlock.RestrictNet {
		t.Errorf("Landlock: %+v", s.Landlock)
	}
	joined := strings.Join(s.Landlock.Write, ",")
	for _, w := range []string{"/home/u/proj", "/tmp", "/dev"} {
		if !strings.Contains(joined, w) {
			t.Errorf("Landlock-Schreibpfad %s fehlt: %s", w, joined)
		}
	}
	if len(s.Bridges) != 2 || s.Bridges[0] != "tcp:127.0.0.1:3128=unix:/tmp/.sdbx/net/proxy.sock" || !strings.Contains(s.Bridges[1], "local-5432.sock") {
		t.Errorf("Bridges: %v", s.Bridges)
	}
	if s.Seccomp == nil || s.Seccomp.BlockUDP {
		t.Errorf("seccomp im bwrap-Modus: %+v", s.Seccomp)
	}
	if s2 := BuildInitSpec(p, r, l, false, true); len(s2.Rlimits) != 3 {
		t.Errorf("mit cgroup kein RLIMIT_NPROC: %+v", s2.Rlimits)
	}
	p.Linux.Landlock, p.Linux.Seccomp = "off", "off"
	if s3 := BuildInitSpec(p, r, l, false, false); s3.Landlock != nil || s3.Seccomp != nil {
		t.Error("abgeschaltete Mechanismen")
	}
}

func TestInitSpecLandlockBackend(t *testing.T) {
	p, r := basePolicy(), rt()
	p.Linux.Backend = "landlock"
	p.Rules = p.Rules[:1]
	s := BuildInitSpec(p, r, NewLayout(p, r), true, false)
	if !s.Landlock.RestrictNet || s.Landlock.ConnectPorts[0] != 3128 || s.Landlock.Mode != "required" {
		t.Errorf("Landlock-Netz: %+v", s.Landlock)
	}
	if !s.Seccomp.BlockUDP || s.Seccomp.BlockInet {
		t.Errorf("seccomp: %+v", s.Seccomp)
	}
	if len(s.Bridges) != 0 {
		t.Error("ohne Netzwerk-Namespace keine Bridge")
	}
}

func TestEmulateDeny(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"a/secret", "a/keep", "b"} {
		os.MkdirAll(filepath.Join(root, d), 0o755)
	}
	os.WriteFile(filepath.Join(root, "a", "file"), nil, 0o644)
	got := EmulateDeny(root, []string{filepath.Join(root, "a", "secret")})
	joined := strings.Join(got, ",")
	for _, want := range []string{"a/keep", "a/file", root + "/b"} {
		if !strings.Contains(joined, want) {
			t.Errorf("%s fehlt: %v", want, got)
		}
	}
	if strings.Contains(joined, "secret") {
		t.Errorf("Sperre nicht ausgespart: %v", got)
	}
	if g := EmulateDeny(filepath.Join(root, "a", "secret", "x"), []string{filepath.Join(root, "a")}); g != nil {
		t.Errorf("Freigabe innerhalb einer Sperre: %v", g)
	}
	if g := EmulateDeny(filepath.Join(root, "b"), []string{filepath.Join(root, "a")}); len(g) != 1 {
		t.Errorf("unbetroffene Freigabe: %v", g)
	}
}

func TestScanSockets(t *testing.T) {
	// kurzer Pfad: sun_path ist auf macOS auf 104 Bytes begrenzt, t.TempDir() ist dort zu lang
	root, err := os.MkdirTemp("", "s")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	home := filepath.Join(root, "home")
	ws := filepath.Join(home, "proj")
	os.MkdirAll(filepath.Join(home, ".config", "tool"), 0o755)
	os.MkdirAll(filepath.Join(home, "node_modules"), 0o755)
	os.MkdirAll(ws, 0o755)
	mk := func(p string) {
		l, err := net.Listen("unix", p)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { l.Close() })
	}
	mk(filepath.Join(home, ".config", "tool", "agent.sock"))
	mk(filepath.Join(home, ".obsidian.sock"))
	mk(filepath.Join(ws, "dev.sock"))
	mk(filepath.Join(home, "node_modules", "x.sock"))
	res := ScanSockets(ScanOptions{Home: home, Skip: []string{ws}})
	joined := strings.Join(res.Sockets, ",")
	if !strings.Contains(joined, "agent.sock") || !strings.Contains(joined, ".obsidian.sock") {
		t.Errorf("Sockets im Home nicht gefunden: %v", res.Sockets)
	}
	if strings.Contains(joined, "dev.sock") || strings.Contains(joined, "node_modules") {
		t.Errorf("Workspace bzw. node_modules hätten übersprungen werden müssen: %v", res.Sockets)
	}
}
