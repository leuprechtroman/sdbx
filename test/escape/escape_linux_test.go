//go:build escape && linux

package escape

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestProtectedCreationReported(t *testing.T) {
	e := newEnv(t, "")
	r := e.run(nil, "run", "--", "sh", "-c", `echo 'export X=1' > .envrc; true`)
	expect(t, r, "geschützter Pfad")
}

// Unter Yama ptrace_scope ≥ 1 (Ubuntu-Default) scheitert das Attach auf fremde Prozesse schon ohne Sandbox;
// TestPtraceChild prüft seccomp unabhängig davon.
func TestPtraceBlocked(t *testing.T) {
	victim := exec.Command("sleep", "30")
	victim.Start()
	defer victim.Process.Kill()
	try := fmt.Sprintf(`import ctypes, os
libc = ctypes.CDLL(None, use_errno=True)
r = libc.ptrace(16, %d, 0, 0)  # PTRACE_ATTACH
print("ATTACH", r, os.strerror(ctypes.get_errno()))`, victim.Process.Pid)
	e := newEnv(t, "version: 1\nprocess:\n  isolate_pids: false\n")
	requireHost(t, e.hostPy(try), "ATTACH 0")
	expect(t, e.py(try), "ATTACH -1")
}

// Attach auf das eigene Kind erlaubt Yama (ptrace_scope 1) auch ohne Sandbox; blockieren muss seccomp.
func TestPtraceChild(t *testing.T) {
	const try = `import ctypes, os, time
libc = ctypes.CDLL(None, use_errno=True)
pid = os.fork()
if pid == 0:
    time.sleep(30)
    os._exit(0)
r = libc.ptrace(16, pid, 0, 0)  # PTRACE_ATTACH
print("ATTACH", r, os.strerror(ctypes.get_errno()))
os.kill(pid, 9)`
	e := newEnv(t, "")
	requireHost(t, e.hostPy(try), "ATTACH 0")
	expect(t, e.py(try), "ATTACH -1")
	e.config("version: 1\nprocess:\n  allow_ptrace: true\n")
	expect(t, e.py(try), "ATTACH 0")
}

func TestPIDNamespaceHidesHost(t *testing.T) {
	e := newEnv(t, "")
	r := e.sh(`ls /proc | grep -c '^[0-9]'`)
	if n := strings.TrimSpace(r.out); n == "" || len(n) > 2 {
		t.Errorf("zu viele Prozesse sichtbar: %s", r.out)
	}
}

func TestNoNewPrivs(t *testing.T) {
	e := newEnv(t, "")
	expect(t, e.sh(`grep NoNewPrivs /proc/self/status`), "NoNewPrivs:\t1")
}

// Ubuntu ab 24.04 sperrt unprivilegierte User Namespaces per AppArmor schon ohne Sandbox.
func TestNamespaceSyscallsBlocked(t *testing.T) {
	const try = `import ctypes, os
libc = ctypes.CDLL(None, use_errno=True)
print("UNSHARE", libc.unshare(0x10000000), os.strerror(ctypes.get_errno()))`
	e := newEnv(t, "")
	requireHost(t, e.hostPy(try), "UNSHARE 0")
	expect(t, e.py(try), "UNSHARE -1 Operation not permitted")
	e.config("version: 1\nlinux:\n  seccomp: \"off\"\n")
	expect(t, e.py(try), "UNSHARE 0")
}

func TestPrivateTmp(t *testing.T) {
	marker := filepath.Join("/tmp", fmt.Sprintf("sdbx-escape-marker-%d", time.Now().UnixNano()))
	os.WriteFile(marker, []byte("x"), 0o644)
	defer os.Remove(marker)
	e := newEnv(t, "")
	refuse(t, e.sh(`ls /tmp`), filepath.Base(marker))
	expect(t, e.sh(`echo $TMPDIR; touch /tmp/x && echo TMP-OK`), "TMP-OK")
}

func TestMaxProcesses(t *testing.T) {
	e := newEnv(t, "version: 1\nlimits:\n  max_processes: 40\n")
	// Kinder schlafen, damit sie gleichzeitig zählen; RLIMIT_NPROC bzw. TasksMax muss vor 200 greifen.
	r := e.py(`import os, time
n = 0
for i in range(200):
    try:
        if os.fork() == 0:
            time.sleep(5)
            os._exit(0)
        n += 1
    except OSError:
        break
print("GESTARTET", n)`)
	expect(t, r, "GESTARTET")
	if strings.Contains(r.out, "GESTARTET 200") {
		t.Errorf("max_processes: 40 nicht durchgesetzt: %s", r.out)
	}
}

func TestFailClosed(t *testing.T) {
	e := newEnv(t, "version: 1\nlimits:\n  max_memory: 1G\n")
	toolDir := filepath.Join(e.ws, "bin")
	if err := os.Mkdir(toolDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, tool := range []string{"bwrap", "sh"} {
		path, err := exec.LookPath(tool)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(path, filepath.Join(toolDir, tool)); err != nil {
			t.Fatal(err)
		}
	}
	extraEnv := []string{"PATH=" + toolDir}
	r := e.sh("echo GESTARTET", extraEnv...)
	if r.code != 126 || strings.Contains(r.out, "GESTARTET") {
		t.Errorf("ohne cgroup muss max_memory den Start verhindern: %d %s", r.code, r.err)
	}
	expect(t, r, "limits.max_memory")
	r = e.run(extraEnv, "run", "--degraded", "--", "sh", "-c", "echo GESTARTET")
	if r.code != 0 {
		t.Errorf("degraded muss den Start erlauben: %d %s", r.code, r.err)
	}
	expect(t, r, "GESTARTET")
}

// linux.backend: landlock (ohne bwrap) hält die Dateisystemgrenzen und meldet, was es nicht durchsetzen kann.
func TestLandlockBackend(t *testing.T) {
	e := newEnv(t, "version: 1\ndegraded: true\nlinux:\n  backend: landlock\n")
	outside := filepath.Join(filepath.Dir(e.home), "draussen")
	os.MkdirAll(outside, 0o755)
	r := e.run(nil, "run", "--", "sh", "-c", `echo x > ws.txt && echo WS-OK; echo y > '`+outside+`/f' && echo DRAUSSEN; cat "$HOME/.ssh/id_ed25519"; cat "$HOME/notes.txt"`)
	if strings.Contains(r.err, "Kernel ohne Landlock") {
		t.Skip("Kernel ohne Landlock")
	}
	expect(t, r, "WS-OK")
	expect(t, r, "lesbar")
	refuse(t, r, "DRAUSSEN")
	refuse(t, r, "GEHEIM-SSH")
	expect(t, r, "Geschützte Pfade")
	e.config(fmt.Sprintf("version: 1\ndegraded: true\nlinux:\n  backend: landlock\nfilesystem:\n  write: [%q]\n", outside))
	expect(t, e.sh(`echo y > '`+outside+`/f' && echo DRAUSSEN`), "DRAUSSEN")
}

func TestLearnMode(t *testing.T) {
	port := hostServer(t)
	e := newEnv(t, "version: 1\nnetwork:\n  allow_private: true\n")
	os.WriteFile(filepath.Join(e.home, "geheim.txt"), []byte("x"), 0o644)
	r := e.run(nil, "learn", "--", "python3", "-c", pyHTTP, "http://127.0.0.1:"+port+"/")
	expect(t, r, "STATUS 200")
	expect(t, r, "network:\n  allow:\n    - 127.0.0.1")
}
