package supervisor

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"sdbx/internal/audit"
	"sdbx/internal/policy"
)

func TestExitCode(t *testing.T) {
	if c := exitCode(exec.Command("sh", "-c", "exit 3").Run(), nil); c != 3 {
		t.Errorf("Exit 3: %d", c)
	}
	if c := exitCode(exec.Command("sh", "-c", "kill -9 $$").Run(), nil); c != 137 {
		t.Errorf("Signal: %d", c)
	}
	if c := exitCode(nil, nil); c != 0 {
		t.Errorf("0: %d", c)
	}
}

func TestLookPath(t *testing.T) {
	if _, err := LookPath("sh", "/usr/bin:/bin", "/"); err != nil {
		t.Error("sh nicht gefunden")
	}
	if _, err := LookPath("gibt-es-nicht", "/usr/bin:/bin", "/"); err == nil {
		t.Error("nicht existierender Befehl gefunden")
	}
	if _, err := LookPath("./x", "", "/nonexistent"); err == nil {
		t.Error("relativer Pfad")
	}
}

func TestShellQuote(t *testing.T) {
	if q := shellQuote([]string{"a", "b c", "it's"}); q != `a 'b c' 'it'\''s'` {
		t.Errorf("%s", q)
	}
}

func TestPostChecks(t *testing.T) {
	dir := t.TempDir()
	envrc := filepath.Join(dir, ".envrc")
	p := &policy.Policy{Rules: []policy.Rule{{Kind: policy.KindProtected, Path: envrc, Note: "geschützt"}}}
	log := audit.New("t", nil, "json")
	if w := postChecks(p, log); len(w) != 0 {
		t.Errorf("ohne Datei: %v", w)
	}
	os.WriteFile(envrc, nil, 0o644)
	if w := postChecks(p, log); len(w) != 1 || !strings.Contains(w[0], ".envrc") || log.Count("protected.created") != 1 {
		t.Errorf("mit Datei: %v", w)
	}
}

func TestNewRepoChecks(t *testing.T) {
	ws := t.TempDir()
	os.MkdirAll(filepath.Join(ws, "alt", ".git"), 0o755)
	p := &policy.Policy{Workspace: ws, Repos: policy.FindRepos(ws)}
	log := audit.New("t", nil, "json")
	if w := postChecks(p, log); len(w) != 0 {
		t.Fatalf("ohne neues Repo: %v", w)
	}
	hooks := filepath.Join(ws, "a", "b", "c", "d", "e", "neu", ".git", "hooks")
	os.MkdirAll(hooks, 0o755)
	os.WriteFile(filepath.Join(hooks, "pre-commit.sample"), nil, 0o755)
	os.WriteFile(filepath.Join(hooks, "pre-commit"), nil, 0o755)
	os.WriteFile(filepath.Join(filepath.Dir(hooks), "config"), nil, 0o644)
	w := postChecks(p, log)
	if len(w) != 1 || !strings.Contains(w[0], "/neu wurde") || !strings.Contains(w[0], ".git/config") ||
		!strings.HasSuffix(w[0], "aktive Hooks: pre-commit") || log.Count("repo.created") != 1 {
		t.Errorf("neues Repo: %v", w)
	}
}

func TestCgroupWrap(t *testing.T) {
	l := policy.Limits{MaxMemory: 1 << 30, MaxProcesses: 40}
	args, env := cgroupWrap("/usr/bin/systemd-run", "/usr/bin/env", l, []string{"/usr/bin/bwrap", "x"}, []string{"PATH=/bin"}, 1000)
	want := "/usr/bin/systemd-run --user --scope --quiet --collect -p MemoryMax=1073741824 -p MemorySwapMax=0 -p TasksMax=40 -- /usr/bin/env -u XDG_RUNTIME_DIR /usr/bin/bwrap x"
	if got := strings.Join(args, " "); got != want {
		t.Errorf("Argumente:\n%s\nerwartet\n%s", got, want)
	}
	if strings.Join(env, " ") != "PATH=/bin XDG_RUNTIME_DIR=/run/user/1000" {
		t.Errorf("Umgebung: %v", env)
	}
	// Ist XDG_RUNTIME_DIR schon gesetzt, bleibt alles unverändert.
	args, env = cgroupWrap("/sr", "/env", policy.Limits{MaxProcesses: 5}, []string{"cmd"}, []string{"XDG_RUNTIME_DIR=/x"}, 1000)
	if strings.Join(args, " ") != "/sr --user --scope --quiet --collect -p TasksMax=5 -- cmd" || len(env) != 1 {
		t.Errorf("mit XDG_RUNTIME_DIR: %v %v", args, env)
	}
}

func TestProcessTree(t *testing.T) {
	cmd := exec.Command("sh", "-c", "sleep 30 & sleep 30 & wait")
	cmd.Start()
	defer cmd.Process.Kill()
	for i := 0; i < 50; i++ {
		if len(descendants(cmd.Process.Pid, processTable())) >= 3 {
			break
		}
		exec.Command("sleep", "0.02").Run()
	}
	if n := len(descendants(cmd.Process.Pid, processTable())); n < 3 {
		t.Fatalf("Nachfahren: %d", n)
	}
	killTree(cmd.Process.Pid, 9, false)
	for i := 0; i < 50 && len(descendants(cmd.Process.Pid, processTable())) > 1; i++ {
		exec.Command("sleep", "0.02").Run()
	}
	if n := len(descendants(cmd.Process.Pid, processTable())); n != 1 {
		t.Errorf("ohne root: %d Prozesse übrig, erwartet nur root", n)
	}
	if err := cmd.Process.Signal(syscall.Signal(0)); err != nil {
		t.Errorf("root wurde beendet: %v", err)
	}
	killTree(cmd.Process.Pid, 9, true)
	cmd.Wait()
}
