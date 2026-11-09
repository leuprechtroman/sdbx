package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func testEnv(t *testing.T, cfg string) (Env, string) {
	t.Helper()
	root, _ := filepath.EvalSymlinks(t.TempDir())
	home := filepath.Join(root, "home")
	ws := filepath.Join(home, "proj")
	os.MkdirAll(filepath.Join(ws, ".git"), 0o755)
	os.MkdirAll(filepath.Join(home, ".ssh"), 0o755)
	if cfg != "" {
		pdir := filepath.Join(home, ".config", "sdbx", "projects")
		os.MkdirAll(pdir, 0o755)
		body := cfg
		if !strings.Contains(cfg, "project:") {
			rest := strings.TrimPrefix(strings.TrimSpace(cfg), "version: 1")
			rest = strings.TrimSpace(rest)
			body = "version: 1\nproject: " + ws + "\n"
			if rest != "" {
				body += rest + "\n"
			}
		}
		os.WriteFile(filepath.Join(pdir, "proj.yaml"), []byte(body), 0o644)
	}
	return Env{Platform: "linux", Home: home, Cwd: ws, UID: 1000, GID: 1000, UserTmp: filepath.Join(root, "tmp"),
		Environ: []string{"HOME=" + home, "PATH=/usr/bin:/bin"}, Exe: "/usr/local/bin/sdbx"}, ws
}

// requireBwrap überspringt Tests, die den echten bwrap-Backend-Pfad brauchen (fail-closed ohne bwrap).
func requireBwrap(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bwrap nicht installiert")
	}
}

func run(env Env, args ...string) (int, string, string) {
	var o, e bytes.Buffer
	code := Main(args, env, IO{In: strings.NewReader(""), Out: &o, Err: &e})
	return code, o.String(), e.String()
}

func TestCheck(t *testing.T) {
	requireBwrap(t)
	env, _ := testEnv(t, "version: 1\ninclude: [node]\n")
	code, out, _ := run(env, "check", "--no-global")
	if code != 0 || !strings.Contains(out, "preset:node") || !strings.Contains(out, "Plattformmatrix") || !strings.Contains(out, "gültig") {
		t.Errorf("%d\n%s", code, out)
	}
	env, _ = testEnv(t, "version: 1\nnetwork:\n  allow: [\"a*b.com\"]\n")
	if code, out, _ := run(env, "check", "--no-global"); code != 125 || !strings.Contains(out, "proj.yaml:") {
		t.Errorf("Fehler mit Zeile: %d\n%s", code, out)
	}
}

func TestConfigErrorExit(t *testing.T) {
	env, _ := testEnv(t, "version: 1\nfilesystem:\n  wirte: []\n")
	code, _, errw := run(env, "check", "--no-global")
	if code != 125 || !strings.Contains(errw, `unbekannter Schlüssel "wirte"`) {
		t.Errorf("%d %s", code, errw)
	}
}

func TestExplain(t *testing.T) {
	env, _ := testEnv(t, "version: 1\nnetwork:\n  allow: [\"*.example.com\"]\n")
	_, out, _ := run(env, "explain", "--no-global", "~/.ssh/id_rsa")
	if !strings.Contains(out, "Zugriff: none") || !strings.Contains(out, "Secret-Sperrliste") {
		t.Errorf("Pfad:\n%s", out)
	}
	_, out, _ = run(env, "explain", "--no-global", "api.example.com:443")
	if !strings.Contains(out, "erlaubt") || !strings.Contains(out, "*.example.com") || !strings.Contains(out, "proj.yaml:") {
		t.Errorf("Host:\n%s", out)
	}
	_, out, _ = run(env, "explain", "--no-global", "--no-network", "api.example.com")
	if !strings.Contains(out, "kein Netzwerk") {
		t.Errorf("--no-network:\n%s", out)
	}
}

func TestPolicyFormats(t *testing.T) {
	env, _ := testEnv(t, "version: 1\n")
	code, out, _ := run(env, "policy", "--no-global", "--format", "json", "--allow-domain", "cli.example.com")
	var v map[string]any
	if code != 0 || json.Unmarshal([]byte(out), &v) != nil || !strings.Contains(out, "cli.example.com  [cli]") {
		t.Errorf("json: %d\n%s", code, out)
	}
	if _, out, _ := run(env, "policy", "--no-global", "--format", "seatbelt"); !strings.Contains(out, "(deny default)") {
		t.Errorf("seatbelt:\n%s", out)
	}
	if _, out, _ := run(env, "policy", "--no-global"); !strings.Contains(out, "filesystem_default: read") {
		t.Errorf("yaml:\n%s", out)
	}
	if code, _, _ := run(env, "policy", "--no-global", "--format", "xml"); code != 125 {
		t.Error("unbekanntes Format")
	}
}

func TestCLIFragmentIntegration(t *testing.T) {
	var c Common
	c.Integration = multi{"clausona=ro", "clausona.profiles=all", "clausona.ide=true", "clausona.daemons=sandboxed"}
	f, err := c.cliFragment("/")
	if err != nil {
		t.Fatal(err)
	}
	cl := f.Integrations.Clausona
	if *cl.Mode != "ro" || cl.Profiles.Kind != "all" || !*cl.IDE || *cl.Daemons != "sandboxed" {
		t.Errorf("%+v", cl)
	}
	for _, bad := range []string{"clausona=maybe", "other=ro", "clausona.foo=1", "clausona"} {
		c := Common{Integration: multi{bad}}
		if _, err := c.cliFragment("/"); err == nil {
			t.Errorf("%q hätte abgelehnt werden müssen", bad)
		}
	}
}

func TestUsageAndUnknown(t *testing.T) {
	env, _ := testEnv(t, "")
	if code, out, _ := run(env, "--help"); code != 0 || !strings.Contains(out, "sdbx run") {
		t.Error("Hilfe")
	}
	if code, _, errw := run(env, "frobnicate"); code != 127 || !strings.Contains(errw, "weder sdbx-Befehl noch Programm") {
		t.Errorf("unbekannter Befehl: %d %s", code, errw)
	}
	if code, _, _ := run(env, "--frobnicate"); code != 125 {
		t.Error("unbekanntes Flag")
	}
	if code, _, errw := run(env, "run", "--no-global"); code != 125 || !strings.Contains(errw, "kein Befehl") {
		t.Error("run ohne Befehl")
	}
	if code, out, _ := run(env, "presets"); code != 0 || !strings.Contains(out, "clausona") {
		t.Error("presets")
	}
}

func TestDryRun(t *testing.T) {
	requireBwrap(t)
	env, _ := testEnv(t, "version: 1\n")
	code, out, errw := run(env, "run", "--no-global", "--dry-run", "--", "sh", "-c", "echo hi")
	if code != 0 {
		t.Fatalf("%d %s", code, errw)
	}
	if !strings.Contains(out, "--unshare-net") || !strings.Contains(out, "__init") {
		t.Errorf("dry-run:\n%s", out)
	}
}
