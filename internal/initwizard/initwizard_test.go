package initwizard

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sdbx/internal/config"
)

var fixed = func() time.Time { return time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC) }

func project(t *testing.T) (string, Env) {
	t.Helper()
	// Erkennung sucht clausona/claude/codex im PATH des Prozesses; installierte Werkzeuge verändern sonst den Dialog
	t.Setenv("PATH", "/nonexistent")
	root := t.TempDir()
	ws := filepath.Join(root, "proj")
	os.MkdirAll(filepath.Join(ws, ".git"), 0o755)
	os.WriteFile(filepath.Join(ws, "package.json"), []byte("{}"), 0o644)
	os.WriteFile(filepath.Join(ws, "go.mod"), []byte("module x"), 0o644)
	os.WriteFile(filepath.Join(ws, ".env"), []byte("X=1"), 0o644)
	os.WriteFile(filepath.Join(ws, ".git", "config"), []byte("[remote \"origin\"]\n\turl = git@github.com:a/b.git\n"), 0o644)
	home := filepath.Join(root, "home")
	os.MkdirAll(home, 0o755)
	return ws, Env{Cwd: ws, Home: home, Platform: "linux", Now: fixed, Environ: []string{"PATH=/nonexistent"}}
}

// cfgPath ist die Override-Datei unter ~/.config/sdbx/projects/ für den Workspace.
func cfgPath(home, ws string) string {
	return filepath.Join(config.ProjectsDir(home), config.ProjectSlug(ws)+".yaml")
}

func TestProjectOverridePathCollision(t *testing.T) {
	home := t.TempDir()
	a, b := filepath.Join(home, "x", "app"), filepath.Join(home, "y", "app")
	os.MkdirAll(a, 0o755)
	os.MkdirAll(b, 0o755)
	pa := projectOverridePath(home, a)
	if pa != cfgPath(home, a) {
		t.Fatalf("freier Name: %s", pa)
	}
	os.MkdirAll(filepath.Dir(pa), 0o755)
	os.WriteFile(pa, []byte("version: 1\nproject: "+a+"\n"), 0o644)
	if got := projectOverridePath(home, a); got != pa {
		t.Fatalf("eigene Datei muss wiederverwendet werden: %s", got)
	}
	pb := projectOverridePath(home, b)
	pb2 := projectOverridePath(home, filepath.Join(home, "z", "app"))
	if pb == pa || pb == pb2 || !strings.HasPrefix(filepath.Base(pb), "app-") || len(filepath.Base(pb)) != len("app-12345678.yaml") {
		t.Fatalf("Kollision: %s / %s", pb, pb2)
	}
}

func TestDetect(t *testing.T) {
	ws, env := project(t)
	d := Detect(ws, env.Home, "linux")
	got := strings.Join(d.Presets, ",")
	if got != "node,go,git-https" {
		t.Errorf("Presets: %s", got)
	}
	if len(d.EnvFiles) != 1 || d.Defaults().Deny[0] != "**/.env" {
		t.Errorf(".env-Erkennung: %v", d.EnvFiles)
	}
}

// clausona installiert, aber ohne Registry: keine Integration vorschlagen (Spec 3.4)
func TestDetectClausonaWithoutRegistry(t *testing.T) {
	ws, env := project(t)
	os.MkdirAll(filepath.Join(env.Home, ".clausona", "cache"), 0o755)
	d := Detect(ws, env.Home, "linux")
	if d.Clausona || d.Defaults().ClausonaMode != "" {
		t.Errorf("Integration vorgeschlagen: %+v", d)
	}
	if !strings.Contains(strings.Join(d.Hints, "\n"), "clausona ist installiert, aber nicht nutzbar") {
		t.Errorf("Hinweis fehlt: %v", d.Hints)
	}
}

func TestGenerateRoundTrip(t *testing.T) {
	a := Answers{Presets: []string{"node", "go"}, NetMode: "proxy", Domains: []string{"api.example.com", "*.cdn.example.com"},
		Write: []string{"~/.cache/x"}, Deny: []string{"**/.env"}, Sockets: []string{"/run/x.sock"},
		Agents: []string{"claude"}, ClausonaMode: "ro", ClausonaProfiles: config.Profiles{Kind: "list", List: []string{"claude:work"}}}
	text := Generate(a, fixed())
	f, err := config.Parse([]byte(text), "x.yaml", "/")
	if err != nil {
		t.Fatalf("erzeugte Datei ungültig: %v\n%s", err, text)
	}
	if strings.Join(f.Include.Values(), ",") != "go,node" || len(f.Network.Allow) != 4 || *f.Integrations.Clausona.Mode != "ro" {
		t.Errorf("Inhalt: %s", text)
	}
	if !strings.Contains(text, "2026-10-28") || !strings.Contains(text, "# Netzwerk") {
		t.Error("Kommentare fehlen")
	}
	// minimal: nur version
	if min := Generate(Answers{NetMode: "proxy"}, fixed()); strings.Count(min, "\n") != 3 {
		t.Errorf("Default-Werte dürfen nicht geschrieben werden:\n%s", min)
	}
	// Reihenfolge stabil
	if Generate(a, fixed()) != text {
		t.Error("nicht deterministisch")
	}
	none := Generate(Answers{NetMode: "none"}, fixed())
	if _, err := config.Parse([]byte(none), "x", "/"); err != nil || !strings.Contains(none, "network: none") {
		t.Errorf("network none: %v\n%s", err, none)
	}
}

func TestNonInteractiveMissing(t *testing.T) {
	ws, env := project(t)
	var out, errw bytes.Buffer
	code := Main(nil, env, strings.NewReader(""), &out, &errw)
	if code != 125 || !strings.Contains(errw.String(), "--preset") || !strings.Contains(errw.String(), "--network") {
		t.Errorf("fehlende Flags: %d %s", code, errw.String())
	}
	if _, err := os.Stat(cfgPath(env.Home, ws)); err == nil {
		t.Error("ohne Angaben darf nichts geschrieben werden")
	}
}

func TestFlagsOnly(t *testing.T) {
	ws, env := project(t)
	var out, errw bytes.Buffer
	code := Main([]string{"--preset", "node", "--network", "proxy", "--allow-domain", "api.example.com"}, env, strings.NewReader(""), &out, &errw)
	if code != 0 {
		t.Fatalf("%d %s", code, errw.String())
	}
	cfg := cfgPath(env.Home, ws)
	b, _ := os.ReadFile(cfg)
	if !strings.Contains(string(b), "- node") || !strings.Contains(string(b), "api.example.com") || !strings.Contains(string(b), "project:") {
		t.Errorf("Inhalt:\n%s", b)
	}
	// existiert jetzt: ohne --force Abbruch, mit --force Ersetzen samt Sicherung
	if code := Main([]string{"--yes"}, env, strings.NewReader(""), &out, &errw); code != 125 {
		t.Errorf("bestehende Datei ohne --force: %d", code)
	}
	if code := Main([]string{"--yes", "--force"}, env, strings.NewReader(""), &out, &errw); code != 0 {
		t.Errorf("--force: %d %s", code, errw.String())
	}
	if _, err := os.Stat(cfg + ".bak"); err != nil {
		t.Error("Sicherung fehlt")
	}
	if code := Main([]string{"--preset", "gibtsnicht", "--network", "proxy"}, env, strings.NewReader(""), &out, &errw); code != 125 {
		t.Error("unbekanntes Preset")
	}
	if code := Main([]string{"--allow-domain", "bad*.com", "--yes"}, env, strings.NewReader(""), &out, &errw); code != 125 {
		t.Error("ungültige Domain")
	}
}

func TestRefuseInsideSandbox(t *testing.T) {
	_, env := project(t)
	env.Environ = append(env.Environ, "SDBX=1")
	var out, errw bytes.Buffer
	if code := Main([]string{"--yes"}, env, strings.NewReader(""), &out, &errw); code != 125 || !strings.Contains(errw.String(), "innerhalb einer Sandbox") {
		t.Errorf("%d %s", code, errw.String())
	}
}

func TestTUIFlow(t *testing.T) {
	ws, env := project(t)
	env.ForceInteractive = true
	const (
		down  = "\x1b[B"
		enter = "\r"
		esc   = "\x1b"
	)
	// Workspace bestätigen, Presets übernehmen, Agenten (keine), Netzwerk proxy,
	// Domain eingeben, Zurück zu Netzwerk (Esc) und wieder vor, Pfade übernehmen, Speichern, kein Probelauf.
	input := enter + enter + enter + enter + "api.test.dev" + enter + enter + enter + enter + enter
	var out, errw bytes.Buffer
	code := Main(nil, env, strings.NewReader(input), &out, &errw)
	if code != 0 {
		t.Fatalf("Exit %d: %s\n%s", code, errw.String(), out.String())
	}
	cfg := cfgPath(env.Home, ws)
	b, _ := os.ReadFile(cfg)
	for _, want := range []string{"project:", "- node", "- go", "api.test.dev", `"**/.env"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("%s fehlt:\n%s", want, b)
		}
	}
	_ = esc
	_ = down
	// Abbrechen in der Zusammenfassung schreibt nichts
	os.Remove(cfg)
	input = enter + enter + enter + enter + enter + enter + down + down + enter
	code = Main(nil, env, strings.NewReader(input), &out, &errw)
	if _, err := os.Stat(cfg); err == nil || code != 125 {
		t.Errorf("Abbrechen hat geschrieben (%d)", code)
	}
}

func TestTUIBackNavigation(t *testing.T) {
	ws, env := project(t)
	env.ForceInteractive = true
	const up, down, enter, esc = "\x1b[A", "\x1b[B", "\r", "\x1b"
	// Workspace ok, Presets ok, Agenten ok, Netzwerk: none wählen, dann Esc in den Pfaden zurück zu Netzwerk,
	// nach oben auf proxy, Liste leer, Pfade übernehmen, speichern, kein Probelauf
	input := enter + enter + enter + down + enter + esc + up + enter + enter + enter + enter + enter
	var out, errw bytes.Buffer
	if code := Main(nil, env, strings.NewReader(input), &out, &errw); code != 0 {
		t.Fatalf("Exit %d: %s", code, errw.String())
	}
	b, _ := os.ReadFile(cfgPath(env.Home, ws))
	if strings.Contains(string(b), "network: none") {
		t.Errorf("Zurück hat die Auswahl nicht geändert:\n%s", b)
	}
}

func TestMergeShowsDiff(t *testing.T) {
	ws, env := project(t)
	env.ForceInteractive = true
	cfg := cfgPath(env.Home, ws)
	os.MkdirAll(filepath.Dir(cfg), 0o755)
	os.WriteFile(cfg, []byte("version: 1\nproject: "+ws+"\nnetwork:\n  allow: [old.example.com]\n"), 0o644)
	const enter = "\r"
	// "Ergänzen" ist Vorauswahl; dann alle Schritte bestätigen und speichern
	input := enter + enter + enter + enter + enter + enter + enter + enter + enter
	var out, errw bytes.Buffer
	if code := Main(nil, env, strings.NewReader(input), &out, &errw); code != 0 {
		t.Fatalf("Exit %d: %s", code, errw.String())
	}
	if !strings.Contains(out.String(), "Änderungen an") || !strings.Contains(out.String(), "+ ") {
		t.Error("Diff fehlt")
	}
	b, _ := os.ReadFile(cfg)
	if !strings.Contains(string(b), "old.example.com") {
		t.Errorf("vorhandene Werte verloren:\n%s", b)
	}
}

func TestDiff(t *testing.T) {
	d := Diff("a\nb\nc", "a\nx\nc")
	if d != "  a\n- b\n+ x\n  c\n" {
		t.Errorf("%q", d)
	}
}
