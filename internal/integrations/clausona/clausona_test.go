package clausona

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sdbx/internal/audit"
	"sdbx/internal/config"
	"sdbx/internal/integrations"
)

func fakeHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	for _, d := range []string{".clausona", ".claude", ".claude-work", ".codex", ".claude/ide"} {
		os.MkdirAll(filepath.Join(home, d), 0o755)
	}
	reg := map[string]any{
		"version":        2,
		"primarySources": map[string]string{"claude": "~/.claude", "codex": "~/.codex"},
		"activeProfiles": map[string]string{"claude": "claude:personal", "codex": "codex:personal"},
		"profiles": map[string]any{
			"claude:personal": map[string]any{"tool": "claude", "configDir": "~/.claude", "email": "a@x", "isPrimary": true},
			"claude:work":     map[string]any{"tool": "claude", "configDir": "~/.claude-work", "email": "b@x"},
			"codex:personal":  map[string]any{"tool": "codex", "configDir": "~/.codex", "email": "a@x", "isPrimary": true},
			"claude:gw": map[string]any{"tool": "claude", "kind": "api", "configDir": "~/.claude-gw", "email": "",
				"api": map[string]any{"baseUrl": "https://openrouter.ai/api", "secret": map[string]string{"source": "keychain"}}},
		},
	}
	b, _ := json.Marshal(reg)
	os.WriteFile(filepath.Join(home, ".clausona", "profiles.json"), b, 0o600)
	os.WriteFile(filepath.Join(home, ".claude", "ide", "51234.lock"), nil, 0o644)
	return home
}

func settings(mode string) config.ClausonaSettings {
	return config.ClausonaSettings{Mode: mode, Profiles: config.Profiles{Kind: "active"}, GuardMCP: "warn", Daemons: "off"}
}

func keys(ps []*Profile) string {
	var k []string
	for _, p := range ps {
		k = append(k, p.Key)
	}
	return strings.Join(k, ",")
}

func TestDetermineProfiles(t *testing.T) {
	home := fakeHome(t)
	reg, err := LoadRegistry(home)
	if err != nil {
		t.Fatal(err)
	}
	rc := func(env map[string]string, argv ...string) integrations.RunContext {
		return integrations.RunContext{Argv: argv, Home: home, Env: env}
	}
	cases := []struct {
		argv []string
		env  map[string]string
		want string
	}{
		{[]string{"clausona", "run", "claude:work"}, nil, "claude:work"},
		{[]string{"csn", "run", "claude", "--", "-p", "x"}, nil, "claude:personal"},
		{[]string{"clausona", "run", "codex"}, nil, "codex:personal"},
		{[]string{"/usr/local/bin/claude"}, nil, "claude:personal"},
		{[]string{"claude"}, map[string]string{"CLAUDE_CONFIG_DIR": home + "/.claude-work"}, "claude:work"},
		{[]string{"clausona", "run", "work"}, nil, ""}, // "work" ist kein Werkzeug
	}
	for _, c := range cases {
		got, err := DetermineProfiles(reg, settings("ro"), rc(c.env, c.argv...))
		if c.want == "" {
			if err == nil {
				t.Errorf("%v: Fehler erwartet", c.argv)
			}
			continue
		}
		if err != nil || keys(got) != c.want {
			t.Errorf("%v: %s (%v), erwartet %s", c.argv, keys(got), err, c.want)
		}
	}
	if _, err := DetermineProfiles(reg, settings("ro"), rc(nil, "bash")); err == nil || !strings.Contains(err.Error(), "nicht ermittelbar") {
		t.Errorf("unbekannter Befehl: %v", err)
	}
	s := settings("ro")
	s.Profile = "work"
	if got, _ := DetermineProfiles(reg, s, rc(nil, "bash")); keys(got) != "claude:work" {
		t.Errorf("Flag clausona.profile: %s", keys(got))
	}
	s = settings("ro")
	s.Profiles = config.Profiles{Kind: "all"}
	if got, _ := DetermineProfiles(reg, s, rc(nil, "bash")); len(got) != 4 {
		t.Errorf("all: %s", keys(got))
	}
}

// --route: sichtbar sind genau die Profile der Route; unbekannte Schlüssel und andere Routen bleiben außen vor.
func TestRouteProfiles(t *testing.T) {
	home := fakeHome(t)
	reg, err := LoadRegistry(home)
	if err != nil {
		t.Fatal(err)
	}
	routes := filepath.Join(home, ".clausona", "routes.json")
	determine := func(argv ...string) (string, error) {
		got, err := DetermineProfiles(reg, settings("ro"), integrations.RunContext{Argv: argv, Home: home})
		return keys(got), err
	}
	if _, err := determine("clausona", "run", "--route", "fast"); err == nil || !strings.Contains(err.Error(), "profiles=all") {
		t.Errorf("ohne routes.json: %v", err)
	}
	os.WriteFile(routes, []byte(`{"routes": {"fast": {"primary": "claude:work", "fallback": ["codex:personal", "claude:unbekannt", "claude:work"]},
		"other": ["claude:gw"]}}`), 0o600)
	for _, argv := range [][]string{{"clausona", "run", "--route", "fast"}, {"csn", "run", "--route=fast", "--", "-p", "x"}} {
		if got, err := determine(argv...); err != nil || got != "claude:work,codex:personal" {
			t.Errorf("%v: %s (%v)", argv, got, err)
		}
	}
	if got, err := determine("clausona", "run", "claude", "--", "--route", "other"); err != nil || got != "claude:personal" {
		t.Errorf("--route nach -- gehört dem Werkzeug: %s (%v)", got, err)
	}
	if _, err := determine("clausona", "run", "--route", "fehlt"); err == nil || !strings.Contains(err.Error(), "nicht gefunden") {
		t.Errorf("unbekannte Route: %v", err)
	}
	os.WriteFile(routes, []byte(`{"leer": ["claude:unbekannt"], "flach": "claude:gw"}`), 0o600)
	if _, err := determine("clausona", "run", "--route", "leer"); err == nil || !strings.Contains(err.Error(), "keine bekannten Profile") {
		t.Errorf("Route ohne bekannte Profile: %v", err)
	}
	if got, err := determine("clausona", "run", "--route", "flach"); err != nil || got != "claude:gw" {
		t.Errorf("Routen ohne routes-Ebene: %s (%v)", got, err)
	}
	os.WriteFile(routes, []byte(`{kaputt`), 0o600)
	if _, err := determine("clausona", "run", "--route", "fast"); err == nil || !strings.Contains(err.Error(), "kein gültiges JSON") {
		t.Errorf("ungültiges JSON: %v", err)
	}
}

func TestLoadRegistryErrors(t *testing.T) {
	home := t.TempDir()
	os.MkdirAll(filepath.Join(home, ".clausona"), 0o755)
	write := func(s string) { os.WriteFile(filepath.Join(home, ".clausona", "profiles.json"), []byte(s), 0o600) }
	write(`{"primarySource":"/x","activeProfile":"a","profiles":{}}`)
	if _, err := LoadRegistry(home); err == nil || !strings.Contains(err.Error(), "alte Format") {
		t.Errorf("v1: %v", err)
	}
	write(`{"version":3,"profiles":{}}`)
	if _, err := LoadRegistry(home); err == nil || !strings.Contains(err.Error(), "Version 3") {
		t.Errorf("v3: %v", err)
	}
	write(`{"version":2,"profiles":{"x":{"tool":"vim","configDir":"/x"}}}`)
	if _, err := LoadRegistry(home); err == nil {
		t.Error("ungültiges Werkzeug")
	}
}

func TestResolveWithoutRegistry(t *testing.T) {
	home := t.TempDir()
	os.MkdirAll(filepath.Join(home, ".clausona", "cache"), 0o755)
	_, err := Resolve(settings("ro"), integrations.RunContext{Argv: []string{"codex"}, Home: home})
	if err == nil || !strings.Contains(err.Error(), "noch nicht eingerichtet") || !strings.Contains(err.Error(), "clausona=off") {
		t.Errorf("fehlende Registry: %v", err)
	}
}

func values(l config.List) string { return strings.Join(l.Values(), "\n") }

func TestResolveRO(t *testing.T) {
	home := fakeHome(t)
	res, err := Resolve(settings("ro"), integrations.RunContext{Argv: []string{"clausona", "run", "claude:work"}, Home: home, UID: 501, Platform: "darwin", TmpRoot: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	f := res.Fragment
	w, ro, deny := values(f.Filesystem.Write), values(f.Filesystem.Readonly), values(f.Filesystem.Deny)
	for _, want := range []string{home + "/.claude-work", home + "/.claude-work/.claude.json", home + "/.clausona"} {
		if !strings.Contains(w, want) {
			t.Errorf("write fehlt %s:\n%s", want, w)
		}
	}
	for _, want := range []string{home + "/.claude-work/settings.json", home + "/.claude-work/plugins", home + "/.clausona/cache", home + "/.clausona/profiles.json"} {
		if !strings.Contains(ro, want) {
			t.Errorf("readonly fehlt %s", want)
		}
	}
	// Primärprofil nicht aktiv → nur kontoeigene Dateien gesperrt; anderes Profil komplett.
	for _, want := range []string{home + "/.claude/.credentials.json", home + "/.claude/projects", home + "/.claude.json", home + "/.claude-gw", home + "/.codex/auth.json", home + "/.clausona/backups", home + "/.clausona/secrets.json"} {
		if !strings.Contains(deny, want) {
			t.Errorf("deny fehlt %s:\n%s", want, deny)
		}
	}
	if strings.Contains(deny, home+"/.claude\n") {
		t.Error("Primärverzeichnis darf nicht komplett gesperrt werden (Symlink-Ziele)")
	}
	allow := values(f.Network.Allow)
	if !strings.Contains(allow, "api.anthropic.com") || strings.Contains(allow, "github.com") || strings.Contains(allow, "chatgpt.com") {
		t.Errorf("Netzwerk: %s", allow)
	}
	if *f.Process.IsolatePids || *f.Process.PrivateTmp || len(res.Required) != 2 {
		t.Error("erzwungene Werte fehlen")
	}
	if f.Env.Set["NODE_USE_ENV_PROXY"] != "1" || values(f.MacOS.MachServices) != "keychain" {
		t.Error("Umgebung bzw. Mach-Gruppe")
	}
	if strings.Contains(values(f.Env.Passthrough), "ANTHROPIC_API_KEY") {
		t.Error("API-Schlüssel nur bei API-Profilen")
	}
	if f.Filesystem.Write[0].Origin.Source != "integration:clausona" {
		t.Error("Herkunft fehlt")
	}
}

func TestResolveRWAndAPI(t *testing.T) {
	home := fakeHome(t)
	s := settings("rw")
	s.IDE = true
	res, err := Resolve(s, integrations.RunContext{Argv: []string{"clausona", "run", "claude:gw"}, Home: home, TmpRoot: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	f := res.Fragment
	if len(f.Filesystem.Readonly) != 0 {
		t.Errorf("rw darf nichts schreibschützen: %s", values(f.Filesystem.Readonly))
	}
	allow := values(f.Network.Allow)
	if !strings.Contains(allow, "openrouter.ai") || !strings.Contains(allow, "github.com") {
		t.Errorf("Netzwerk rw/API: %s", allow)
	}
	if !strings.Contains(values(f.Env.Passthrough), "ANTHROPIC_API_KEY") {
		t.Error("API-Profil braucht Schlüsselvariablen")
	}
	if strings.Contains(values(f.Filesystem.Deny), "secrets.json") {
		t.Error("API-Profil braucht secrets.json")
	}
}

// mergeSessions: Sitzungsordner des Primärprofils werden geteilt, Zugangsdaten bleiben gesperrt.
func TestResolveMergedSessions(t *testing.T) {
	home := fakeHome(t)
	path := filepath.Join(home, ".clausona", "profiles.json")
	var reg map[string]any
	b, _ := os.ReadFile(path)
	json.Unmarshal(b, &reg)
	profs := reg["profiles"].(map[string]any)
	profs["claude:work"].(map[string]any)["mergeSessions"] = true
	profs["codex:work"] = map[string]any{"tool": "codex", "configDir": "~/.codex-work", "email": "b@x", "mergeSessions": true}
	b, _ = json.Marshal(reg)
	os.WriteFile(path, b, 0o600)
	resolve := func(profile string) (w, ro, deny []string) {
		t.Helper()
		res, err := Resolve(settings("ro"), integrations.RunContext{Argv: []string{"clausona", "run", profile}, Home: home, TmpRoot: t.TempDir()})
		if err != nil {
			t.Fatal(err)
		}
		fs := res.Fragment.Filesystem
		return fs.Write.Values(), fs.Readonly.Values(), fs.Deny.Values()
	}
	has := func(list []string, p string) bool {
		for _, l := range list {
			if l == p {
				return true
			}
		}
		return false
	}
	c := home + "/.claude/"
	w, _, deny := resolve("claude:work")
	for _, m := range ClaudeMerged {
		if !has(w, c+m) || has(deny, c+m) {
			t.Errorf("claude merged: %s muss beschreibbar und nicht gesperrt sein", m)
		}
	}
	for _, p := range []string{c + ".credentials.json", c + "sessions", c + "history.jsonl", home + "/.claude.json"} {
		if !has(deny, p) {
			t.Errorf("claude merged: %s muss gesperrt bleiben", p)
		}
	}
	x := home + "/.codex"
	w, ro, deny := resolve("codex:work")
	if !has(w, x) {
		t.Errorf("codex merged: %s muss beschreibbar sein", x)
	}
	for _, p := range []string{x + "/auth.json", x + "/memories", x + "/memories_*.sqlite"} {
		if !has(deny, p) {
			t.Errorf("codex merged: %s muss gesperrt bleiben", p)
		}
	}
	if !has(ro, x+"/config.toml") || !has(ro, x+"/hooks.json") {
		t.Errorf("codex merged ro: Konfiguration des Primärprofils muss schreibgeschützt sein: %v", ro)
	}
}

func TestIDEPorts(t *testing.T) {
	home := fakeHome(t)
	if p := IDEPorts(filepath.Join(home, ".claude", "ide")); len(p) != 1 || p[0] != 51234 {
		t.Errorf("IDE-Ports: %v", p)
	}
}

func TestDirectClaudeSetsConfigDir(t *testing.T) {
	home := fakeHome(t)
	s := settings("ro")
	s.Profile = "claude:work"
	res, err := Resolve(s, integrations.RunContext{Argv: []string{"claude"}, Home: home, Env: map[string]string{}, TmpRoot: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if res.Fragment.Env.Set["CLAUDE_CONFIG_DIR"] != home+"/.claude-work" {
		t.Errorf("CLAUDE_CONFIG_DIR: %v", res.Fragment.Env.Set)
	}
}

func TestRewriteCodex(t *testing.T) {
	cases := map[string]string{
		"codex":                            "codex -c daemon_auto_start=false",
		"codex resume --last":              "codex -c daemon_auto_start=false resume --last",
		"clausona run codex:work -- -p hi": "clausona run codex:work -- -c daemon_auto_start=false -p hi",
		"clausona run codex":               "clausona run codex -- -c daemon_auto_start=false",
		"clausona run --route main -- x":   "clausona run --route main -- -c daemon_auto_start=false x",
		"clausona run claude:work":         "",
		"npx @openai/codex":                "",
	}
	for in, want := range cases {
		got := strings.Join(RewriteCodex(strings.Fields(in)), " ")
		if got != want {
			t.Errorf("%q → %q, erwartet %q", in, got, want)
		}
	}
}

func TestDaemons(t *testing.T) {
	home := fakeHome(t)
	tmp, _ := os.MkdirTemp("", "d")
	defer os.RemoveAll(tmp)
	sock := ClaudeDaemonSocket(tmp, 501, filepath.Join(home, ".claude-work"))
	if !strings.Contains(sock, "cc-daemon-501/") || len(filepath.Base(filepath.Dir(sock))) != 8 {
		t.Fatalf("Socket-Pfad: %s", sock)
	}
	os.MkdirAll(filepath.Dir(sock), 0o700)
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	rc := integrations.RunContext{Argv: []string{"clausona", "run", "claude:work"}, Home: home, UID: 501, TmpRoot: tmp}
	res, _ := Resolve(settings("ro"), rc)
	if len(res.SocketDeny) != 1 || res.SocketDeny[0] != sock || len(res.Errors) != 0 {
		t.Errorf("off: deny=%v err=%v", res.SocketDeny, res.Errors)
	}
	s := settings("ro")
	s.Daemons = "sandboxed"
	res, _ = Resolve(s, rc)
	if len(res.Errors) != 1 || !strings.Contains(res.Errors[0], "claude daemon stop") || len(res.SocketAllowDirs) != 2 {
		t.Errorf("sandboxed: %+v", res)
	}
	s.Daemons = "host"
	res, _ = Resolve(s, rc)
	if len(res.SocketDeny) != 0 || len(res.Notes) == 0 {
		t.Errorf("host: %+v", res)
	}
	// Codex-Symlinks
	cx := filepath.Join(home, ".codex", "app-server-control")
	os.MkdirAll(cx, 0o755)
	os.Symlink("/tmp/codex-daemon-501/abc", filepath.Join(cx, "app-server-control.sock"))
	if got := CodexDaemonSockets(filepath.Join(home, ".codex")); len(got) != 1 || got[0] != "/tmp/codex-daemon-501/abc" {
		t.Errorf("Codex-Symlinks: %v", got)
	}
}

func TestMCPGuard(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".claude.json")
	write := func(v any) { b, _ := json.Marshal(v); os.WriteFile(path, b, 0o600) }
	write(map[string]any{"numStartups": 1, "mcpServers": map[string]any{}, "projects": map[string]any{"/p": map[string]any{"hasTrustDialogAccepted": false}}})
	log := audit.New("t", nil, "json")

	g := NewGuard([]string{path}, "warn", dir)
	write(map[string]any{"numStartups": 2, "mcpServers": map[string]any{}, "projects": map[string]any{"/p": map[string]any{"hasTrustDialogAccepted": false}}})
	if w := g.Check(log); len(w) != 0 {
		t.Errorf("Zustandsänderung ist kein Verstoß: %v", w)
	}
	write(map[string]any{"numStartups": 3, "mcpServers": map[string]any{"evil": map[string]any{"command": "sh"}}, "projects": map[string]any{"/p": map[string]any{"hasTrustDialogAccepted": true}}})
	if w := g.Check(log); len(w) != 1 || !strings.Contains(w[0], "mcpServers") || !strings.Contains(w[0], "hasTrustDialogAccepted") {
		t.Errorf("warn: %v", w)
	}

	g = NewGuard([]string{path}, "revert", dir)
	write(map[string]any{"numStartups": 4, "mcpServers": map[string]any{"evil2": map[string]any{"command": "x"}}, "projects": map[string]any{"/p": map[string]any{"hasTrustDialogAccepted": false, "mcpServers": map[string]any{"x": 1}}}})
	if w := g.Check(log); len(w) != 1 || !strings.Contains(w[0], "zurückgesetzt") {
		t.Fatalf("revert: %v", w)
	}
	var doc map[string]any
	b, _ := os.ReadFile(path)
	json.Unmarshal(b, &doc)
	if doc["numStartups"].(float64) != 4 {
		t.Error("Zustand muss erhalten bleiben")
	}
	if m := doc["mcpServers"].(map[string]any); m["evil"] == nil || m["evil2"] != nil {
		t.Errorf("mcpServers nicht auf Ausgangsstand: %v", m)
	}
	pr := doc["projects"].(map[string]any)["/p"].(map[string]any)
	if pr["hasTrustDialogAccepted"] != true || pr["mcpServers"] != nil {
		t.Errorf("Projekteinträge nicht zurückgesetzt: %v", pr)
	}
	backups, _ := filepath.Glob(filepath.Join(dir, ".claude.json.before-revert.*"))
	if len(backups) != 1 {
		t.Error("Sicherung fehlt")
	}
	if log.Count("integration.clausona.mcp_changed") != 2 {
		t.Error("Audit-Ereignisse fehlen")
	}
}
