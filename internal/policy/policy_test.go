package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sdbx/internal/config"
	"sdbx/internal/testutil"
)

type env struct {
	home, ws, tmp string
}

func setup(t *testing.T) env {
	t.Helper()
	root := t.TempDir()
	root, _ = filepath.EvalSymlinks(root)
	e := env{home: filepath.Join(root, "home"), ws: filepath.Join(root, "home", "proj"), tmp: filepath.Join(root, "sdbxtmp")}
	testutil.IsolateConfigHome(t, e.home)
	for _, d := range []string{e.ws, e.tmp, filepath.Join(e.home, ".ssh"), filepath.Join(e.home, ".cache", "tool"),
		filepath.Join(e.ws, ".git", "hooks"), filepath.Join(e.ws, "sub", ".git"), filepath.Join(e.home, "bin")} {
		os.MkdirAll(d, 0o755)
	}
	os.WriteFile(filepath.Join(e.home, ".ssh", "id_ed25519"), []byte("secret"), 0o600)
	os.WriteFile(filepath.Join(e.home, ".ssh", "known_hosts"), []byte("hosts"), 0o644)
	os.WriteFile(filepath.Join(e.home, ".bashrc"), nil, 0o644)
	return e
}

func compile(t *testing.T, e env, yaml string, mod ...func(*Context)) *Policy {
	t.Helper()
	f, err := config.Parse([]byte(yaml), filepath.Join(e.ws, "sdbx.yaml"), e.ws)
	if err != nil {
		t.Fatal(err)
	}
	c, err := config.Build(nil, nil, []config.Fragment{{File: f, Source: filepath.Join(e.ws, "sdbx.yaml"), Dir: e.ws}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := Context{Platform: "linux", Home: e.home, UID: 1000, GID: 1000, UserTmp: "/tmp", SdbxTmp: e.tmp,
		DefaultWorkspace: e.ws, SharedTmp: filepath.Join(filepath.Dir(e.tmp), "sharedtmp"), ConfigFiles: []string{filepath.Join(e.ws, "sdbx.yaml")},
		LookupEnv: func(string) (string, bool) { return "", false }, PathEnv: filepath.Join(e.home, "bin") + ":/usr/bin"}
	for _, m := range mod {
		m(&ctx)
	}
	p, err := Compile(c, ctx)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func access(p *Policy, path string) Access { return p.Evaluate(path).Access }

func TestEvaluationRules(t *testing.T) {
	e := setup(t)
	p := compile(t, e, `version: 1
filesystem:
  write: [~/.cache]
  deny: [~/.cache/tool]
  readonly: [./vendor]
`)
	cases := map[string]Access{
		filepath.Join(e.ws, "main.go"):               Write, // Workspace
		filepath.Join(e.ws, "vendor", "x"):           Read,  // readonly
		filepath.Join(e.home, ".cache", "other"):     Write, // write
		filepath.Join(e.home, ".cache", "tool", "f"): None,  // deny gewinnt gegen write darüber
		filepath.Join(e.home, ".ssh", "id_ed25519"):  None,  // Secret-Sperrliste
		filepath.Join(e.home, ".ssh", "known_hosts"): Read,  // Ausnahme
		filepath.Join(e.home, "notes.txt"):           Read,  // default read
		filepath.Join(e.ws, ".git", "hooks", "pre"):  Read,  // geschützt
		filepath.Join(e.ws, ".git", "objects", "ab"): Write, // Rest von .git beschreibbar
		filepath.Join(e.ws, "sub", ".git", "config"): Read,  // geschütztes Unter-Repository
		filepath.Join(e.ws, "sdbx.yaml"):             Read,  // Konfiguration geschützt
		filepath.Join(e.ws, ".envrc"):                Read,  // auch wenn nicht existent
		filepath.Join(e.tmp, "x"):                    Write, // privates Temp
		"/etc/shadow":                                None,
		filepath.Join(e.home, ".bashrc"):             Read,
	}
	for path, want := range cases {
		if got := access(p, path); got != want {
			t.Errorf("%s: %s, erwartet %s (%s)", path, got, want, p.Evaluate(path).Reason)
		}
	}
}

func TestDenyBeatsDeeperWrite(t *testing.T) {
	e := setup(t)
	p := compile(t, e, "version: 1\nfilesystem:\n  write: [~/.cache/tool]\n  deny: [~/.cache]\n")
	if got := access(p, filepath.Join(e.home, ".cache", "tool", "x")); got != None {
		t.Fatalf("deny muss auch tiefere write-Regeln schlagen, ist %s", got)
	}
	found := false
	for _, i := range p.Issues {
		found = found || strings.Contains(i.Msg, "bleibt gesperrt")
	}
	if !found {
		t.Error("Überschneidung wurde nicht gemeldet")
	}
}

func TestDefaultDeny(t *testing.T) {
	e := setup(t)
	p := compile(t, e, "version: 1\nfilesystem:\n  default: deny\n  read: [~/notes]\n")
	if got := access(p, filepath.Join(e.home, "other")); got != None {
		t.Errorf("default deny: %s", got)
	}
	if got := access(p, "/usr/bin/env"); got != Read {
		t.Errorf("Systembasis muss lesbar sein: %s", got)
	}
	if got := access(p, filepath.Join(e.ws, "x")); got != Write {
		t.Errorf("Workspace: %s", got)
	}
}

func TestExemptAndUnprotect(t *testing.T) {
	e := setup(t)
	p := compile(t, e, "version: 1\nfilesystem:\n  exempt: [~/.ssh]\n  unprotect: [./.envrc, ./not-protected]\n")
	if got := access(p, filepath.Join(e.home, ".ssh", "id_ed25519")); got != Read {
		t.Errorf("exempt greift nicht: %s", got)
	}
	if got := access(p, filepath.Join(e.ws, ".envrc")); got != Write {
		t.Errorf("unprotect greift nicht: %s", got)
	}
	msgs := ""
	for _, i := range p.Issues {
		msgs += i.Msg + "\n"
	}
	if !strings.Contains(msgs, "Schutz für") || !strings.Contains(msgs, "ist kein geschützter Pfad") {
		t.Errorf("Warnungen fehlen:\n%s", msgs)
	}
}

func TestPathHijackProtection(t *testing.T) {
	e := setup(t)
	p := compile(t, e, "version: 1\nfilesystem:\n  write: [~]\n")
	if got := access(p, filepath.Join(e.home, "bin", "git")); got != Read {
		t.Errorf("PATH-Verzeichnis unter write muss schreibgeschützt sein: %s", got)
	}
	p = compile(t, e, "version: 1\nfilesystem:\n  write: [~/bin]\n")
	if got := access(p, filepath.Join(e.home, "bin", "git")); got != Write {
		t.Errorf("explizit freigegebenes PATH-Verzeichnis: %s", got)
	}
	warned := false
	for _, i := range p.Issues {
		warned = warned || strings.Contains(i.Msg, "PATH-Hijacking")
	}
	if !warned {
		t.Error("PATH-Hijacking-Warnung fehlt")
	}
}

// Leere und relative PATH-Einträge zeigen in den Workspace (beschreibbar gewollt); PATH-Verzeichnisse
// im Workspace bleiben beschreibbar, außerhalb unter einer Schreibfreigabe werden sie schreibgeschützt.
func TestPathHijackEdgeCases(t *testing.T) {
	e := setup(t)
	wsBin := filepath.Join(e.ws, "node_modules", ".bin")
	os.MkdirAll(wsBin, 0o755)
	os.Symlink(filepath.Join(e.home, "bin"), filepath.Join(e.home, "binlink"))
	p := compile(t, e, "version: 1\nfilesystem:\n  write: [~]\n", func(c *Context) {
		c.PathEnv = strings.Join([]string{"", "relbin", wsBin, filepath.Join(e.home, "binlink"), "/usr/bin"}, ":")
	})
	if got := access(p, filepath.Join(wsBin, "tool")); got != Write {
		t.Errorf("PATH-Verzeichnis im Workspace: %s", got)
	}
	if got := access(p, filepath.Join(e.home, "bin", "git")); got != Read {
		t.Errorf("PATH-Eintrag über Symlink muss das Ziel schützen: %s", got)
	}
	for _, r := range p.Rules {
		if r.Note == "PATH-Verzeichnis" && (strings.Contains(r.Path, "relbin") || r.Path == "") {
			t.Errorf("relativer PATH-Eintrag als Regel: %+v", r)
		}
	}
}

// network.deny wird übersetzt und gewinnt gegen eine passende Freigabe; ungültige Muster sind Fehler.
func TestNetworkDeny(t *testing.T) {
	e := setup(t)
	p := compile(t, e, "version: 1\nnetwork:\n  allow: [\"*.example.com\"]\n  deny: [evil.example.com, \"bad*deny\"]\n")
	if d, _ := p.Net.Matcher.Decide("api.example.com", 443); !d.Allowed {
		t.Errorf("Freigabe: %+v", d)
	}
	if d, _ := p.Net.Matcher.Decide("evil.example.com", 443); d.Allowed || !strings.Contains(d.Source, "sdbx.yaml") {
		t.Errorf("Sperre muss gewinnen und ihre Quelle nennen: %+v", d)
	}
	if errs := p.Errors(); len(errs) != 1 || !strings.Contains(errs[0].Msg, "network.deny") {
		t.Errorf("ungültiges deny-Muster: %v", errs)
	}
	for mode, want := range map[string]string{"host": "uneingeschränkt", "none": "keine Wirkung"} {
		p = compile(t, e, "version: 1\nnetwork:\n  mode: "+mode+"\n  allow: [example.com]\n")
		if !hasIssue(p, want) {
			t.Errorf("mode %s: Warnung %q fehlt: %v", mode, want, p.Issues)
		}
	}
}

// sockets.allow: relative Pfade zum Konfigurationsverzeichnis, Symlinks aufgelöst, Globs mit aufgelöstem Präfix.
func TestSocketsAllow(t *testing.T) {
	e := setup(t)
	os.MkdirAll(filepath.Join(e.home, "run"), 0o755)
	os.Symlink(filepath.Join(e.home, "run"), filepath.Join(e.home, "runlink"))
	p := compile(t, e, "version: 1\nsockets:\n  allow: [./dev.sock, ~/runlink/agent.sock, \"~/runlink/*/ctl.sock\"]\n", func(c *Context) {
		c.SocketDeny = []string{filepath.Join(e.home, "runlink", "alt.sock")}
	})
	want := []SocketRule{
		{Path: filepath.Join(e.ws, "dev.sock")},
		{Path: filepath.Join(e.home, "run", "agent.sock")},
		{Glob: filepath.Join(e.home, "run") + "/*/ctl.sock"},
	}
	if len(p.Sockets) != len(want) {
		t.Fatalf("Sockets: %+v", p.Sockets)
	}
	for i, w := range want {
		if p.Sockets[i].Path != w.Path || p.Sockets[i].Glob != w.Glob {
			t.Errorf("Socket %d: %+v, erwartet %+v", i, p.Sockets[i], w)
		}
	}
	if len(p.SocketDeny) != 1 || p.SocketDeny[0] != filepath.Join(e.home, "run", "alt.sock") {
		t.Errorf("SocketDeny: %v", p.SocketDeny)
	}
}

// linux.devices: nur Geräte unter /dev, auch nach Auflösen von ".." und Symlinks; jede Freigabe mit Warnung.
func TestLinuxDevices(t *testing.T) {
	e := setup(t)
	p := compile(t, e, "version: 1\nlinux:\n  devices: [/dev/kvm, /etc/shadow, /dev/../etc/passwd, /dev, dev/kvm]\n")
	if len(p.Linux.Devices) != 1 || p.Linux.Devices[0] != "/dev/kvm" {
		t.Errorf("Geräte: %v", p.Linux.Devices)
	}
	if len(p.Errors()) != 4 || !hasIssue(p, "Gerät /dev/kvm ist in der Sandbox verfügbar") {
		t.Errorf("Meldungen: %v", p.Issues)
	}
}

func hasIssue(p *Policy, s string) bool {
	for _, i := range p.Issues {
		if strings.Contains(i.Msg, s) {
			return true
		}
	}
	return false
}

func TestGlobRules(t *testing.T) {
	e := setup(t)
	p := compile(t, e, "version: 1\nfilesystem:\n  deny: [\"**/.env\"]\n")
	if got := access(p, filepath.Join(e.ws, "a", ".env")); got != None {
		t.Errorf("Glob-Sperre: %s", got)
	}
	if got := access(p, filepath.Join(e.ws, "a", ".env.example")); got != Write {
		t.Errorf("Glob trifft zu viel: %s", got)
	}
}

func TestWarningsAndErrors(t *testing.T) {
	e := setup(t)
	p := compile(t, e, `version: 1
filesystem:
  write: [./does-not-exist, "${ENV:NOT_SET}/x"]
network:
  allow: ["bad*host.com"]
macos:
  mach_services: [nosuchgroup, com.apple.pasteboard.1]
`)
	var errs, warns []string
	for _, i := range p.Issues {
		if i.Error {
			errs = append(errs, i.Msg)
		} else {
			warns = append(warns, i.Msg)
		}
	}
	all := strings.Join(warns, "\n")
	for _, w := range []string{"existiert nicht und wird übersprungen", "entfällt", "Mach-Service com.apple.pasteboard.1"} {
		if !strings.Contains(all, w) {
			t.Errorf("Warnung %q fehlt in:\n%s", w, all)
		}
	}
	if len(errs) != 2 || !strings.Contains(errs[0], "sdbx.yaml:5") {
		t.Errorf("Fehler mit Zeilenangabe erwartet: %v", errs)
	}
}

func TestMachExpansion(t *testing.T) {
	e := setup(t)
	p := compile(t, e, "version: 1\nmacos:\n  mach_services: [keychain]\n")
	joined := strings.Join(p.MachServices, ",")
	for _, s := range []string{"com.apple.logd", "com.apple.SecurityServer", "com.apple.authd"} {
		if !strings.Contains(joined, s) {
			t.Errorf("%s fehlt", s)
		}
	}
	if strings.Count(joined, "com.apple.trustd.agent") != 1 {
		t.Error("Dienste müssen dedupliziert werden")
	}
	if len(p.MachNoReport) != 1 || p.MachNoReport[0] != "com.apple.analyticsd" {
		t.Errorf("analyticsd muss stumm verweigert werden: %v", p.MachNoReport)
	}
}

func TestWorkspaceOverride(t *testing.T) {
	e := setup(t)
	os.MkdirAll(filepath.Join(e.ws, "inner"), 0o755)
	p := compile(t, e, "version: 1\nworkspace: ./inner\n")
	if p.Workspace != filepath.Join(e.ws, "inner") {
		t.Fatalf("Workspace: %s", p.Workspace)
	}
}

func TestCreateMissing(t *testing.T) {
	e := setup(t)
	p := compile(t, e, "version: 1\nfilesystem:\n  write: [~/.newcache]\n  create_missing: true\n")
	for _, r := range p.Rules {
		if strings.HasSuffix(r.Path, ".newcache") && !r.Create {
			t.Fatal("create_missing nicht übernommen")
		}
	}
}

// Ein explizites write hebt den Schutz nur bei den Bin-Verzeichnissen im Home auf.
func TestExplicitWriteKeepsProtection(t *testing.T) {
	e := setup(t)
	os.MkdirAll(filepath.Join(e.home, ".config", "sdbx"), 0o755)
	p := compile(t, e, "version: 1\nfilesystem:\n  write: [./.git/hooks, ~/.config/sdbx, ~/.local/bin]\n")
	for _, f := range []string{filepath.Join(e.ws, ".git", "hooks", "pre-commit"), filepath.Join(e.home, ".config", "sdbx", "config.yaml")} {
		if got := access(p, f); got != Read {
			t.Errorf("%s: write darf den Schutz nicht aufheben: %s", f, got)
		}
	}
	if got := access(p, filepath.Join(e.home, ".local", "bin", "x")); got != Write {
		t.Errorf("explizit freigegebenes ~/.local/bin: %s", got)
	}
	warned := false
	for _, i := range p.Issues {
		warned = warned || strings.Contains(i.Msg, filepath.Join(e.home, ".local", "bin")+" ist beschreibbar")
	}
	if !warned {
		t.Errorf("Warnung für ~/.local/bin fehlt: %+v", p.Issues)
	}
}

// Compile legt nichts an (check/explain); fehlende Bin-Verzeichnisse unter write werden nur markiert.
func TestCompileHasNoSideEffects(t *testing.T) {
	e := setup(t)
	p := compile(t, e, "version: 1\nfilesystem:\n  write: [~]\n")
	lb := filepath.Join(e.home, ".local", "bin")
	if _, err := os.Stat(lb); !os.IsNotExist(err) {
		t.Fatalf("Compile hat %s angelegt", lb)
	}
	found := false
	for _, r := range p.Rules {
		if r.Path == lb && r.Kind == KindProtected {
			found = r.Create && r.IsDir
		}
	}
	if !found {
		t.Error("~/.local/bin muss als anzulegendes geschütztes Verzeichnis markiert sein")
	}
	p = compile(t, e, "version: 1\n")
	for _, r := range p.Rules {
		if r.Path == lb && r.Create {
			t.Error("ohne Schreibbereich darüber darf nichts angelegt werden")
		}
	}
}

func TestXDGConfigDirProtected(t *testing.T) {
	e := setup(t)
	xdg := filepath.Join(e.home, "xdg")
	os.MkdirAll(filepath.Join(xdg, "sdbx"), 0o755)
	t.Setenv("XDG_CONFIG_HOME", xdg)
	p := compile(t, e, "version: 1\nfilesystem:\n  write: [~]\n")
	if got := access(p, filepath.Join(xdg, "sdbx", "projects", "x.yaml")); got != Read {
		t.Errorf("$XDG_CONFIG_HOME/sdbx muss geschützt sein: %s", got)
	}
}
