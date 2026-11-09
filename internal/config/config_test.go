package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func write(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestParseFullSchema(t *testing.T) {
	body := `version: 1
include: [node]
workspace: .
filesystem:
  default: read
  read: [/opt/x]
  write: [./build, ~/.cache/tool]
  deny: ["**/.env"]
  readonly: [./vendor]
  exempt: [~/.npmrc]
  unprotect: [./.vscode]
  create_missing: true
network:
  mode: proxy
  default: deny
  allow: [github.com, "*.example.org"]
  deny: [evil.example.org]
  ports: [443, 80]
  allow_private: false
  local: [5432]
  ssh: true
sockets:
  allow: [/tmp/my.sock]
env:
  mode: allowlist
  passthrough: [GOPATH, "LC_*"]
  deny: [SECRET_*]
  set:
    CI: "true"
process:
  isolate_pids: true
  allow_ptrace: false
  private_tmp: true
limits:
  timeout: 30m
  kill_grace: 5s
  max_processes: 512
  max_memory: 4G
  max_file_size: 1G
  max_open_files: 1024
  cpu_time: 1h
macos:
  mach_services: [default, keychain]
linux:
  backend: bwrap
  landlock: auto
  seccomp: strict
  devices: [/dev/kvm]
integrations:
  clausona:
    mode: ro
    profiles: [work, codex:personal]
    guard_mcp: revert
    ide: true
    daemons: off
audit:
  file: /tmp/sdbx.log
  format: text
  summary: false
degraded: true
`
	f, err := Parse([]byte(body), "/w/sdbx.yaml", "/w")
	if err != nil {
		t.Fatal(err)
	}
	if got := f.Filesystem.Write[0]; got.Value != "./build" || got.Origin.Line != 7 || got.Origin.Source != "/w/sdbx.yaml" || got.Origin.Dir != "/w" {
		t.Fatalf("Herkunft falsch: %+v", got)
	}
	if f.Limits.MaxMemory.Bytes != 4<<30 || f.Limits.Timeout.Duration != 30*time.Minute {
		t.Fatalf("Limits falsch: %+v", f.Limits)
	}
	if f.Integrations.Clausona.Profiles.Kind != "list" || len(f.Integrations.Clausona.Profiles.List) != 2 {
		t.Fatalf("Profile falsch: %+v", f.Integrations.Clausona.Profiles)
	}
}

func TestAuditSummaryDefault(t *testing.T) {
	c, err := Build(nil, nil, nil, nil, nil)
	if err != nil || c.AuditSummary {
		t.Fatalf("Zusammenfassung muss per Default aus sein: %v", err)
	}
	on, _ := Parse([]byte("version: 1\naudit:\n  summary: true\n"), "project", "")
	if c, _ := Build(nil, nil, []Fragment{{File: on, Source: "project"}}, nil, nil); !c.AuditSummary {
		t.Fatal("audit.summary: true wird ignoriert")
	}
}

func TestShorthands(t *testing.T) {
	f, err := Parse([]byte("version: 1\nnetwork: none\nintegrations:\n  clausona: ro\n"), "x", "")
	if err != nil {
		t.Fatal(err)
	}
	if *f.Network.Mode != "none" || *f.Integrations.Clausona.Mode != "ro" {
		t.Fatalf("Kurzformen nicht erkannt")
	}
}

func TestStrictErrors(t *testing.T) {
	cases := map[string]string{
		"version: 1\nfilesystem:\n  wirte: [x]\n":                `sdbx.yaml:3: unbekannter Schlüssel "wirte" in filesystem`,
		"version: 1\nfoo: 1\n":                                   `sdbx.yaml:2: unbekannter Schlüssel "foo"`,
		"filesystem: {}\n":                                       `"version: 1" fehlt`,
		"version: 2\n":                                           "version 2 wird nicht unterstützt",
		"version: 1\nnetwork:\n  mode: tunnel\n":                 `network.mode: "tunnel" ist ungültig`,
		"version: 1\nlimits:\n  timeout: soon\n":                 `sdbx.yaml:3: ungültige Dauer "soon"`,
		"version: 1\nlimits:\n  max_memory: viel\n":              `ungültige Größe "viel"`,
		"version: 1\nnetwork:\n  local: [70000]\n":               `ungültiger Port "70000"`,
		"version: 1\nenv:\n  set:\n    1BAD: x\n":                `kein gültiger Variablenname`,
		"version: 1\nfilesystem:\n  write: x\n":                  "Liste erwartet",
		"version: 1\nversion: 1\n":                               "doppelt",
		"":                                                       "Datei ist leer",
		"version: 1\nintegrations:\n  clausona: {mode: maybe}\n": `integrations.clausona.mode: "maybe" ist ungültig`,
		"version: 1\nfilesystem:\n  write: [{a: b}]\n":           "einfacher Wert",
		"version: 1\nfilesystem: [a]\n":                          "sdbx.yaml:2: filesystem: Abschnitt erwartet",
		"- version: 1\n":                                         "sdbx.yaml:1: Wurzel: Abschnitt erwartet",
		"version: 1\nenv:\n  set: [A]\n":                         "sdbx.yaml:3: env.set: Zuordnung erwartet",
		"version: 1\nenv:\n  set:\n    A: [x]\n":                 "sdbx.yaml:4: env.set: nur einfache Werte erlaubt",
		"version: [1]\n":                                         "sdbx.yaml:1: version: einfacher Wert erwartet",
		"version: 1\nprocess:\n  isolate_pids: {a: 1}\n":         "sdbx.yaml:3: process.isolate_pids: einfacher Wert erwartet",
		"version: 1\nnetwork: &n {mode: none}\nenv: *n\n":        "YAML-Aliase",
	}
	for body, want := range cases {
		_, err := Parse([]byte(body), "sdbx.yaml", "")
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Eingabe %q: Fehler %v, erwartet %q", body, err, want)
		}
	}
}

func TestIncludesOrderAndCycles(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "base.yaml", "version: 1\nfilesystem:\n  write: [./from-base]\n")
	write(t, dir, "proj.yaml", "version: 1\ninclude: [node, base.yaml]\nfilesystem:\n  write: [./from-project]\n")
	l, err := Load(LoadOptions{ConfigPath: filepath.Join(dir, "proj.yaml"), NoGlobal: true, StartDir: dir, Home: dir})
	if err != nil {
		t.Fatal(err)
	}
	var srcs []string
	for _, f := range l.Project {
		srcs = append(srcs, filepath.Base(f.Source))
	}
	if strings.Join(srcs, ",") != "preset:node,base.yaml,proj.yaml" {
		t.Fatalf("Reihenfolge: %v", srcs)
	}
	if len(l.Files) != 2 {
		t.Fatalf("geladene Dateien: %v", l.Files)
	}

	write(t, dir, "a.yaml", "version: 1\ninclude: [b.yaml]\n")
	write(t, dir, "b.yaml", "version: 1\ninclude: [a.yaml]\n")
	_, err = Load(LoadOptions{ConfigPath: filepath.Join(dir, "a.yaml"), NoGlobal: true, StartDir: dir})
	if err == nil || !strings.Contains(err.Error(), "Include-Zyklus") {
		t.Fatalf("Zyklus nicht erkannt: %v", err)
	}
	write(t, dir, "c.yaml", "version: 1\ninclude: [nonexistent-preset]\n")
	_, err = Load(LoadOptions{ConfigPath: filepath.Join(dir, "c.yaml"), NoGlobal: true, StartDir: dir})
	if err == nil || !strings.Contains(err.Error(), "unbekanntes Preset") {
		t.Fatalf("unbekanntes Preset: %v", err)
	}
}

func TestIncludeDepth(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 11; i++ {
		write(t, dir, filepathName(i), "version: 1\ninclude: ["+filepathName(i+1)+"]\n")
	}
	write(t, dir, filepathName(11), "version: 1\n")
	_, err := Load(LoadOptions{ConfigPath: filepath.Join(dir, filepathName(0)), NoGlobal: true, StartDir: dir})
	if err == nil || !strings.Contains(err.Error(), "zu tief") {
		t.Fatalf("Tiefe nicht begrenzt: %v", err)
	}
}

func filepathName(i int) string { return "f" + string(rune('a'+i)) + ".yaml" }

func TestFindWorkspaceAndLegacy(t *testing.T) {
	root := t.TempDir()
	write(t, root, "sdbx.yaml", "version: 1\n")
	repo := filepath.Join(root, "repo")
	os.MkdirAll(filepath.Join(repo, ".git"), 0o755)
	os.MkdirAll(filepath.Join(repo, "sub"), 0o755)
	if got := FindWorkspace(filepath.Join(repo, "sub"), root); got != repo {
		t.Fatalf("Workspace: %s, erwartet %s", got, repo)
	}
	if got := FindLegacyProjectFile(filepath.Join(repo, "sub"), root); got != "" {
		t.Fatalf("Legacy-Suche hätte an der Git-Wurzel stoppen müssen: %s", got)
	}
	write(t, repo, ".sdbx.yaml", "version: 1\n")
	if got := FindLegacyProjectFile(filepath.Join(repo, "sub"), root); got != filepath.Join(repo, ".sdbx.yaml") {
		t.Fatalf("gefunden: %s", got)
	}
}

func TestConfigHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", "")
	if got := ConfigHome(home); got != filepath.Join(home, ".config") {
		t.Fatalf("ohne XDG: %s", got)
	}
	xdg := filepath.Join(t.TempDir(), "xdg")
	t.Setenv("XDG_CONFIG_HOME", xdg)
	if got := ConfigHome(home); got != xdg {
		t.Fatalf("mit XDG: %s", got)
	}
	if got := ProjectsDir(home); got != filepath.Join(xdg, "sdbx", "projects") {
		t.Fatalf("ProjectsDir folgt XDG, nicht home: %s", got)
	}
}

func TestProjectOverrideLoad(t *testing.T) {
	home := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	ws := filepath.Join(home, "code", "app")
	os.MkdirAll(filepath.Join(ws, ".git"), 0o755)
	os.MkdirAll(filepath.Join(ws, "pkg"), 0o755)
	pdir := ProjectsDir(home)
	os.MkdirAll(pdir, 0o755)
	write(t, pdir, "app.yaml", "version: 1\nproject: "+ws+"\nnetwork:\n  allow: [example.com]\n")
	write(t, ws, "sdbx.yaml", "version: 1\nnetwork:\n  allow: [evil.com]\n") // Legacy, wird ignoriert
	l, err := Load(LoadOptions{StartDir: filepath.Join(ws, "pkg"), Home: home, NoGlobal: true})
	if err != nil {
		t.Fatal(err)
	}
	if l.Workspace != ws || l.ProjectFile != filepath.Join(pdir, "app.yaml") {
		t.Fatalf("Workspace=%s File=%s", l.Workspace, l.ProjectFile)
	}
	if len(l.Warnings) != 1 || !strings.Contains(l.Warnings[0], "ignoriert") {
		t.Fatalf("Warnung: %v", l.Warnings)
	}
	if len(l.Project) != 1 || l.Project[0].Dir != ws {
		t.Fatalf("Fragment.Dir sollte Workspace sein: %+v", l.Project)
	}
	// ~ in project:
	write(t, pdir, "app.yaml", "version: 1\nproject: ~/code/app\n")
	l, err = Load(LoadOptions{StartDir: ws, Home: home, NoGlobal: true})
	if err != nil || l.ProjectFile == "" {
		t.Fatalf("~ expand: %v file=%s", err, l.ProjectFile)
	}
	// Fragmente ohne project: (Include-Ziele) werden übersprungen, mehrere Treffer sind ein Fehler
	write(t, pdir, "shared.yaml", "version: 1\nnetwork:\n  allow: [shared.example]\n")
	if l, err = Load(LoadOptions{StartDir: ws, Home: home, NoGlobal: true}); err != nil || l.ProjectFile != filepath.Join(pdir, "app.yaml") {
		t.Fatalf("Datei ohne project: muss übersprungen werden: %v file=%s", err, l.ProjectFile)
	}
	write(t, pdir, "app2.yaml", "version: 1\nproject: "+ws+"\n")
	if _, err = Load(LoadOptions{StartDir: ws, Home: home, NoGlobal: true}); err == nil || !strings.Contains(err.Error(), "mehrere") {
		t.Fatalf("mehrere Overrides: %v", err)
	}
}

func TestMergeOrderAndRequired(t *testing.T) {
	g, _ := Parse([]byte("version: 1\nprocess:\n  isolate_pids: true\nfilesystem:\n  write: [/a]\n"), "global", "")
	integ, _ := Parse([]byte("version: 1\nprocess:\n  isolate_pids: false\n"), "integration:clausona", "")
	proj, _ := Parse([]byte("version: 1\nfilesystem:\n  write: [/b]\n  default: deny\n"), "project", "")
	cli, _ := Parse([]byte("version: 1\nfilesystem:\n  default: read\n"), "cli", "")
	req := []RequiredValue{{Key: "process.isolate_pids", Value: false, Source: "integration:clausona"}}
	c, err := Build([]Fragment{{File: g, Source: "global"}}, []Fragment{{File: integ, Source: "integration:clausona"}},
		[]Fragment{{File: proj, Source: "project"}}, []Fragment{{File: cli, Source: "cli"}}, req)
	if err != nil {
		t.Fatal(err)
	}
	if c.FSDefault != "read" || c.ScalarOrigin["filesystem.default"] != "cli" {
		t.Fatalf("CLI muss zuletzt gewinnen: %s von %s", c.FSDefault, c.ScalarOrigin["filesystem.default"])
	}
	if strings.Join(c.FSWrite.Values(), ",") != "/a,/b" {
		t.Fatalf("Listen werden vereinigt: %v", c.FSWrite.Values())
	}
	if c.IsolatePids {
		t.Fatal("Integration muss isolate_pids=false setzen")
	}

	bad, _ := Parse([]byte("version: 1\nprocess:\n  isolate_pids: true\n"), "project", "")
	_, err = Build(nil, []Fragment{{File: integ, Source: "integration:clausona"}}, []Fragment{{File: bad, Source: "project"}}, nil, req)
	if err == nil || !strings.Contains(err.Error(), "widerspricht integration:clausona") {
		t.Fatalf("Konflikt mit erzwungenem Wert nicht erkannt: %v", err)
	}
}

// limits: spätere Quellen überschreiben einzelne Werte, die übrigen bleiben; die Herkunft wird je Wert vermerkt.
func TestLimitsMerge(t *testing.T) {
	g, _ := Parse([]byte("version: 1\nlimits:\n  timeout: 30m\n  max_memory: 4G\n  max_processes: 512\n  max_open_files: 1024\n  cpu_time: 1h\n  max_file_size: 1G\n"), "global", "")
	p, _ := Parse([]byte("version: 1\nlimits:\n  timeout: 2m\n  max_memory: 0\n  kill_grace: 3s\n"), "project", "")
	c, err := Build([]Fragment{{File: g, Source: "global"}}, nil, []Fragment{{File: p, Source: "project"}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.Timeout != 2*time.Minute || c.KillGrace != 3*time.Second || c.MaxMemory != 0 || c.MaxProcesses != 512 ||
		c.MaxOpenFiles != 1024 || c.CPUTime != time.Hour || c.MaxFileSize != 1<<30 {
		t.Errorf("Werte: %+v", c)
	}
	for key, want := range map[string]string{"limits.timeout": "project", "limits.max_memory": "project", "limits.max_processes": "global"} {
		if c.ScalarOrigin[key] != want {
			t.Errorf("Herkunft %s: %q, erwartet %q", key, c.ScalarOrigin[key], want)
		}
	}
}

// Jeder erzwingbare Wert wird geprüft; unbekannte Schlüssel sind ein interner Fehler statt still ignoriert.
func TestCheckRequiredKeys(t *testing.T) {
	c := Defaults()
	for key, ok := range map[string]any{"process.isolate_pids": true, "process.private_tmp": true, "process.allow_ptrace": false,
		"network.mode": "proxy", "env.mode": "allowlist"} {
		if err := c.CheckRequired([]RequiredValue{{Key: key, Value: ok, Source: "integration:x"}}); err != nil {
			t.Errorf("%s=%v: %v", key, ok, err)
		}
		if err := c.CheckRequired([]RequiredValue{{Key: key, Value: "anders", Source: "integration:x"}}); err == nil {
			t.Errorf("%s: Abweichung nicht erkannt", key)
		}
	}
	if err := c.CheckRequired([]RequiredValue{{Key: "limits.timeout", Value: "1m"}}); err == nil || !strings.Contains(err.Error(), "nicht erzwingbar") {
		t.Errorf("unbekannter Schlüssel: %v", err)
	}
}

func TestDefaults(t *testing.T) {
	c := Defaults()
	if c.FSDefault != "read" || c.NetMode != "proxy" || c.NetDefault != "deny" || !c.IsolatePids || !c.PrivateTmp ||
		c.EnvMode != "allowlist" || c.KillGrace != 10*time.Second || c.Clausona.Daemons != "off" {
		t.Fatalf("Defaults weichen von Spec 4.5 ab: %+v", c)
	}
}

func TestSizes(t *testing.T) {
	for in, want := range map[string]int64{"0": 0, "512": 512, "4K": 4096, "512M": 512 << 20, "4G": 4 << 30, "1T": 1 << 40, "2gb": 2 << 30} {
		got, err := ParseSize(in)
		if err != nil || got != want {
			t.Errorf("%s: %d, %v", in, got, err)
		}
	}
	// Ein Überlauf ergäbe eine negative Größe, und die Grenze wäre stillschweigend aus.
	for _, in := range []string{"8388609T", "9223372036854775808", "-1G"} {
		if got, err := ParseSize(in); err == nil {
			t.Errorf("%s: %d ohne Fehler", in, got)
		}
	}
}
