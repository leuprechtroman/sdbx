package darwin

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sdbx/internal/backend"
	"sdbx/internal/config"
	"sdbx/internal/netmatch"
	"sdbx/internal/policy"
)

var update = flag.Bool("update", false, "Golden-Dateien neu schreiben")

func testPolicy() *policy.Policy {
	o := config.Origin{Source: "test"}
	return &policy.Policy{
		Platform: "darwin", Workspace: "/Users/r/proj", SdbxTmp: "/private/var/folders/x/T/sdbx-1",
		FSDefault: "read",
		Rules: []policy.Rule{
			{Kind: policy.KindWrite, Path: "/Users/r/proj", Origin: o},
			{Kind: policy.KindWrite, Path: "/private/tmp", Origin: o},
			{Kind: policy.KindWrite, Glob: "/Users/r/.cache/**/x", Regex: `^/Users/r/\.cache/(?:.*/)?x(?:/.*)?$`, Origin: o},
			{Kind: policy.KindProtected, Path: "/Users/r/proj/.git/hooks", Origin: o},
			{Kind: policy.KindReadonly, Path: "/Users/r/proj/vendor", Origin: o},
			{Kind: policy.KindDeny, Path: "/Users/r/.ssh", Except: []string{"/Users/r/.ssh/known_hosts"}, Origin: o},
		},
		Net:          policy.NetPolicy{Mode: "proxy", Matcher: &netmatch.Matcher{}, Local: []int{5432}},
		Sockets:      []policy.SocketRule{{Path: "/private/tmp/cc-daemon-501/ab12cd34/control.sock"}},
		SocketDeny:   []string{"/private/tmp/codex-daemon-501/old"},
		MachServices: policy.MachGroups["default"],
		MachNoReport: policy.MachNoReport,
	}
}

func TestGolden(t *testing.T) {
	rt := &backend.Runtime{ProxyPort: 41234}
	prof, err := Generate(testPolicy(), rt)
	if err != nil {
		t.Fatal(err)
	}
	got := prof.Text + "\n;; Parameter\n"
	for _, p := range prof.Params {
		got += ";; " + p.Key + "=" + p.Value + "\n"
	}
	golden := filepath.Join("testdata", "default.sb.golden")
	if *update {
		os.MkdirAll("testdata", 0o755)
		os.WriteFile(golden, []byte(got), 0o644)
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("Golden-Datei fehlt (go test -update): %v", err)
	}
	if got != string(want) {
		t.Fatalf("Profil weicht von %s ab (go test ./internal/backend/darwin -update):\n%s", golden, got)
	}
}

func TestOrderingDenyAfterAllow(t *testing.T) {
	prof, _ := Generate(testPolicy(), &backend.Runtime{ProxyPort: 1})
	txt := prof.Text
	iw := strings.Index(txt, "(allow file-write*")
	ip := strings.Index(txt, "(deny file-write*")
	id := strings.Index(txt, "(deny file-read* file-write*")
	ie := strings.Index(txt, `(allow file-read* (literal (param "E0")))`)
	if !(iw < ip && ip < id && id < ie) {
		t.Fatalf("Reihenfolge falsch: write=%d protect=%d deny=%d except=%d", iw, ip, id, ie)
	}
	if !strings.Contains(txt, "(deny file-ioctl (ioctl-command TIOCSTI))") {
		t.Fatal("TIOCSTI-Filter fehlt")
	}
	if !strings.Contains(txt, `(deny mach-lookup (global-name "com.apple.analyticsd") (with no-report))`) {
		t.Fatal("analyticsd stumm verweigern fehlt")
	}
	if strings.Contains(txt, "/Users/r/proj\"") {
		t.Fatal("Pfade müssen als Parameter übergeben werden")
	}
}

// Socket-Freigaben per Glob werden zu Regex-Regeln; Sperren einzelner Sockets stehen danach und gewinnen.
func TestSocketGlob(t *testing.T) {
	p := testPolicy()
	p.Sockets = append(p.Sockets, policy.SocketRule{Glob: "/Users/r/run/*/ctl.sock"})
	p.SocketDeny = []string{"/Users/r/run/alt/ctl.sock"}
	prof, err := Generate(p, &backend.Runtime{})
	if err != nil {
		t.Fatal(err)
	}
	allow := `(allow network-outbound (remote unix-socket (regex #"^/Users/r/run/[^/]*/ctl\.sock(/.*)?$")))`
	deny := `(deny network-outbound (remote unix-socket (path-literal (param "S`
	ia, id := strings.Index(prof.Text, allow), strings.Index(prof.Text, deny)
	if ia < 0 || id < 0 || id < ia {
		t.Errorf("Glob-Freigabe (%d) muss vor der Sperre (%d) stehen:\n%s", ia, id, prof.Text)
	}
}

// Mit bekanntem sdbx-Binary läuft der Befehl unter "sdbx __reap", sonst direkt.
func TestPrepareReaper(t *testing.T) {
	for exe, want := range map[string][]string{
		"/usr/local/bin/sdbx": {"/usr/local/bin/sdbx", "__reap", "--", "codex", "-x"},
		"":                    {"codex", "-x"},
	} {
		rt := &backend.Runtime{RunDir: t.TempDir(), SdbxExe: exe, Argv: []string{"codex", "-x"}}
		l, err := Prepare(testPolicy(), rt)
		if err != nil {
			t.Fatal(err)
		}
		tail := l.Args[len(l.Args)-len(want):]
		if strings.Join(tail, " ") != strings.Join(want, " ") || l.Reaper != (exe != "") || l.Args[0] != SandboxExec {
			t.Errorf("exe %q: %v (Reaper %v)", exe, l.Args, l.Reaper)
		}
		if _, err := os.Stat(filepath.Join(rt.RunDir, "profile.sb")); err != nil {
			t.Errorf("Profil nicht geschrieben: %v", err)
		}
	}
}

// Elternverzeichnisse geschützter Pfade in Schreibbereichen, auch der Workspace selbst unter beschreibbarem Home.
func TestRenameGuards(t *testing.T) {
	o := config.Origin{Source: "test"}
	p := &policy.Policy{Rules: []policy.Rule{
		{Kind: policy.KindWrite, Path: "/Users/r", Origin: o},
		{Kind: policy.KindWrite, Path: "/Users/r/proj", Origin: o},
		{Kind: policy.KindProtected, Path: "/Users/r/proj/.git/hooks", Origin: o},
		{Kind: policy.KindProtected, Path: "/Users/r/proj/.claude/settings.json", Origin: o},
		{Kind: policy.KindDeny, Path: "/Users/r/.config/gcloud", Origin: o},
		{Kind: policy.KindDeny, Path: "/etc/shadow", Origin: o},
		{Kind: policy.KindDeny, Glob: "/Users/r/proj/**/.env", Origin: o},
	}}
	got := strings.Join(renameGuards(p), ",")
	if got != "/Users/r/.config,/Users/r/proj,/Users/r/proj/.claude,/Users/r/proj/.git" {
		t.Errorf("renameGuards: %s", got)
	}
}

// Meldende deny-Regeln tragen die Run-Markierung, stumme (no-report) nicht.
func TestRunMarker(t *testing.T) {
	prof, _ := Generate(testPolicy(), &backend.Runtime{ProxyPort: 1, RunID: "abc123"})
	txt := prof.Text
	for _, want := range []string{
		`(deny default (with message "sdbx-run:abc123"))`,
		`(deny file-ioctl (ioctl-command TIOCSTI) (with message "sdbx-run:abc123"))`,
		`(deny file-read* file-write* (subpath (param "P4")) (with message "sdbx-run:abc123"))`,
		`(deny mach-lookup (global-name "com.apple.analyticsd") (with no-report))`,
	} {
		if !strings.Contains(txt, want) {
			t.Errorf("fehlt: %s", want)
		}
	}
	for _, l := range strings.Split(txt, "\n") {
		if strings.HasPrefix(l, "(deny ") && !strings.Contains(l, "with message") && !strings.Contains(l, "no-report") {
			t.Errorf("deny-Regel ohne Markierung: %s", l)
		}
	}
}

func TestNetworkModes(t *testing.T) {
	p := testPolicy()
	p.Net.Mode = "none"
	prof, _ := Generate(p, &backend.Runtime{ProxyPort: 9})
	if strings.Contains(prof.Text, `localhost:9"`) {
		t.Fatal("network: none darf keinen Proxy erlauben")
	}
	p.Net.Mode = "host"
	prof, _ = Generate(p, &backend.Runtime{})
	if !strings.Contains(prof.Text, "(allow network*)") {
		t.Fatal("host-Modus")
	}
}

func TestDefaultDenyReadRules(t *testing.T) {
	p := testPolicy()
	p.FSDefault = "deny"
	p.Rules = append(p.Rules, policy.Rule{Kind: policy.KindSystem, Path: "/usr"})
	prof, _ := Generate(p, &backend.Runtime{})
	if strings.Contains(prof.Text, "(allow file-read*)\n") {
		t.Fatal("default deny darf nicht pauschal lesen erlauben")
	}
	if !strings.Contains(prof.Text, "(allow file-read-metadata)") {
		t.Fatal("Metadaten werden für Pfadauflösung gebraucht")
	}
}

func TestQuoteInGlobRejected(t *testing.T) {
	p := testPolicy()
	p.Rules = append(p.Rules, policy.Rule{Kind: policy.KindDeny, Glob: `/x/"*`, Regex: `^/x/"[^/]*$`})
	if _, err := Generate(p, &backend.Runtime{}); err == nil {
		t.Fatal("Anführungszeichen im Regex muss abgelehnt werden")
	}
}
