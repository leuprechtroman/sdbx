package pathutil

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExpand(t *testing.T) {
	v := Vars{Home: "/h", Workspace: "/w", UID: 501, GID: 20, TmpDir: "/t", SdbxTmp: "/s",
		LookupEnv: func(k string) (string, bool) {
			if k == "GOPATH" {
				return "/go", true
			}
			return "", false
		}}
	cases := map[string]string{
		"~":                     "/h",
		"~/x":                   "/h/x",
		"${HOME}/a":             "/h/a",
		"${WORKSPACE}/b":        "/w/b",
		"${CONFIG_DIR}/c":       "/cfg/c",
		"/tmp/cc-daemon-${UID}": "/tmp/cc-daemon-501",
		"${GID}":                "20",
		"${TMPDIR}/${SDBX_TMP}": "/t//s",
		"${ENV:GOPATH}/pkg":     "/go/pkg",
		"price$$":               "price$",
		"no~expansion":          "no~expansion",
	}
	for in, want := range cases {
		got, err := v.Expand(in, "/cfg")
		if err != nil || got != want {
			t.Errorf("%q → %q (%v), erwartet %q", in, got, err, want)
		}
	}
	if _, err := v.Expand("${ENV:MISSING}/x", ""); err == nil {
		t.Error("leere ENV-Variable muss Eintrag verwerfen")
	} else if _, ok := err.(*ErrDropped); !ok {
		t.Errorf("falscher Fehlertyp %T", err)
	}
	for _, bad := range []string{"${NOPE}", "${HOME:x}", "${ENV:}"} {
		if _, err := v.Expand(bad, ""); err == nil {
			t.Errorf("%q hätte fehlschlagen müssen", bad)
		}
	}
	if got, _ := v.Expand("${CONFIG_DIR}", ""); got != "/w" {
		t.Errorf("CONFIG_DIR ohne Datei muss Workspace sein, ist %q", got)
	}
}

func TestResolve(t *testing.T) {
	dir := t.TempDir()
	real, _ := filepath.EvalSymlinks(dir)
	os.MkdirAll(filepath.Join(dir, "a"), 0o755)
	os.Symlink(filepath.Join(dir, "a"), filepath.Join(dir, "link"))
	r, ex := Resolve(filepath.Join(dir, "link"))
	if !ex || r != filepath.Join(real, "a") {
		t.Fatalf("Symlink nicht aufgelöst: %s %v", r, ex)
	}
	r, ex = Resolve(filepath.Join(dir, "link", "missing", "deep"))
	if ex || r != filepath.Join(real, "a", "missing", "deep") {
		t.Fatalf("nicht existierender Pfad: %s %v", r, ex)
	}
}

func TestIsUnder(t *testing.T) {
	if !IsUnder("/a/b", "/a") || !IsUnder("/a", "/a") || IsUnder("/ab", "/a") || !IsUnder("/x", "/") {
		t.Fatal("IsUnder falsch")
	}
}

func TestGlob(t *testing.T) {
	cases := []struct {
		pat, path string
		want      bool
	}{
		{"/w/**/.env", "/w/.env", true},
		{"/w/**/.env", "/w/a/b/.env", true},
		{"/w/**/.env", "/w/a/.envrc", false},
		{"/w/*.log", "/w/x.log", true},
		{"/w/*.log", "/w/sub/x.log", false},
		{"/w/sub/*", "/w/sub/x/y", true},
		{"/w/file?.txt", "/w/file1.txt", true},
		{"/w/[ab].txt", "/w/b.txt", true},
		{"/w/[!ab].txt", "/w/b.txt", false},
		{"/tmp/cc-daemon-501/**", "/tmp/cc-daemon-501/abc/control.sock", true},
		{"/w/a.b", "/w/aXb", false},
	}
	for _, c := range cases {
		if got := Match(c.pat, c.path); got != c.want {
			t.Errorf("Match(%q, %q) = %v", c.pat, c.path, got)
		}
	}
	if StaticPrefix("/w/**/.env") != "/w" || StaticPrefix("**/x") != "/" {
		t.Error("StaticPrefix falsch")
	}
	if _, err := GlobRegex("/w/[abc"); err == nil {
		t.Error("unvollständige Klasse nicht erkannt")
	}
}

func TestExpandGlob(t *testing.T) {
	dir := t.TempDir()
	for _, p := range []string{"a/.env", "b/c/.env", "node_modules/x/.env", ".git/.env", "keep.txt"} {
		os.MkdirAll(filepath.Dir(filepath.Join(dir, p)), 0o755)
		os.WriteFile(filepath.Join(dir, p), nil, 0o644)
	}
	m, trunc := ExpandGlob(dir+"/**/.env", 1000)
	if trunc {
		t.Fatal("abgeschnitten")
	}
	got := strings.Join(m, ",")
	for _, want := range []string{"a/.env", "b/c/.env", "node_modules/x/.env"} {
		if !strings.Contains(got, want) {
			t.Errorf("%s fehlt in %s", want, got)
		}
	}
	if strings.Contains(got, ".git/.env") {
		t.Error(".git sollte übersprungen werden")
	}
	_, trunc = ExpandGlob(dir+"/**/.env", 2)
	if !trunc {
		t.Error("Limit nicht erkannt")
	}
}
