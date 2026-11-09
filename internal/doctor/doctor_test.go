package doctor

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	home := t.TempDir()
	os.MkdirAll(filepath.Join(home, ".sdbx", "lima"), 0o755)
	var b bytes.Buffer
	Run(&b, Options{Platform: runtime.GOOS, Home: home, UID: os.Getuid()})
	out := b.String()
	if !strings.Contains(out, "Altlast") {
		t.Errorf("Prototyp-Hinweis fehlt:\n%s", out)
	}
	if runtime.GOOS == "linux" && !strings.Contains(out, "bubblewrap") {
		t.Errorf("bwrap-Prüfung fehlt:\n%s", out)
	}
	var u bytes.Buffer
	if code := Run(&u, Options{Platform: "plan9"}); code != 1 {
		t.Error("unbekannte Plattform muss fehlschlagen")
	}
}
