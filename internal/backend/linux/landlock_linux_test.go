package linux

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

func TestHandledFS(t *testing.T) {
	const base = uint64(1<<13 - 1) // execute … make_sym (ABI 1)
	for abi, want := range map[int]uint64{
		1: base, 2: base | fsRefer, 3: base | fsRefer | fsTruncate, 4: base | fsRefer | fsTruncate,
		5: base | fsRefer | fsTruncate | fsIoctlDev,
	} {
		if got := handledFS(abi); got != want {
			t.Errorf("ABI %d: %b, erwartet %b", abi, got, want)
		}
	}
}

// Landlock gilt für den Thread und ist nicht rücknehmbar: Der Versuch läuft im erneut gestarteten Testbinary.
func TestApplyLandlock(t *testing.T) {
	if dir := os.Getenv("SDBX_LANDLOCK_HELPER"); dir != "" {
		landlockHelper(t, dir)
		return
	}
	if LandlockABI() == 0 {
		t.Skip("Kernel ohne Landlock")
	}
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "frei"), 0o755)
	os.MkdirAll(filepath.Join(dir, "gesperrt"), 0o755)
	os.WriteFile(filepath.Join(dir, "gesperrt", "lesbar.txt"), []byte("INHALT"), 0o644)
	os.WriteFile(filepath.Join(dir, "datei.txt"), []byte("x"), 0o644)
	cmd := exec.Command(os.Args[0], "-test.run=^TestApplyLandlock$", "-test.v")
	cmd.Env = append(os.Environ(), "SDBX_LANDLOCK_HELPER="+dir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Hilfsprozess: %v\n%s", err, out)
	}
	for _, want := range []string{"frei:ok", "gesperrt:EACCES", "lesen:INHALT", "datei:ok", "mkdir:EACCES", "nachbar:EACCES"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("%q fehlt:\n%s", want, out)
		}
	}
}

func landlockHelper(t *testing.T, dir string) {
	runtime.LockOSThread()
	spec := &LandlockSpec{Read: []string{"/"}, Write: []string{filepath.Join(dir, "frei")}, ReadWriteFile: []string{filepath.Join(dir, "datei.txt")}}
	if _, err := ApplyLandlock(spec); err != nil {
		t.Fatal(err)
	}
	try := func(name string, err error) {
		switch {
		case err == nil:
			fmt.Println(name + ":ok")
		case errors.Is(err, syscall.EACCES):
			fmt.Println(name + ":EACCES")
		default:
			fmt.Println(name+":", err)
		}
	}
	try("frei", os.WriteFile(filepath.Join(dir, "frei", "x"), []byte("x"), 0o644))
	try("gesperrt", os.WriteFile(filepath.Join(dir, "gesperrt", "x"), []byte("x"), 0o644))
	b, _ := os.ReadFile(filepath.Join(dir, "gesperrt", "lesbar.txt"))
	fmt.Println("lesen:" + string(b))
	try("datei", os.WriteFile(filepath.Join(dir, "datei.txt"), []byte("y"), 0o644))
	try("mkdir", os.Mkdir(filepath.Join(dir, "neu"), 0o755))
	try("nachbar", os.WriteFile(filepath.Join(dir, "nachbar.txt"), []byte("x"), 0o644))
}
