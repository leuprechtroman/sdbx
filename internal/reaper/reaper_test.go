package reaper

import (
	"strings"
	"testing"
)

func TestReadStatus(t *testing.T) {
	if c, ok := ReadStatus(strings.NewReader("7\n")); !ok || c != 7 {
		t.Errorf("7: %d %v", c, ok)
	}
	if _, ok := ReadStatus(strings.NewReader("")); ok {
		t.Error("leer gilt als gemeldet")
	}
}

// Ohne Sandbox darf der Aufräumer nie kill(-1) senden.
func TestNotSandboxed(t *testing.T) {
	if sandboxed() {
		t.Fatal("Testprozess gilt als sandboxed – kill(-1) träfe alle Prozesse des Nutzers")
	}
}

func TestExitCodes(t *testing.T) {
	for argv, want := range map[string]int{"true": 0, "false": 1, "gibt-es-nicht-xyz": 127} {
		if got := run([]string{argv}); got != want {
			t.Errorf("%s: %d, erwartet %d", argv, got, want)
		}
	}
	if got := run([]string{"sh", "-c", "kill -TERM $$"}); got != 143 {
		t.Errorf("Signal: %d, erwartet 143", got)
	}
}
