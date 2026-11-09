// Package testutil enthält Hilfen für Unit-Tests.
package testutil

import (
	"path/filepath"
	"testing"
)

// IsolateConfigHome setzt XDG_CONFIG_HOME auf <home>/.config, damit
// config.GlobalConfigPath und config.ProjectsDir unter dem Test-Home landen
// und nicht unter dem XDG des CI-Runners oder der Entwickler-Maschine.
func IsolateConfigHome(t *testing.T, home string) {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
}
