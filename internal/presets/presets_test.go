package presets_test

import (
	"testing"

	"sdbx/internal/config"
	"sdbx/internal/presets"
)

func TestAllPresetsValid(t *testing.T) {
	names := presets.Names()
	if len(names) != 5 {
		t.Fatalf("Presets: %v", names)
	}
	for _, n := range names {
		if _, err := config.LoadPreset(n); err != nil {
			t.Errorf("%s: %v", n, err)
		}
		if presets.Description(n) == "" {
			t.Errorf("%s: Beschreibung fehlt", n)
		}
	}
}
