//go:build !linux

package linux

import "fmt"

// RunInit ist nur unter Linux verfügbar.
func RunInit(string) error { return fmt.Errorf("__init ist nur unter Linux verfügbar") }

// LandlockABI ist außerhalb von Linux immer 0.
func LandlockABI() int { return 0 }
