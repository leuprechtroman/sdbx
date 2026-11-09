//go:build !linux

package supervisor

// becomeSubreaper: Unter macOS übernimmt der Aufräumprozess in der Sandbox (sdbx __reap) diese Aufgabe.
func becomeSubreaper() bool { return false }
