// Package backend definiert die Schnittstelle der plattformspezifischen Sandbox-Backends.
package backend

// Runtime enthält die Laufzeitdaten eines Laufs, die das Backend braucht.
type Runtime struct {
	RunID   string
	RunDir  string // privates Verzeichnis des Supervisors (Host-Pfad)
	SdbxTmp string // privates Temp-Verzeichnis (Host-Pfad)
	SdbxExe string // Pfad des sdbx-Binarys
	Cwd     string // Arbeitsverzeichnis des Zielprozesses (Host-Pfad)

	// Netzwerk
	ProxyPort       int            // macOS: TCP-Port auf 127.0.0.1; Linux: Port im Namespace
	ProxyHostSocket string         // Linux: Unix-Socket des Proxys auf dem Host
	LocalSockets    map[int]string // Linux: lokaler Port → Unix-Socket auf dem Host

	// Sockets, deren Verzeichnisse erreichbar sein sollen (z. B. Daemons in der Sandbox)
	SocketAllowDirs []string

	Argv []string
	Env  []string
}

// Launch ist die fertige Startbeschreibung.
type Launch struct {
	Path  string
	Args  []string // inklusive argv[0]
	Env   []string
	Dir   string
	Notes []string
	// Files sind zusätzliche Dateien, die an den Kindprozess vererbt werden.
	Files []string
	// Reaper: Der Kindprozess ist "sdbx __reap", der eigentliche Befehl läuft als dessen Kind (macOS).
	Reaper bool
}
