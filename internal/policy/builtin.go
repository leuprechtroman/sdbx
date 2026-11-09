package policy

// Secret ist ein Eintrag der Secret-Sperrliste (Spec 5.5).
type Secret struct {
	Path     string   // relativ zu $HOME, wenn nicht absolut
	Except   []string // Pfade unterhalb, die lesbar bleiben
	Category string
}

// SecretDenylist ist die eingebaute Sperrliste. Sie gilt plattformübergreifend;
// nicht existierende Pfade schaden nicht.
var SecretDenylist = []Secret{
	{Path: ".ssh", Except: []string{"known_hosts", "known_hosts2"}, Category: "SSH/GPG"},
	{Path: ".gnupg", Category: "SSH/GPG"},
	{Path: ".aws", Category: "Cloud"},
	{Path: ".azure", Category: "Cloud"},
	{Path: ".config/gcloud", Category: "Cloud"},
	{Path: ".kube", Category: "Cloud"},
	{Path: ".oci", Category: "Cloud"},
	{Path: ".config/doctl", Category: "Cloud"},
	{Path: ".netrc", Category: "Token-Dateien"},
	{Path: ".npmrc", Category: "Token-Dateien"},
	{Path: ".pypirc", Category: "Token-Dateien"},
	{Path: ".docker/config.json", Category: "Token-Dateien"},
	{Path: ".config/gh/hosts.yml", Category: "Token-Dateien"},
	{Path: ".git-credentials", Category: "Token-Dateien"},
	{Path: ".terraform.d/credentials.tfrc.json", Category: "Token-Dateien"},
	{Path: ".password-store", Category: "Passwortspeicher"},
	{Path: "Library/Keychains", Category: "Passwortspeicher"},
	{Path: ".local/share/keyrings", Category: "Passwortspeicher"},
	{Path: "Library/Application Support/Google/Chrome", Category: "Browser"},
	{Path: "Library/Application Support/Firefox", Category: "Browser"},
	{Path: "Library/Application Support/Arc", Category: "Browser"},
	{Path: "Library/Application Support/BraveSoftware", Category: "Browser"},
	{Path: "Library/Safari", Category: "Browser"},
	{Path: "Library/Cookies", Category: "Browser"},
	{Path: ".mozilla", Category: "Browser"},
	{Path: ".config/google-chrome", Category: "Browser"},
	{Path: ".config/chromium", Category: "Browser"},
	{Path: ".config/BraveSoftware", Category: "Browser"},
	{Path: ".bash_history", Category: "Verläufe"},
	{Path: ".zsh_history", Category: "Verläufe"},
	{Path: ".local/share/fish/fish_history", Category: "Verläufe"},
	{Path: ".python_history", Category: "Verläufe"},
	{Path: ".node_repl_history", Category: "Verläufe"},
	{Path: ".psql_history", Category: "Verläufe"},
	{Path: "Library/Mail", Category: "Mail/Messenger"},
	{Path: "Library/Messages", Category: "Mail/Messenger"},
	{Path: ".thunderbird", Category: "Mail/Messenger"},
	{Path: "/etc/shadow", Category: "System"},
	{Path: "/etc/gshadow", Category: "System"},
	{Path: "/etc/sudoers", Category: "System"},
	{Path: "/etc/sudoers.d", Category: "System"},
}

// ProtectedInRepo sind geschützte Pfade relativ zu Workspace und Git-Repositories (Spec 5.4).
var ProtectedInRepo = []string{
	".git/hooks",
	".git/config",
	".git/info",
	".gitmodules",
	".envrc",
	".vscode",
	".idea",
	".zed",
	".claude/settings.json",
	".claude/settings.local.json",
	".mcp.json",
	".cursor",
	".codex",
	".husky",
}

// ProtectedInHome sind geschützte Pfade relativ zu $HOME (Spec 5.4).
var ProtectedInHome = []string{
	".bashrc", ".bash_profile", ".bash_login", ".bash_logout", ".profile",
	".zshrc", ".zshenv", ".zprofile", ".zlogin", ".zlogout",
	".config/fish",
	".gitconfig", ".config/git",
	".ssh/config",
	".config/systemd/user",
	".config/autostart",
	".config/sdbx", // globale Config und Projekt-Overrides
	"Library/LaunchAgents",
	".local/share/applications",
	// PATH-Hijacking auch ohne Eintrag in $PATH (z. B. später per .profile)
	"bin",
	".local/bin",
	".local/share/bin",
}

// ProtectedHomeDirs sind Verzeichnisse aus ProtectedInHome; fehlen sie unter einem
// Schreibbereich, legt sdbx sie vor dem Start an, damit der Schreibschutz greift.
var ProtectedHomeDirs = []string{
	".config/fish", ".config/git", ".config/systemd/user", ".config/autostart", ".config/sdbx",
	"Library/LaunchAgents", ".local/share/applications",
	"bin", ".local/bin", ".local/share/bin",
}

// HomeBinDirs sind die Bin-Verzeichnisse aus ProtectedInHome; ein exakt gleicher write-Eintrag
// hebt ihren Schutz auf (mit Warnung).
var HomeBinDirs = []string{"bin", ".local/bin", ".local/share/bin"}

// SystemBase ist bei filesystem.default: deny immer lesbar (Spec 5.1).
var SystemBase = map[string][]string{
	"darwin": {
		"/usr", "/bin", "/sbin", "/System", "/Library/Apple", "/private/etc",
		"/private/var/db/timezone", "/opt/homebrew", "/usr/local",
		"/Applications/Xcode.app", "/Library/Developer/CommandLineTools", "/dev",
		"/private/var/select", "/Library/Preferences",
	},
	"linux": {
		"/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32", "/etc",
		"/nix/store", "/opt", "/proc", "/sys", "/dev", "/run/systemd/resolve",
	},
}

// MachGroups sind die Mach-Service-Gruppen (Spec 7.4, gemessen unter macOS 26.6.2).
var MachGroups = map[string][]string{
	"default": {
		"com.apple.logd",
		"com.apple.system.notification_center",
		"com.apple.system.opendirectoryd.libinfo",
		"com.apple.system.opendirectoryd.membership",
		"com.apple.bsd.dirhelper",
		"com.apple.SystemConfiguration.configd",
		"com.apple.SystemConfiguration.DNSConfiguration",
		"com.apple.trustd.agent",
	},
	"keychain": {
		"com.apple.SecurityServer",
		"com.apple.authd",
		"com.apple.trustd.agent",
	},
	"fsevents": {"com.apple.FSEvents"},
	"dns":      {"com.apple.dnssd.service", "com.apple.mDNSResponder"},
}

// MachNoReport werden stumm verweigert (Spec 7.4).
var MachNoReport = []string{"com.apple.analyticsd"}

// MachDangerousPrefixes dürfen nur einzeln und mit Warnung freigegeben werden.
var MachDangerousPrefixes = []string{
	"com.apple.pasteboard.",
	"com.apple.coreservices.appleevents",
	"com.apple.lsd.",
	"com.apple.coreservices.launchservicesd",
	"com.apple.CARenderServer",
	"com.apple.windowserver.",
	"com.apple.tccd",
	"com.apple.accessibility.",
	"com.apple.screencapture",
	"com.apple.replayd",
}

// BaseEnvAllowlist wird bei env.mode: allowlist übernommen (Spec 7.2).
var BaseEnvAllowlist = []string{
	"PATH", "HOME", "USER", "LOGNAME", "SHELL", "TERM", "TERMINFO", "COLORTERM",
	"COLUMNS", "LINES", "LANG", "LANGUAGE", "LC_*", "TZ", "EDITOR", "VISUAL", "PAGER",
	"NO_COLOR", "FORCE_COLOR", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME",
}

// BaseEnvDeny sind Sperrmuster, die in beiden Modi gelten (Spec 7.2).
var BaseEnvDeny = []string{
	"*_TOKEN", "*_SECRET", "*_SECRET_*", "*_PASSWORD", "*_PASSWD", "*_API_KEY", "*_ACCESS_KEY*",
	"*_PRIVATE_KEY", "AWS_*", "AZURE_*", "GOOGLE_APPLICATION_CREDENTIALS", "GH_*", "GITHUB_*",
	"NPM_TOKEN", "SSH_AUTH_SOCK", "GPG_AGENT_INFO", "DBUS_SESSION_BUS_ADDRESS", "DISPLAY",
	"WAYLAND_DISPLAY", "XAUTHORITY",
}

// KnownSocketLocations werden unter Linux immer maskiert (Spec 7.1).
// Pfade ohne führenden Schrägstrich gelten relativ zu $HOME.
var KnownSocketLocations = []string{
	"/var/run/docker.sock", "/run/docker.sock", "/run/podman", "/run/containerd",
	"/run/dbus", "/var/run/dbus", "/tmp/.X11-unix",
	".gnupg", ".docker", ".colima", ".orbstack", ".lima", ".local/share/containers",
}
