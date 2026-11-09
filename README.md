# sdbx

![Orange pixel mascot digging in a sandbox](assets/title.svg)

![Status: Beta](https://img.shields.io/badge/Status-Beta-orange)
[![CI](https://github.com/leuprechtroman/sdbx/actions/workflows/ci.yml/badge.svg)](https://github.com/leuprechtroman/sdbx/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/leuprechtroman/sdbx?logo=github&label=release)](https://github.com/leuprechtroman/sdbx/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue)](LICENSE)
[![Go 1.23](https://img.shields.io/badge/Go-1.23-00ADD8?logo=go&logoColor=white)](https://go.dev/)
![platform: macOS | Linux](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey)
![arch: amd64 | arm64](https://img.shields.io/badge/arch-amd64%20%7C%20arm64-lightgrey)
[![docs: man page](https://img.shields.io/badge/docs-man%20page-4f46e5)](docs/sdbx.1)

`sdbx` runs a command and all of its child processes in an **OS-level sandbox** – no VM, no container.

The process uses your real tools and your home directory, but is restricted by kernel mechanisms:

| Platform | Mechanism |
|---|---|
| macOS | Seatbelt (`sandbox-exec`) |
| Linux | bubblewrap + Landlock + seccomp |

It is built mainly for **AI coding agents** (Claude Code, Codex CLI, …) and for tools whose code you don't fully trust (`npm install` with postinstall scripts).

The full specification (in German) is in [`docs/spezifikation.md`](docs/spezifikation.md); the man page is [`docs/sdbx.1`](docs/sdbx.1). sdbx's own messages are currently in German.

## What the sandbox protects

With the secure defaults:

- **Workspace** writable, rest of the filesystem readable
- **Secrets** blocked (`~/.ssh`, `~/.aws`, cloud credentials, browser profiles, shell histories …)
- **Network** only through the built-in proxy, to allowed domains
- **Unix sockets** of other services masked (Docker, D-Bus, agents …)
- **Environment variables** filtered (no tokens / `SSH_AUTH_SOCK` / `LD_PRELOAD` by default)
- **Persistence** blocked: Git hooks, shell rc files, autostart, `~/bin`, `~/.local/bin`, editor tasks, `~/.config/sdbx/`

Fail-closed: if a requested restriction can't be enforced, the command doesn't start (exit 126) – unless degraded mode is explicitly allowed.

## Installation

Requirements: **Go ≥ 1.23**, no CGO dependencies. On Linux additionally `bubblewrap` (`apt install bubblewrap`).

```bash
git clone <repo> && cd sdbx
make build                 # → bin/sdbx
bin/sdbx doctor            # check the platform
# optionally put it on PATH, together with the man page:
cp bin/sdbx ~/.local/bin/
mkdir -p ~/.local/share/man/man1 && cp docs/sdbx.1 ~/.local/share/man/man1/
```

You can also read the man page directly: `man ./docs/sdbx.1`.

Cross builds: `make cross` → `dist/sdbx-{linux,darwin}-{amd64,arm64}`.

## Quick start

```bash
cd my-project
sdbx init                  # create an override in ~/.config/sdbx/projects/ (TUI)
sdbx check                 # configuration and platform matrix
sdbx run -- npm test
sdbx run -- clausona run claude:work
sdbx codex                 # short for sdbx run -- codex
```

Without your own rules, the defaults above apply. `sdbx init` does **not** write into the repo but into `~/.config/sdbx/` – outside the writable workspace.

## Configuration

```
~/.config/sdbx/
  config.yaml                 # global (optional)
  projects/
    my-project.yaml           # exceptions for one workspace
```

Example project override:

```yaml
version: 1
project: ~/Code/my-project     # the workspace this applies to (Git root)

include: [node, git-https]

filesystem:
  write: [~/.cache/my-tool]
  deny: ["**/.env"]

network:
  allow:
    - api.example.com
    - "*.cdn.example.com"

integrations:
  clausona: ro                 # or: { mode: rw, profiles: all }
```

| Source | Role |
|---|---|
| Built-in defaults | secure baseline |
| `~/.config/sdbx/config.yaml` | global settings |
| Integrations (e.g. clausona) | permissions for the detected tool |
| `~/.config/sdbx/projects/*.yaml` | override, if `project:` matches the current workspace |
| CLI flags | applied last |

If `XDG_CONFIG_HOME` is set, everything lives under `$XDG_CONFIG_HOME/sdbx/`.

A few rules for overrides:

- Relative paths in entries (and `${CONFIG_DIR}`) resolve against the workspace, not against `projects/`. Only `include:` paths are relative to the file itself.
- Files without `project:` are skipped during lookup – useful for shared fragments, e.g. a `projects/shared.yaml` that several overrides pull in with `include: [./shared.yaml]`.
- If two files match the same workspace, sdbx aborts with an error.

An old `sdbx.yaml` in the repo is **no longer** loaded (warning); it stays write-protected if it still exists. To migrate, move it to `~/.config/sdbx/projects/<name>.yaml` and add `project: <path>`. Use `--config <file>` to load a file explicitly.

Protected paths (Git hooks, `~/.config/sdbx`, shell rc files …) stay write-protected even if a `write` entry covers or names them exactly. Protection can only be lifted with `filesystem.unprotect` (with a warning). Exception: an exactly matching `write` entry unlocks `~/bin`, `~/.local/bin` and `~/.local/share/bin`, e.g. for installers – also with a warning.

Useful commands:

```bash
sdbx explain ~/.ssh/id_ed25519
sdbx explain api.example.com:443
sdbx policy --format yaml
sdbx learn -- npm install      # collect violations, print a YAML suggestion
```

## Commands

| Command | Purpose |
|---|---|
| `sdbx run [flags] -- <command>` | run a command in the sandbox |
| `sdbx <command> [args…]` | short for `run --` |
| `sdbx shell` | `$SHELL` in the sandbox |
| `sdbx check` | configuration and platform matrix |
| `sdbx policy --format yaml\|json\|seatbelt\|bwrap` | resolved policy / backend config |
| `sdbx explain <path\|host[:port]>` | which rule applies |
| `sdbx learn -- <command>` | learning mode |
| `sdbx init` | create a project override (TUI or flags/`--yes`) |
| `sdbx init --global` | create the global `config.yaml` |
| `sdbx doctor` | check prerequisites |
| `sdbx presets` | list presets and integrations |

**Exit codes:** target command's code unchanged · 124 timeout · 125 configuration error · 126 sandbox could not be set up · 127 command not found · 128+n signal.

## Platforms

**macOS:** Seatbelt profile, proxy on localhost, a cleanup process (`__reap`) that also kills detached child processes. Clipboard, keychain and AppleEvents are blocked by default.

**Linux:** bwrap (namespaces, mounts), Landlock as an additional layer, seccomp (among other things no `ptrace`, no `TIOCSTI`, restricted networking). Without a PID namespace (e.g. with clausona), sdbx acts as a subreaper and cleans up orphaned descendants. Memory/process limits need cgroup v2 via `systemd-run --user`.

Restricted fallback without bwrap: `linux.backend: landlock` with `degraded: true` (less protection, see spec §5.6).

## Tests

```bash
make test      # unit tests + vet
make race      # race detector
make escape    # escape tests: real binary, real sandbox (not as root)
make cover     # coverage from unit + escape tests
```

Among other things, the escape tests try: writing outside the workspace, reading SSH keys, tampering with Git hooks and config, bypassing the proxy, DNS rebinding, the Docker socket, signal/timeout behaviour, detached background processes. On macOS additionally clipboard, keychain and AppleEvents; on Linux ptrace, namespaces, the Landlock backend and cgroup limits.

## Dependencies

The only third-party library is `gopkg.in/yaml.v3`. Landlock, seccomp (with its own BPF assembler), Punycode, CLI and TUI are implemented in-house.

## Limitations

In short (details in spec §10.5):

- No protection against kernel exploits or side channels
- Exfiltration through explicitly allowed domains remains possible
- On Linux, globs and socket masking only apply to paths that exist at start; new sockets created outside afterwards are a residual risk
- Repositories created during a run are reported; their Git config can still be modified before the next run (hooks are blocked by regex on macOS)
- The macOS keychain can only be allowed as a whole
