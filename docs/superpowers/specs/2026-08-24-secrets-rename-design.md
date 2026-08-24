# Design: rename `secret` to `secrets`, split library from CLI

Date: 2026-08-24
Status: approved

## Purpose

The project ships one sourceable file, `secret.sh`, defining a `secret`
shell function. Two problems follow from that shape:

1. **The name is singular while everything around it is plural.** The
   environment variables are `SECRETS_*` and the store is `~/.secrets`.
   The command is the odd one out.
2. **Sourcing is the only entry point.** A shell function is invisible to
   child processes, so every script that wants a secret must know where
   the library lives and source it. There is no `secrets` command.

This design renames the project to `secrets` and splits it into a
library plus a command-line front end that wraps it. The library stays
sourceable for callers that want in-process use; the CLI serves everyone
else, including scripts, and carries the shell completions.

## Layout

```
bin/secrets              CLI entry point (executable, #!/bin/sh)
lib/secrets-lib.sh       the library (no shebang, sourceable)
tests/test-secrets.sh    one suite, covering library and CLI
Makefile                 install / uninstall / test
README.md  CHANGELOG.md
```

`secret.sh` is deleted outright. Version 0.1.0 is unreleased, so there is
no installed base to keep working and no deprecation shim.

The file keeps the `-lib` suffix even though it sits in `lib/`. Users
curl it standalone into a share directory, where a bare `secrets.sh`
would not say what it is.

## Library

A mechanical rename, no behavior change:

| Before | After |
| ------ | ----- |
| `secret()` | `secrets()` |
| `_secret_*` | `_secrets_*` |
| `_secret_complete` | `_secrets_complete` |
| `secret: ` message prefix | `secrets: ` |
| `secret <cmd>` in emitted completions | `secrets <cmd>` |

Unchanged: every `SECRETS_*` variable, the `~/.secrets` default store,
the `.age` on-disk format, every subcommand name, and every exit code. A
store written by `secret` is read by `secrets` with no migration.

The subshell-body convention `f() (...)` stays, and so does the
leak-detection test that enforces it. Sourcing the library must remain
safe under `set -eu`.

## CLI

`bin/secrets` resolves its own directory from `$0`, sources the library,
calls `secrets "$@"`, and propagates the exit status. It holds no
secret-store logic of its own. It runs under `set -u` but not `set -e`,
so the library's exit status is propagated deliberately rather than
aborting the wrapper.

### Library resolution

First readable candidate wins:

| # | Candidate | Covers |
| - | --------- | ------ |
| 1 | `$SECRETS_LIB` | explicit override |
| 2 | `$dir/../lib/secrets-lib.sh` | git checkout |
| 3 | `$dir/../share/secrets/secrets-lib.sh` | installed, any prefix |
| 4 | `$dir/secrets-lib.sh` | both files in one directory |
| 5 | `$HOME/.local/share/secrets/secrets-lib.sh` | user install |
| 6 | `/usr/local/share/secrets/secrets-lib.sh` | system install |
| 7 | `/usr/share/secrets/secrets-lib.sh` | distro package |

Candidate 3 is prefix-relative, which is what lets `make install
PREFIX=~/.local` and `PREFIX=/usr/local` both work with no path
substituted at install time.

Exhausting the list prints `secrets: cannot find secrets-lib.sh (set
SECRETS_LIB to its path)` and exits 127, matching the library's existing
127 for a missing age backend.

### Symlinks are not resolved

`$0` is used as-is. `readlink -f` is not POSIX, and the project's
portability claim is "strictly POSIX sh, sole exception `mktemp`";
a second exception is not worth this.

Consequence: symlinking `bin/secrets` out of a checkout into a PATH
directory falls through to candidates 5-7 and fails unless the library
was also installed. `SECRETS_LIB` is the documented escape hatch, and
`make install` copies rather than symlinks, so the supported install
paths are unaffected.

### Shell completions

Unchanged in structure. The emitted scripts register against the command
word `secrets` and shell out to `secrets ls` for stored names. Because
that is a command substitution, it resolves the PATH executable exactly
as it previously resolved the sourced function; completion of secret
names works in bash, zsh, and fish with no sourcing in the interactive
shell.

Consequence of the CLI being a child process: `SECRETS_DIR` and friends
must now be *exported* to take effect. An unexported `SECRETS_DIR` is
silently ignored and the default store is used instead. The README must
say so.

## Makefile

Targets `install`, `uninstall`, and `test` (which runs
`sh tests/test-secrets.sh`). Honors `PREFIX` (default
`/usr/local`) and `DESTDIR`. Installs `bin/secrets` to
`$(PREFIX)/bin/secrets` mode 755 and `lib/secrets-lib.sh` to
`$(PREFIX)/share/secrets/secrets-lib.sh` mode 644. Copies; never
symlinks.

## Testing

One suite, `tests/test-secrets.sh`. The existing `SECRET_SH` override
becomes `SECRETS_LIB`, the same variable the CLI reads, so suite and CLI
agree on one knob.

A new `== cli wrapper ==` section covers: resolution from a checkout,
from a synthesized `$PREFIX/share` tree, and via `SECRETS_LIB`; the 127
failure with no library present; exit-code propagation through the extra
process (1 for a missing secret, 2 for an invalid name); stdin piping
through the CLI; and completions emitting `secrets` rather than
`secret`.

The CLI always runs under `#!/bin/sh` regardless of `TEST_SHELL`, so
these checks are shell-independent and simply repeat across the matrix.
That redundancy is accepted in exchange for keeping CI at one command.

## Touch points

- `secret.sh` -> `lib/secrets-lib.sh`, with the header comment rewritten:
  new command name, new install and sourcing paths, `SECRETS_LIB`
  documented alongside the other variables.
- `bin/secrets`: new.
- `Makefile`: new.
- `tests/test-secret.sh` -> `tests/test-secrets.sh`: rename every call,
  switch the override variable, update the leak-check helper names, add
  the CLI section.
- `.github/workflows/ci.yml`: shellcheck targets become
  `lib/secrets-lib.sh`, `bin/secrets`, `tests/test-secrets.sh`; the
  runner becomes `tests/test-secrets.sh`. Matrix unchanged.
- `README.md`: install via `make install` and via curl-two-files; usage
  block renamed; a "use as a library" section; `SECRETS_LIB` added to the
  config table; the export caveat; updated check count.
- `CHANGELOG.md`: reword the 0.1.0 entry, which currently claims the tool
  is "sourced as a single file".
- `docs/superpowers/` specs and plans: left untouched. They record
  decisions made when the tool was named `secret`.

## Out of scope

No `secret` compatibility shim or alias. No symlink resolution. No
packaging beyond the Makefile (no Homebrew formula, no distro packaging,
no release tarball). No change to the store format, subcommand set, or
exit codes. No new subcommands.
