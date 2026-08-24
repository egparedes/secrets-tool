# Design: rename `secret` to `secrets`, split library from CLI

Date: 2026-08-24
Status: approved

> **2026-08-24 revision (post whole-branch review):** the library
> resolution order and `$SECRETS_LIB` override strictness described below
> were revised after the implementation shipped. Two defects traced back
> to this spec, not to the code that followed it: (1) `$PREFIX/lib` was
> listed ahead of `$PREFIX/share/secrets`, so anything writable at
> `$PREFIX/lib` could shadow the installed library for every user of an
> installed `secrets`; (2) "first readable candidate wins" read as
> license for a set-but-unreadable `$SECRETS_LIB` to fall through to the
> candidate list, i.e. to fail open, which is the wrong failure mode for
> a tool handling key material. The "Library resolution" section below
> reflects the corrected order and the corrected override behavior.

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

First readable candidate wins, with one exception: a `$SECRETS_LIB` that
is set to a non-empty, unreadable path is a hard error rather than a
candidate that simply failed to match -- see below the table.

| # | Candidate | Covers |
| - | --------- | ------ |
| 1 | `$SECRETS_LIB` | explicit override (empty falls through; set-and-unreadable is a hard error) |
| 2 | `$dir/../share/secrets/secrets-lib.sh` | installed, any prefix |
| 3 | `$dir/../lib/secrets-lib.sh` | git checkout |
| 4 | `$dir/secrets-lib.sh` | both files in one directory |
| 5 | `$HOME/.local/share/secrets/secrets-lib.sh` | user install |
| 6 | `/usr/local/share/secrets/secrets-lib.sh` | system install |
| 7 | `/usr/share/secrets/secrets-lib.sh` | distro package |

Candidate 2 is prefix-relative, which is what lets `make install
PREFIX=~/.local` and `PREFIX=/usr/local` both work with no path
substituted at install time. It is tried *before* candidate 3
specifically so that a stray or hand-placed `$dir/../lib/secrets-lib.sh`
cannot shadow an installed library: anyone able to write `$PREFIX/lib`
would otherwise substitute the library every user of an installed
`secrets` runs, and a stale file left there would shadow real upgrades
indefinitely. Candidate 3 exists for the git-checkout layout, where no
`../share/secrets` directory is present to match first, so the order is
free of behavioral cost for that case.

Before the candidate loop runs, a `$SECRETS_LIB` that is set to a
non-empty value and is not readable is a hard error: the CLI prints
`secrets: SECRETS_LIB=<path> not readable` to stderr and exits 127
immediately, without trying any candidate. An *empty* `$SECRETS_LIB`
(as produced by `SECRETS_LIB=`) is not an error and falls through to
candidate 2 as before -- this is the convention the test suite relies on
for exercising the candidate list. The distinction matters because this
tool handles key material: a typo'd override must fail loudly rather
than risk silently sourcing a different, possibly stale or system-wide,
library.

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

Directories are created under `umask 022` rather than chmod'ed afterwards.
The distinction matters twice: `mkdir -p` under the caller's umask would
leave a `umask 077` root install unreadable to every other user (and would
miss intermediate components entirely), while an explicit `chmod` would
need ownership it may not have, and would silently rewrite the mode of a
prefix directory that already existed -- dropping setgid on layouts like
Debian's historical `/usr/local/bin`. Setting the umask affects only the
directories `make install` actually creates.

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
