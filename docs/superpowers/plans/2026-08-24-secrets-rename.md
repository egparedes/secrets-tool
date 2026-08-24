# `secrets` Rename and Library/CLI Split Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rename the project from `secret` to `secrets` and split the single sourceable file into `lib/secrets-lib.sh` (library) plus `bin/secrets` (CLI front end), with a Makefile, updated tests, CI, and README.

**Architecture:** The library keeps every behavior it has today; only identifiers and the message prefix change. A new ~35-line `bin/secrets` resolves the library from a fixed candidate list rooted at its own `$0` directory, sources it, calls `secrets "$@"`, and propagates the exit status. No path is substituted at install time — a prefix-relative candidate (`$dir/../share/secrets/secrets-lib.sh`) makes `make install` work for any `PREFIX`.

**Tech Stack:** POSIX `sh` (dash/bash/zsh compatible), age/rage backends, plain-sh test harness, GNU/BSD-compatible Makefile, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-08-24-secrets-rename-design.md`

## Global Constraints

- Strictly POSIX `sh`. The only permitted non-POSIX tool is `mktemp`. Do **not** introduce `readlink`, `realpath`, or any other new dependency.
- Every library subcommand keeps its subshell body `f() (...)` so nothing leaks into a sourcing shell. The leak-detection test enforces this.
- Sourcing `lib/secrets-lib.sh` must stay safe under `set -eu`.
- `shellcheck` must be clean on `lib/secrets-lib.sh`, `bin/secrets`, and `tests/test-secrets.sh`. CI runs it and will fail the build otherwise.
- Behavior that must NOT change: every `SECRETS_*` variable name, the `~/.secrets` default store, the `.age` on-disk format, every subcommand name, and every exit code (0 success, 1 missing/exists, 2 invalid name or usage, 3 missing identity/recipients, 127 missing backend).
- The word `secret` stays singular where it is English prose (`no such secret:`, `delete a secret`, `rekeyed N secret(s)`) and in the test suite's plaintext payloads. Only the program name becomes `secrets`.
- Baseline before any change: `sh tests/test-secret.sh` prints `79 passed, 0 failed`. Every task must end with the suite fully green.
- Commit after every task.

---

### Task 1: Rename the library and suite into their new homes

**Files:**
- Move: `secret.sh` -> `lib/secrets-lib.sh`
- Move: `tests/test-secret.sh` -> `tests/test-secrets.sh`
- Modify: `.github/workflows/ci.yml:20-21` (shellcheck targets), `.github/workflows/ci.yml:64` (test runner)

**Interfaces:**
- Produces: `lib/secrets-lib.sh` defining the shell function `secrets` (dispatcher) and helpers `_secrets_age`, `_secrets_keygen`, `_secrets_name`, `_secrets_need_recipients`, `_secrets_need_identity`, `_secrets_encrypt_to`, `_secrets_init`, `_secrets_enc`, `_secrets_dec`, `_secrets_ls`, `_secrets_rm`, `_secrets_rename`, `_secrets_recipients`, `_secrets_rekey`, `_secrets_completions`, `_secrets_help`. Task 2's `bin/secrets` calls `secrets "$@"` after sourcing this file.
- Produces: `tests/test-secrets.sh`, which sets `SECRETS_LIB` (unexported) to the path of the library under test, replacing the old `SECRET_SH`, and defines the helpers `ok`, `bad`, `check "<label>" "<want>" "<got>"` plus the variables `T` (temp dir) and `pass`/`fail` counters. Task 2 appends a section to this file.

- [ ] **Step 1: Confirm the baseline is green before touching anything**

```bash
sh tests/test-secret.sh 2>&1 | tail -2
```

Expected: `79 passed, 0 failed`. If it is not green, stop and report — the rest of this plan assumes a clean starting point.

- [ ] **Step 2: Move both files with git so history follows**

```bash
mkdir -p lib
git mv secret.sh lib/secrets-lib.sh
git mv tests/test-secret.sh tests/test-secrets.sh
```

- [ ] **Step 3: Rename every call site in the test suite**

The subcommand alternation is deliberately explicit: a blind `s/secret/secrets/g` would corrupt the plaintext payload on line 43 (`printf 'secret\nuser: enrique...'`) and the prose in `missing secret rc`.

```bash
sed -i \
  -e 's/\bSECRET_SH\b/SECRETS_LIB/g' \
  -e 's|\.\./secret\.sh|../lib/secrets-lib.sh|' \
  -e 's|Test suite for secret\.sh|Test suite for secrets-lib.sh|' \
  -e 's|/tmp/secret-test\.|/tmp/secrets-test.|' \
  -e 's/_secret_age/_secrets_age/g' \
  -e 's/_secret_keygen/_secrets_keygen/g' \
  -e 's/\bsecret \(init\|enc\|dec\|ls\|rm\|rename\|recipients\|rekey\|completions\|help\|get\|bogus\)\b/secrets \1/g' \
  tests/test-secrets.sh
```

Then hand-edit the sourcing line. The sed above rewrites it to
`. "${SECRETS_LIB:-$(dirname "$0")/../lib/secrets-lib.sh}"`, which only
*reads* the variable — Task 2 needs it as an actual variable it can `cp`.
Replace those two lines with:

```sh
SECRETS_LIB=${SECRETS_LIB:-$(dirname "$0")/../lib/secrets-lib.sh}
# shellcheck disable=SC1090  # path is computed
. "$SECRETS_LIB"
```

Do **not** add `SECRETS_LIB` to the `export` line above it. It must stay
unexported: Task 2's resolution tests rely on child `secrets` processes
*not* inheriting it, otherwise every candidate resolves through case [1]
and the fallback chain is never actually exercised.

- [ ] **Step 4: Verify only the intended `secret` occurrences survive in the suite**

```bash
grep -n '\bsecret\b' tests/test-secrets.sh
```

Expected: exactly five lines — 43, 44, 47 (the pass-style plaintext payload and the assertions on it) and 61, 62 (the prose `missing secret rc` / `missing secret empty` labels). Anything else is a bad substitution; fix it before continuing.

- [ ] **Step 5: Run the suite to watch it fail**

```bash
sh tests/test-secrets.sh 2>&1 | tail -3
```

Expected: FAIL. The suite now calls `secrets ...` but the library still defines `secret`, so nearly every check errors with `secrets: not found`. This is the red half of the cycle — it proves the suite is actually exercising the renamed surface.

- [ ] **Step 6: Rename the library**

`_secret_` covers every helper except zsh's completion function `_secret()`, which has no trailing underscore and is handled by the third expression. The `'secret: ` pattern targets the program-name prefix inside `printf` format strings and leaves `no such secret:` alone because that substring is not preceded by a quote.

```bash
sed -i \
  -e 's/_secret_/_secrets_/g' \
  -e 's/^secret()/secrets()/' \
  -e 's/^\(\s*\)_secret()/\1_secrets()/' \
  -e "s/'secret: /'secrets: /g" \
  -e 's/\bsecret ls\b/secrets ls/g' \
  -e 's/complete -F _secrets_complete secret\b/complete -F _secrets_complete secrets/' \
  -e 's/compdef _secret secret\b/compdef _secrets secrets/' \
  -e 's/complete -c secret\b/complete -c secrets/g' \
  -e 's/\bsecret \(init\|enc\|dec\|ls\|rm\|rename\|recipients\|rekey\|completions\|help\)\b/secrets \1/g' \
  -e 's/usage: secret /usage: secrets /' \
  -e '2s/── secret ──/── secrets ──/' \
  -e '41s|completions/secret\.fish|completions/secrets.fish|' \
  lib/secrets-lib.sh
```

- [ ] **Step 7: Trim the header banner back to 79 columns**

Line 2 gained a character from `secret` -> `secrets`, so its box-drawing rule is now 80 wide while line 49 is 79.

```bash
sed -i '2s/─$//' lib/secrets-lib.sh
awk 'NR==2||NR==49{printf "line %d: %d chars\n", NR, length($0)}' lib/secrets-lib.sh
```

Expected: both lines report `79 chars`.

- [ ] **Step 8: Verify only prose `secret` survives in the library**

```bash
grep -n '\bsecret\b' lib/secrets-lib.sh
grep -n '_secret[^s]' lib/secrets-lib.sh
```

Expected from the first command: lines 3, 12, 13, 186, 205, 221, 243, 285, 327, 346, 347 — all English prose (`Tiny secret store`, `delete a secret`, `no such secret: %s`, `rekeyed %d secret(s)`, `overwrite existing secret`). Expected from the second command: no output at all. Any `_secret_` identifier remaining is a bug.

- [ ] **Step 9: Run the suite to verify it passes**

```bash
sh tests/test-secrets.sh 2>&1 | tail -3
```

Expected: `79 passed, 0 failed`.

- [ ] **Step 10: Run the suite under all three shells**

```bash
for s in dash bash zsh; do printf '%s: ' "$s"; $s tests/test-secrets.sh 2>&1 | tail -1; done
```

Expected: `79 passed, 0 failed` three times.

- [ ] **Step 11: Verify shellcheck is clean**

```bash
shellcheck --shell=sh lib/secrets-lib.sh tests/test-secrets.sh && echo CLEAN
```

Expected: `CLEAN` with no findings.

- [ ] **Step 12: Point CI at the new paths**

In `.github/workflows/ci.yml`, replace the two shellcheck lines in the `lint` job:

```yaml
          shellcheck --shell=sh lib/secrets-lib.sh
          shellcheck --shell=sh tests/test-secrets.sh
```

and the final `run` line of the `test` job:

```yaml
        run: ${{ matrix.shell }} tests/test-secrets.sh
```

`bin/secrets` is added to the lint job in Task 2, not here — it does not exist yet.

- [ ] **Step 13: Commit**

```bash
git add -A
git commit -m "Rename secret to secrets, move library to lib/secrets-lib.sh"
```

---

### Task 2: Add the `bin/secrets` CLI front end

**Files:**
- Create: `bin/secrets`
- Modify: `tests/test-secrets.sh` (new section immediately before `== no variable leakage into sourcing shell ==`)
- Modify: `.github/workflows/ci.yml` (add `bin/secrets` to the lint job)

**Interfaces:**
- Consumes: `lib/secrets-lib.sh` from Task 1, specifically the `secrets` dispatcher function.
- Produces: `bin/secrets`, an executable taking the same argument vector as the `secrets` function and returning the same exit status. Reads `SECRETS_LIB` (absolute path to the library; empty or unset means fall back to the candidate list). Exits 127 with `secrets: cannot find secrets-lib.sh (set SECRETS_LIB to its path)` when no candidate is readable. Task 3's `make install` places this file at `$(PREFIX)/bin/secrets`.

- [ ] **Step 1: Write the failing tests**

In `tests/test-secrets.sh`, insert this section immediately before the `echo "== no variable leakage into sourcing shell (subshell bodies) =="` line.

Note the explicit `SECRETS_LIB=` on the fallback cases: the suite sets `SECRETS_LIB` for its own sourcing, and if a caller exported it, it would leak into these child processes and make every candidate resolve through case [1], silently defeating the point of the test.

```sh
echo "== cli wrapper =="
CLI=$(dirname "$0")/../bin/secrets

# [2] resolution straight from a git checkout: $dir/../lib/secrets-lib.sh
check "cli: checkout resolution" "ghp_abc123" "$(SECRETS_LIB= "$CLI" dec github)"

# [3] resolution from an installed prefix: $dir/../share/secrets/secrets-lib.sh
mkdir -p "$T/pfx/bin" "$T/pfx/share/secrets"
cp "$CLI" "$T/pfx/bin/secrets"
cp "$SECRETS_LIB" "$T/pfx/share/secrets/secrets-lib.sh"
check "cli: prefix/share resolution" "ghp_abc123" \
    "$(SECRETS_LIB= HOME=/nonexistent "$T/pfx/bin/secrets" dec github)"

# [4] resolution with both files in one directory
mkdir -p "$T/same"
cp "$CLI" "$SECRETS_LIB" "$T/same/"
check "cli: same-dir resolution" "ghp_abc123" \
    "$(SECRETS_LIB= HOME=/nonexistent "$T/same/secrets" dec github)"

# [1] SECRETS_LIB overrides everything, even with no library near the binary
mkdir -p "$T/lone/bin"
cp "$CLI" "$T/lone/bin/secrets"
check "cli: SECRETS_LIB override" "ghp_abc123" \
    "$(SECRETS_LIB="$T/pfx/share/secrets/secrets-lib.sh" HOME=/nonexistent \
       "$T/lone/bin/secrets" dec github)"

# no library reachable at all
cli_err=$(SECRETS_LIB= HOME=/nonexistent "$T/lone/bin/secrets" ls 2>&1 >/dev/null)
check "cli: missing lib rc" "127" "$?"
printf '%s' "$cli_err" | grep -q 'SECRETS_LIB'
check "cli: missing lib names SECRETS_LIB" "0" "$?"

# exit codes survive the extra process
SECRETS_LIB= "$CLI" dec nonexistent >/dev/null 2>&1
check "cli: missing secret rc" "1" "$?"
SECRETS_LIB= "$CLI" dec '../etc/passwd' >/dev/null 2>&1
check "cli: invalid name rc" "2" "$?"
SECRETS_LIB= "$CLI" bogus >/dev/null 2>&1
check "cli: unknown subcommand rc" "2" "$?"
SECRETS_LIB= "$CLI" >/dev/null 2>&1
check "cli: no args is help" "0" "$?"

# stdin flows through the wrapper unchanged
printf 'via-cli\n' | SECRETS_LIB= "$CLI" enc fromcli
check "cli: stdin pipe roundtrip" "via-cli" "$(SECRETS_LIB= "$CLI" dec fromcli)"

# completions emitted by the CLI name the new command
SECRETS_LIB= "$CLI" completions bash > "$T/cli.bash"
grep -q 'complete -F _secrets_complete secrets' "$T/cli.bash"
check "cli: bash completion registers secrets" "0" "$?"
grep -qw 'secret' "$T/cli.bash"
check "cli: no stale 'secret' in bash completion" "1" "$?"
```

- [ ] **Step 2: Run the suite to verify the new checks fail**

```bash
sh tests/test-secrets.sh 2>&1 | tail -20
```

Expected: the `== cli wrapper ==` checks FAIL (`bin/secrets` does not exist yet, so every invocation reports `No such file or directory`) while the original 79 still pass.

- [ ] **Step 3: Write the CLI**

Create `bin/secrets` with exactly this content:

```sh
#!/bin/sh
# secrets -- command-line front end for secrets-lib.sh
#
# Locates the library, sources it, and hands off to the secrets()
# dispatcher. Holds no secret-store logic of its own. Set SECRETS_LIB to
# override discovery -- needed when this file is reached through a symlink,
# because resolving one would require readlink(1), which is not POSIX.
set -u

self=$0
case $self in
    */*) ;;
    *)   self=$(command -v -- "$self") || {
             printf 'secrets: cannot locate self (set SECRETS_LIB)\n' >&2
             exit 127
         } ;;
esac
dir=$(unset CDPATH; cd -- "${self%/*}" && pwd) || exit 127

for cand in \
    "${SECRETS_LIB:-}" \
    "$dir/../lib/secrets-lib.sh" \
    "$dir/../share/secrets/secrets-lib.sh" \
    "$dir/secrets-lib.sh" \
    "${HOME:-}/.local/share/secrets/secrets-lib.sh" \
    /usr/local/share/secrets/secrets-lib.sh \
    /usr/share/secrets/secrets-lib.sh
do
    if [ -z "$cand" ] || [ ! -r "$cand" ]; then continue; fi
    # shellcheck disable=SC1090  # path is resolved at runtime
    . "$cand"
    secrets "$@"
    exit $?
done

printf 'secrets: cannot find secrets-lib.sh (set SECRETS_LIB to its path)\n' >&2
exit 127
```

Three details that are load-bearing and must not be "cleaned up":

- `unset CDPATH` inside the subshell rather than a `CDPATH= cd` prefix: the prefix form trips shellcheck SC1007.
- `if [ -z ... ] || [ ! -r ... ]; then continue; fi` rather than `[ -n ] && [ -r ] || continue`: the `&&`/`||` form trips shellcheck SC2015.
- `set -u` but **not** `set -e`: the library's exit status must propagate through `exit $?`, not abort the wrapper.

- [ ] **Step 4: Make it executable**

```bash
chmod +x bin/secrets
```

- [ ] **Step 5: Run the suite to verify it passes**

```bash
sh tests/test-secrets.sh 2>&1 | tail -3
```

Expected: `92 passed, 0 failed` (79 original plus 13 new). If the count differs from 92 but `0 failed` holds, record the real number — Task 4 writes it into the README and CHANGELOG.

- [ ] **Step 6: Run under all three shells**

```bash
for s in dash bash zsh; do printf '%s: ' "$s"; $s tests/test-secrets.sh 2>&1 | tail -1; done
```

Expected: the same `N passed, 0 failed` three times.

- [ ] **Step 7: Verify shellcheck is clean on the new file**

```bash
shellcheck bin/secrets && echo CLEAN
```

Expected: `CLEAN`. `bin/secrets` carries a `#!/bin/sh` shebang, so no `--shell=sh` flag is needed.

- [ ] **Step 8: Smoke-test completion against the real command**

```bash
export PATH="$PWD/bin:$PATH"
bash --noprofile --norc -c '
  eval "$(secrets completions bash)"
  COMP_WORDS=(secrets dec ""); COMP_CWORD=2; COMPREPLY=()
  _secrets_complete; echo "names: ${COMPREPLY[*]}"'
```

Expected: a `names:` line listing the secrets in `~/.secrets` (empty is a valid result on a machine with no store — the point is that the function is defined and runs without error).

- [ ] **Step 9: Document the CLI in the library header**

The spec requires the library's header block to describe the new entry
point. In `lib/secrets-lib.sh`, add `SECRETS_LIB` to the Config listing
(after the `SECRETS_ARMOR` line, around line 24):

```sh
#   SECRETS_LIB         library path, CLI only     (see search order in README)
```

and replace the two-line note about sourcing (around lines 43-46, the
"Portability notes" paragraph's neighbours) so it states both entry points:

```sh
# Two ways in: run the `secrets` command, which finds and sources this file,
# or source this file yourself and call the `secrets` function directly.
# Sourcing leaks nothing -- helper functions use subshell bodies `f() (...)`.
```

Re-run `shellcheck --shell=sh lib/secrets-lib.sh` afterwards; comment-only
edits should keep it clean.

- [ ] **Step 10: Add the CLI to the lint job**

In `.github/workflows/ci.yml`, add to the `lint` job's `run` block, after the existing shellcheck lines:

```yaml
          shellcheck bin/secrets
```

- [ ] **Step 11: Commit**

```bash
git add -A
git commit -m "Add bin/secrets CLI front end with library discovery"
```

---

### Task 3: Add the Makefile

**Files:**
- Create: `Makefile`
- Modify: `tests/test-secrets.sh` (append to the `== cli wrapper ==` section from Task 2)

**Interfaces:**
- Consumes: `bin/secrets` and `lib/secrets-lib.sh`.
- Produces: targets `install`, `uninstall`, `test`, and a default `all`. Honors `PREFIX` (default `/usr/local`) and `DESTDIR` (default empty). Installs to `$(DESTDIR)$(PREFIX)/bin/secrets` mode 755 and `$(DESTDIR)$(PREFIX)/share/secrets/secrets-lib.sh` mode 644.

- [ ] **Step 1: Write the failing test**

Append to the end of the `== cli wrapper ==` section in `tests/test-secrets.sh`, still before the leak-check section:

```sh
# a staged `make install` tree resolves via the prefix-relative candidate
( cd "$(dirname "$0")/.." && make install DESTDIR="$T/dest" PREFIX=/usr/local ) >/dev/null 2>&1
check "make install rc" "0" "$?"
check "installed bin mode" "755" "$(stat -c %a "$T/dest/usr/local/bin/secrets" 2>/dev/null)"
check "installed lib mode" "644" \
    "$(stat -c %a "$T/dest/usr/local/share/secrets/secrets-lib.sh" 2>/dev/null)"
check "installed cli works" "ghp_abc123" \
    "$(SECRETS_LIB= HOME=/nonexistent "$T/dest/usr/local/bin/secrets" dec github)"
( cd "$(dirname "$0")/.." && make uninstall DESTDIR="$T/dest" PREFIX=/usr/local ) >/dev/null 2>&1
check "uninstall removes both" "0" "$(find "$T/dest" -type f 2>/dev/null | wc -l)"
```

- [ ] **Step 2: Run the suite to verify the new checks fail**

```bash
sh tests/test-secrets.sh 2>&1 | tail -12
```

Expected: the five `make` checks FAIL — there is no Makefile, so `make` reports `No targets specified and no makefile found` and the staged paths do not exist.

- [ ] **Step 3: Write the Makefile**

Create `Makefile` with exactly this content. Note the recipe lines are indented with **tabs**, not spaces — a Makefile with leading spaces will not run.

```make
PREFIX  ?= /usr/local
DESTDIR ?=

BINDIR = $(DESTDIR)$(PREFIX)/bin
LIBDIR = $(DESTDIR)$(PREFIX)/share/secrets

.PHONY: all install uninstall test

all:
	@echo 'targets: install uninstall test   (PREFIX=$(PREFIX))'

install:
	mkdir -p '$(BINDIR)' '$(LIBDIR)'
	cp bin/secrets '$(BINDIR)/secrets'
	chmod 755 '$(BINDIR)/secrets'
	cp lib/secrets-lib.sh '$(LIBDIR)/secrets-lib.sh'
	chmod 644 '$(LIBDIR)/secrets-lib.sh'

uninstall:
	rm -f '$(BINDIR)/secrets' '$(LIBDIR)/secrets-lib.sh'
	-rmdir '$(LIBDIR)'

test:
	sh tests/test-secrets.sh
```

`install` copies rather than symlinks. That is deliberate: the CLI does not resolve symlinks, so a symlinked install would fall through to the absolute candidates and fail.

The leading `-` on `rmdir` lets uninstall succeed when the directory still holds files a user put there.

- [ ] **Step 4: Verify the recipes use real tabs**

```bash
grep -Pn '^    ' Makefile
```

Expected: no output. Any match means spaces were used where a tab is required.

- [ ] **Step 5: Run the suite to verify it passes**

```bash
sh tests/test-secrets.sh 2>&1 | tail -3
```

Expected: `97 passed, 0 failed` (92 from Task 2 plus 5). Record the real number for Task 4.

- [ ] **Step 6: Verify `make test` works as the documented entry point**

```bash
make test 2>&1 | tail -2
```

Expected: the same `N passed, 0 failed`.

- [ ] **Step 7: Verify a non-default prefix installs correctly**

```bash
rm -rf /tmp/secrets-prefix-check
make install DESTDIR=/tmp/secrets-prefix-check PREFIX=/opt/tools >/dev/null
find /tmp/secrets-prefix-check -type f
rm -rf /tmp/secrets-prefix-check
```

Expected: exactly `/tmp/secrets-prefix-check/opt/tools/bin/secrets` and `/tmp/secrets-prefix-check/opt/tools/share/secrets/secrets-lib.sh`. This confirms the prefix-relative candidate works for arbitrary prefixes, not just the two hardcoded absolute fallbacks.

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "Add Makefile with install, uninstall, and test targets"
```

---

### Task 4: Update the README and CHANGELOG

**Files:**
- Modify: `README.md` (title, opening example, Install, Usage, Configuration table, Testing, plus a new library section)
- Modify: `CHANGELOG.md:6-8` (the bullet describing the single-file design)

**Interfaces:**
- Consumes: everything from Tasks 1-3. No code changes; documentation must match the shipped behavior exactly.

- [ ] **Step 1: Record the true check count**

```bash
sh tests/test-secrets.sh 2>&1 | tail -1
```

Write down the number. Every place the README or CHANGELOG says "79 checks" must become this number. Do not carry over the estimate from Task 3.

- [ ] **Step 2: Update the README title and opening example**

Change the title from `# secret.sh` to `# secrets`, and the description line from "One sourceable POSIX `sh` file" to "A POSIX `sh` library plus a small CLI that wraps it." Update the console block so every command reads `secrets`:

```console
$ secrets init
secrets: backend    age
secrets: public key age1levmga375nt6rjs69al874uh4xjpmdng87up5g7v9u2vhu3hmddqtt9d4r
$ printf 'ghp_abc123\n' | secrets enc github
$ secrets dec github
ghp_abc123
$ export GITHUB_TOKEN="$(secrets dec github)"
```

- [ ] **Step 3: Replace the Install section**

The current section documents curling one file and sourcing it. Replace its body with both supported paths:

````markdown
Requires `age` (or `rage`) — single static binaries, also in most package
managers (`apt install age`, `brew install age`, `pacman -S age`, ...).

From a clone:

```sh
make install                      # -> /usr/local, may need sudo
make install PREFIX=~/.local      # -> ~/.local/bin and ~/.local/share
```

Or fetch the two files directly, no clone needed:

```sh
mkdir -p ~/.local/bin ~/.local/share/secrets
base=https://raw.githubusercontent.com/OWNER/secret-sh/main
curl -fsSL "$base/bin/secrets"          -o ~/.local/bin/secrets
curl -fsSL "$base/lib/secrets-lib.sh"   -o ~/.local/share/secrets/secrets-lib.sh
chmod +x ~/.local/bin/secrets
```

Make sure `~/.local/bin` is on your `PATH`. The CLI finds the library
relative to its own location, so any prefix works; `SECRETS_LIB` overrides
the search if you put the library somewhere unusual — or if you reach
`secrets` through a symlink, which is not resolved.
````

- [ ] **Step 4: Update the completions block**

```sh
# bash (.bashrc):                 eval "$(secrets completions bash)"
# zsh  (.zshrc, after compinit):  eval "$(secrets completions zsh)"
# fish:  secrets completions fish > ~/.config/fish/completions/secrets.fish
```

- [ ] **Step 5: Update the Usage block and the inline examples**

Rename every `secret ` to `secrets ` in the usage listing and in the `pass`(1)-convention example further down:

```sh
printf 'hunter2\nuser: enrique\nurl: example.com\n' | secrets enc example
secrets dec example | head -n 1        # -> hunter2
secrets dec example | tail -n +2       # -> the metadata
```

- [ ] **Step 6: Add a "Use it as a library" section**

Place it immediately after the Usage section:

````markdown
### Use it as a library

`secrets` is a thin wrapper around a sourceable POSIX `sh` file. Scripts
that want the dispatcher in-process can source it directly and skip the
extra process:

```sh
#!/bin/sh
set -eu
. ~/.local/share/secrets/secrets-lib.sh
export GITHUB_TOKEN="$(secrets dec github)"
```

Helper functions use subshell bodies, so sourcing leaks no variables into
your shell. This also works from your `.bashrc` if you prefer the function
over the command.
````

- [ ] **Step 7: Add `SECRETS_LIB` to the Configuration table and document the export caveat**

Add this row to the table:

```markdown
| `SECRETS_LIB`        | search path (see Install)        | library location, CLI only       |
```

Then add this paragraph directly beneath the table:

```markdown
Because `secrets` is a separate process, these variables must be
**exported** to take effect. An unexported `SECRETS_DIR=...` is silently
ignored and the default store is used instead. Sourcing the library
directly does not have this constraint.
```

- [ ] **Step 8: Update the Testing section**

```sh
make test                                      # autodetected backend
sh tests/test-secrets.sh                       # same thing
SECRETS_AGE=rage dash tests/test-secrets.sh    # pin backend and shell
```

Update the sentence beneath it to the real check count from Step 1, and extend the coverage list to mention CLI library discovery and install staging.

- [ ] **Step 9: Update the CHANGELOG**

Replace the first bullet under `## [0.1.0] - unreleased`, which currently reads "POSIX `sh` secret store sourced as a single file; `secret` dispatcher with ...", with:

```markdown
- POSIX `sh` secret store as a sourceable library (`lib/secrets-lib.sh`)
  plus a `secrets` CLI that wraps it; `init`, `enc`, `dec`, `ls`, `rm`,
  `rename`, `recipients`, `rekey`, `completions`, `help` subcommands.
- `Makefile` with `install`, `uninstall`, and `test` targets, honoring
  `PREFIX` and `DESTDIR`.
```

Update the final bullet's check count to the real number from Step 1.

- [ ] **Step 10: Verify no stale references remain anywhere**

```bash
grep -rn 'secret\.sh\|test-secret\.sh\|SECRET_SH' README.md CHANGELOG.md Makefile bin lib tests .github
```

Expected: no output. Matches inside `docs/superpowers/` are fine and expected — those are historical records and are deliberately excluded from this grep.

- [ ] **Step 11: Verify every README command block actually runs**

Walk the README top to bottom and execute each shell block against a scratch store:

```bash
export SECRETS_DIR=$(mktemp -d)
export PATH="$PWD/bin:$PATH"
secrets init
printf 'ghp_abc123\n' | secrets enc github
secrets dec github
secrets ls
printf 'hunter2\nuser: enrique\nurl: example.com\n' | secrets enc example
secrets dec example | head -n 1
secrets dec example | tail -n +2
rm -rf "$SECRETS_DIR"
```

Expected: `ghp_abc123`, then `example` and `github` from `ls`, then `hunter2`, then the two metadata lines. Any command that errors means the README is wrong — fix the README, not the test.

- [ ] **Step 12: Final full verification**

```bash
for s in dash bash zsh; do printf '%s: ' "$s"; $s tests/test-secrets.sh 2>&1 | tail -1; done
SECRETS_AGE=rage sh tests/test-secrets.sh 2>&1 | tail -1
shellcheck --shell=sh lib/secrets-lib.sh tests/test-secrets.sh && shellcheck bin/secrets && echo CLEAN
```

Expected: `N passed, 0 failed` four times and `CLEAN`.

- [ ] **Step 13: Commit**

```bash
git add -A
git commit -m "Update README and CHANGELOG for the secrets rename"
```
