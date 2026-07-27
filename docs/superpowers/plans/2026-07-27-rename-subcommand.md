# `secret rename` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `secret rename [-f] OLD NEW`, which renames a stored secret by moving `$SECRETS_DIR/OLD.age` to `$SECRETS_DIR/NEW.age`.

**Architecture:** One new `_secret_rename` subshell-body function plus a dispatcher case in the single-file store `secret.sh`. Renaming is a pure filesystem `mv` — age does not bind filenames into ciphertext, so no crypto, identity, or recipients file is involved. Spec: `docs/superpowers/specs/2026-07-27-rename-subcommand-design.md`.

**Tech Stack:** POSIX `sh` (dash/bash/zsh compatible), age/rage backends, plain-sh test harness in `tests/test-secret.sh`.

## Global Constraints

- Strictly POSIX `sh`; no bashisms; the only allowed non-POSIX tool is `mktemp` (not needed here).
- Every subcommand function uses a subshell body `f() (...)` so no variables leak into the sourcing shell.
- Error message wording and exit codes must match existing subcommands exactly: invalid name → exit 2 via `_secret_name`; missing secret → `secret: no such secret: NAME`, exit 1; clobber → `secret: <path> already exists (use -f to overwrite)`, exit 1.
- Every place that enumerates subcommands must stay in sync: header comment, `_secret_help`, dispatcher, bash/zsh/fish completions, README usage block, CHANGELOG.
- Run the suite as `sh tests/test-secret.sh`; it must end `N passed, 0 failed`.

---

### Task 1: `_secret_rename` core (tests, implementation, dispatcher, help, header)

**Files:**
- Modify: `secret.sh` (header listing ~line 12, new function after `_secret_rm` ~line 208, help text ~line 322, dispatcher ~line 340)
- Test: `tests/test-secret.sh` (new section after the `== ls / rm / recipients / help / dispatcher ==` section, ~line 121; leak-check list ~line 134)

**Interfaces:**
- Consumes: `_secret_name NAME` (exit 2 on invalid), `$SECRETS_DIR`.
- Produces: `_secret_rename [-f] OLD NEW` (exit 0 silent success; exit 1 on missing OLD, self-rename, or clobber without `-f`; exit 2 on invalid names) and dispatcher case `secret rename …`. Task 2 relies on the subcommand existing under the name `rename`.

- [ ] **Step 1: Write the failing tests**

In `tests/test-secret.sh`, insert after the `== ls / rm / recipients / help / dispatcher ==` section (after the `secret bogus` line) and before `== completions emit and parse ==`:

```sh
echo "== rename =="
printf 'moved\n' | secret enc oldname
secret rename oldname newname; check "rename rc" "0" "$?"
check "old name gone" "0" "$(secret ls | grep -cx oldname)"
check "new name decrypts" "moved" "$(secret dec newname)"
secret rename missing x >/dev/null 2>&1; check "rename missing rc" "1" "$?"
printf 'other\n' | secret enc taken
secret rename newname taken >/dev/null 2>&1; check "rename clobber refused" "1" "$?"
check "clobber target intact" "other" "$(secret dec taken)"
secret rename -f newname taken; check "rename -f rc" "0" "$?"
check "rename -f overwrote" "moved" "$(secret dec taken)"
secret rename taken taken >/dev/null 2>&1; check "self-rename refused" "1" "$?"
secret rename '../x' ok2 >/dev/null 2>&1; check "bad OLD rejected" "2" "$?"
secret rename taken 'a/b' >/dev/null 2>&1; check "bad NEW rejected" "2" "$?"
```

In the same file, extend the leak-check list with the new locals `src` and `dst` — change:

```sh
for var in agebin keygen out tmp in name f n stage st pub force; do
```

to:

```sh
for var in agebin keygen out tmp in name f n stage st pub force src dst; do
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `sh tests/test-secret.sh`
Expected: the `== rename ==` checks FAIL (`rename` is an unknown subcommand, rc 2 not 0/1); the two new leak checks pass (vars never set); final line shows nonzero failed count.

- [ ] **Step 3: Implement `_secret_rename` and wire it up**

In `secret.sh`, insert after `_secret_rm` (after its closing `)`):

```sh
_secret_rename() (
    force=0
    if [ "${1-}" = "-f" ]; then force=1; shift; fi

    _secret_name "${1-}" || exit $?
    _secret_name "${2-}" || exit $?

    src="$SECRETS_DIR/$1.age"
    dst="$SECRETS_DIR/$2.age"
    if [ ! -e "$src" ]; then
        printf 'secret: no such secret: %s\n' "$1" >&2
        exit 1
    fi
    if [ "$1" = "$2" ]; then
        printf 'secret: %s is already named %s\n' "$1" "$2" >&2
        exit 1
    fi
    if [ -e "$dst" ] && [ "$force" -eq 0 ]; then
        printf 'secret: %s already exists (use -f to overwrite)\n' "$dst" >&2
        exit 1
    fi
    mv -f -- "$src" "$dst"
)
```

In the dispatcher, add after the `rm)` line:

```sh
        rename)      shift; _secret_rename "$@" ;;
```

In the header comment, add after the `secret rm` line (description column starts at char 33, matching neighbors):

```sh
#   secret rename [-f] OLD NEW  rename a secret
```

In `_secret_help`, add after the `rm   NAME` line (description column starts at char 24, matching neighbors):

```sh
  rename [-f] OLD NEW  rename a secret (-f overwrites)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `sh tests/test-secret.sh` — expected: `76 passed, 0 failed`.
Also run under dash and bash if available: `dash tests/test-secret.sh`, `bash tests/test-secret.sh`.
Run: `shellcheck -s sh secret.sh` if shellcheck is installed; expected clean.

- [ ] **Step 5: Commit**

```bash
git add secret.sh tests/test-secret.sh
git commit -m "Add rename subcommand"
```

---

### Task 2: Shell completions for `rename`

**Files:**
- Modify: `secret.sh` (`_secret_completions`: bash ~lines 265-279, zsh ~lines 281-296, fish ~lines 298-304)
- Test: `tests/test-secret.sh` (`== completions emit and parse ==` section, ~line 124)

**Interfaces:**
- Consumes: the `rename` subcommand name from Task 1; existing `$T/c.bash`, `$T/c.zsh`, `$T/c.fish` files already emitted by the completions test section.
- Produces: completion scripts whose subcommand lists include `rename`, completing `-f` plus stored names for its arguments (same treatment as `enc`).

- [ ] **Step 1: Write the failing tests**

In `tests/test-secret.sh`, at the end of the `== completions emit and parse ==` section (after the `unknown shell rc` check):

```sh
grep -qw rename "$T/c.bash"; check "bash completes rename" "0" "$?"
grep -qw rename "$T/c.zsh";  check "zsh completes rename" "0" "$?"
grep -qw rename "$T/c.fish"; check "fish completes rename" "0" "$?"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `sh tests/test-secret.sh`
Expected: exactly the three new checks FAIL (grep rc 1), everything else passes.

- [ ] **Step 3: Add `rename` to the three completion scripts**

In `_secret_completions` in `secret.sh`, make these edits inside the heredocs:

bash — word list and the `enc` case line become:

```sh
        COMPREPLY=($(compgen -W "init enc dec ls rm rename recipients rekey completions help" -- "$cur"))
```

```sh
        enc|rename)   COMPREPLY=($(compgen -W "-f $(secret ls 2>/dev/null)" -- "$cur")) ;;
```

zsh — subcommand array and the `enc` case line become:

```sh
    subcmds=(init enc dec ls rm rename recipients rekey completions help)
```

```sh
        enc|rename)   compadd -- -f ${(f)"$(secret ls 2>/dev/null)"} ;;
```

fish — the subcommand list, name-completion, and `-f` lines become:

```sh
complete -c secret -n '__fish_use_subcommand' -a 'init enc dec ls rm rename recipients rekey completions help'
complete -c secret -n '__fish_seen_subcommand_from dec rm enc rename' -a '(secret ls 2>/dev/null)'
complete -c secret -n '__fish_seen_subcommand_from enc rename' -s f -d 'overwrite existing secret'
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `sh tests/test-secret.sh` — expected: `79 passed, 0 failed` (bash/zsh `-n` parse checks must still pass).

- [ ] **Step 5: Commit**

```bash
git add secret.sh tests/test-secret.sh
git commit -m "Complete rename in bash/zsh/fish completions"
```

---

### Task 3: Documentation (README, CHANGELOG)

**Files:**
- Modify: `README.md` (usage block ~lines 61-70, test-count sentence ~line 123)
- Modify: `CHANGELOG.md` (subcommand list bullet ~line 8, test-suite bullet ~line 19)

**Interfaces:**
- Consumes: final check count from `sh tests/test-secret.sh` after Task 2 (expected 79 — use the number the suite actually prints).
- Produces: user-facing docs in sync with the code.

- [ ] **Step 1: Update README usage block**

Add after the `secret rm` line (description column starts at char 29, matching neighbors):

```
secret rename [-f] OLD NEW  rename a secret
```

- [ ] **Step 2: Update README test-count sentence**

Change `The suite (63 checks) covers` to `The suite (79 checks) covers` (use the actual count printed by the suite).

- [ ] **Step 3: Update CHANGELOG**

In the 0.1.0 dispatcher bullet, change the list to `init`, `enc`, `dec`, `ls`, `rm`, `rename`, `recipients`, `rekey`, `completions`, `help`. In the test-suite bullet, change `63-check` to `79-check` (actual count).

- [ ] **Step 4: Verify**

Run: `sh tests/test-secret.sh` — expected: `79 passed, 0 failed`. Confirm `grep -rn '63' README.md CHANGELOG.md` returns nothing stale.

- [ ] **Step 5: Commit**

```bash
git add README.md CHANGELOG.md
git commit -m "Document rename subcommand"
```
