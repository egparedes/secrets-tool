# Changelog

## [0.2.0] - unreleased

The store is now byte-for-byte a
[passage](https://github.com/FiloSottile/passage) /
[pago](https://github.com/dbohdan/pago) store: all three tools can drive the
same directory. Same feature set as 0.1.0, same subcommands, same
guarantees — the layout and the naming rules changed underneath them.

### Changed

- **Store layout.** Entries live in `$SECRETS_DIR/store/`, the identity is
  `$SECRETS_DIR/identities`, and recipients are
  `$SECRETS_DIR/store/.age-recipients` — passage's `~/.passage` and pago's
  `~/.local/share/pago` exactly. `SECRETS_DIR=~/.passage secrets ls` is all
  it takes to work in someone else's store.
- **Hierarchical names.** `work/aws` is `store/work/aws.age`. `ls` recurses
  and sorts, `enc` and `rename` create the directories they need, and `rm`
  and `rename` prune the ones they empty.
- **Name validation** now rejects what could escape the store or collide
  with its dot-files (`..`, absolute or trailing `/`, empty or dot-leading
  components, control characters) and accepts everything else a passage
  store can hold, including spaces, `@`, `+` and shell metacharacters.
  Names are only ever quoted path arguments, never shell input.
- **Recipients are resolved per entry**, by passage's rule: the nearest
  `.age-recipients` at or above the entry's directory wins, falling back to
  the identities file when the store has none. `rekey` honours the walk;
  `rename` re-encrypts an entry that crosses a boundary and otherwise still
  moves it without needing the private key. `SECRETS_RECIPIENTS` now pins
  one file for the whole store, as `PASSAGE_RECIPIENTS_FILE` does.
- **Paths are derived per call**, not when the library is sourced, so
  changing `SECRETS_DIR` in a shell that sourced the library moves the whole
  store. Sourcing now sets no variables at all.
- `secrets recipients` takes an optional `NAME` and reports the recipients
  that actually govern it; with no `.age-recipients` anywhere it derives the
  public keys from the identity, which is what encryption would use.
- The bash completion no longer expands stored names through `compgen -W`,
  now that names may contain metacharacters. It also rejoins the pieces bash
  splits a name into at `:` (a `COMP_WORDBREAKS` character) and trims them
  back off its replies, and quotes what it returns, so names holding colons
  or spaces complete correctly rather than producing `zz:zz:colon` or two
  arguments. zsh and fish already handled both.

### Added

- **`secrets migrate`**, a one-shot in-place conversion of a pre-0.2 flat
  store. Until it is run, `secrets` refuses to operate on such a store
  (exit code 4) instead of starting an empty one beside it. Nothing is
  re-encrypted.
- **Encrypted identities.** pago keeps its identities file under a master
  password; that is detected from the file's header and unwrapped with age
  into a mode-600 temporary file, preferring a tmpfs such as `/dev/shm`,
  removed when the command returns. Encrypting never needs it.
- **`tests/test-interop.sh`** (`make test-interop`), which drives one store
  with `secrets` and with the real `passage` and `pago` in both directions.
  A new CI job runs it against pinned releases of both.

### Fixed

- **`rekey` silently rekeyed only part of the store.** `secrets ls`, which
  builds rekey's work list, ran `find` as the head of a pipeline; POSIX `sh`
  has no `pipefail`, so a directory `find` could not read came back as a
  quietly short list and rekey reported success. Entries kept a recipient the
  user believed they had revoked. `ls` now fails loudly instead.
- **The whole tool was broken under zsh.** Two `for f in "$DIR"/*.age` loops
  are fatal errors under zsh's `NO_MATCH` rather than leaving the glob
  literal, so every subcommand died on a store that did not exist yet.
  Replaced with `find`. The test suite passes under zsh again, and CI now
  also parses the library and both suites under dash, bash and zsh.
- **`rekey`'s install pass is now genuinely all-or-nothing.** It was a bare
  loop of `mv`s: a failure part way through left the store split across two
  recipient sets, and the cleanup trap then deleted the remaining work. Each
  original is now moved into the staging tree before its replacement lands,
  so a failure rolls every entry back.
- **`rekey` no longer converts a pago store's armored entries to binary.**
  Armor is decided per entry from the file already on disk.
- **`secrets rm` no longer silently does nothing.** `rm -i` reads its
  confirmation from stdin and at EOF declines while still exiting 0, so an
  unattended `secrets rm` reported success having deleted nothing. It now
  refuses without a terminal and takes `-f`; either way it verifies the file
  is gone.
- `enc` no longer leaves an orphaned ciphertext temp file (invisible to
  `secrets ls`) when it cannot install its result.
- The unwrapped identity is removed if the command is interrupted at the
  passphrase prompt; the caller's trap could not cover that window.
- `secrets recipients` exits 3, like every other path, where it exited 1 for
  the same "no recipients and no identity" condition; `secrets recipients ''`
  validates the empty name instead of reporting the store root. Exit codes
  are now documented in `secrets help` and the README.
- `rename` across a recipients boundary could destroy the source and leave
  an empty secret behind. Encrypting the empty output of a failed `age -d`
  still produces a valid, non-empty age file, and POSIX `sh` has no
  `pipefail` to notice, so a failed decrypt read as a clean re-encryption.
  The decrypt's status is now checked directly, as `rekey` already did.
- `rekey` and `rename` now drop their staging trees and any unwrapped
  identity on every exit path, via one `EXIT` trap instead of per-branch
  cleanup that some error paths missed.

## [0.1.0] - unreleased

Initial release.

- POSIX `sh` secret store as a sourceable library (`lib/secrets-lib.sh`)
  plus a `secrets` CLI that wraps it; `init`, `enc`, `dec`, `ls`, `rm`,
  `rename`, `recipients`, `rekey`, `completions`, `help` subcommands.
- `Makefile` with `install`, `uninstall`, and `test` targets, honoring
  `PREFIX` and `DESTDIR`.
- Interchangeable age / rage backends, auto-detected, pinnable via
  `SECRETS_AGE`.
- Asymmetric encryption against a recipients file; write-only operation
  without the identity present; SSH keys usable as identities.
- Atomic, all-or-nothing `rekey`; tamper rejection via age's authenticated
  encryption; strict secret-name validation.
- Shell completions for bash, zsh, and fish.
- Format-agnostic storage: secrets are opaque byte blobs, decrypted
  verbatim with no KEY=value or other content conventions.
- 113-check test suite run in CI across {dash, bash, zsh} x {age, rage}.
