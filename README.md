# secrets

A tiny secret store for the shell, built on [age](https://age-encryption.org)
or its Rust implementation [rage](https://github.com/str4d/rage). A POSIX
`sh` library plus a small CLI that wraps it, no daemon, no config format.

The store is laid out exactly like
[passage](https://github.com/FiloSottile/passage)'s and
[pago](https://github.com/dbohdan/pago)'s, so all three drive the same
directory.

```console
$ secrets init
secrets: backend    age
secrets: store      /home/you/.secrets/store
secrets: identity   /home/you/.secrets/identities
secrets: recipients /home/you/.secrets/store/.age-recipients
secrets: public key age1levmga375nt6rjs69al874uh4xjpmdng87up5g7v9u2vhu3hmddqtt9d4r
secrets: back up the identity -- without it every .age file is unrecoverable
$ printf 'ghp_abc123\n' | secrets enc github
$ secrets dec github
ghp_abc123
$ export GITHUB_TOKEN="$(secrets dec github)"
```

## Why

- **Authenticated encryption.** age uses ChaCha20-Poly1305; a corrupted or
  tampered blob fails loudly instead of decrypting to garbage (unlike
  `openssl enc` CBC pipelines).
- **Asymmetric by default.** Encrypting needs only the public
  `.age-recipients`, so a machine or CI job can *write* secrets it cannot
  read.
- **No lock-in.** The store *is* a passage/pago store. Point any of the
  three at it, or walk away and use plain `age` — the files are ordinary
  age ciphertext in a directory tree.
- **Portable.** Strictly POSIX `sh` (sole exception: `mktemp`, which is
  universal in practice). CI runs the suite under dash, bash and zsh
  against both age and rage. One store, either binary.
- **Multi-machine.** Append another machine's public key to
  `.age-recipients`, run `secrets rekey`, sync the directory (ciphertext
  only — safe for git/rsync).

## Install

Requires `age` (or `rage`) — single static binaries, also in most package
managers (`apt install age`, `brew install age`, `pacman -S age`, ...).

From a clone:

```sh
make install                            # -> /usr/local, may need sudo
make install PREFIX="$HOME/.local"      # -> ~/.local/bin and ~/.local/share
```

Or fetch the two files directly, no clone needed:

```sh
mkdir -p ~/.local/bin ~/.local/share/secrets
base=https://raw.githubusercontent.com/egparedes/secrets-tool/main
curl -fsSL "$base/bin/secrets"          -o ~/.local/bin/secrets
curl -fsSL "$base/lib/secrets-lib.sh"   -o ~/.local/share/secrets/secrets-lib.sh
chmod +x ~/.local/bin/secrets
```

Pin a tag or commit instead of `main` for reproducible installs — these
two files are fetched straight into your `PATH`, so tracking a moving
branch means every re-run can bring different code.

Make sure `~/.local/bin` is on your `PATH`. The CLI finds the library
relative to its own location, so any prefix works; `SECRETS_LIB` overrides
the search if you put the library somewhere unusual — or if you reach
`secrets` through a symlink, which is not resolved.

Then, optionally, tab completion:

```sh
# bash (.bashrc):                 eval "$(secrets completions bash)"
# zsh  (.zshrc, after compinit):  eval "$(secrets completions zsh)"
# fish:  secrets completions fish > ~/.config/fish/completions/secrets.fish
```

## Usage

```
secrets init                 create the store, generate an identity
secrets enc  [-f] NAME       encrypt stdin -> NAME.age  (-f overwrites)
secrets dec  NAME            decrypt to stdout, verbatim
secrets ls                   list stored names
secrets rm   [-f] NAME       delete a secret (-f skips the prompt)
secrets rename [-f] OLD NEW  rename a secret
secrets recipients [NAME]    show who can decrypt
secrets rekey                re-encrypt everything to current recipients
secrets migrate              convert a pre-0.2 flat store (see Migrating)
secrets completions SHELL    emit completions (bash | zsh | fish)
```

Names are hierarchical, as in passage and pago: `work/aws` is
`$SECRETS_STORE/work/aws.age`, `secrets ls` recurses, and `secrets rm`
cleans up the directories it empties.

`secrets rm` confirms before deleting. Because that confirmation is read
from stdin, off a terminal it refuses rather than guessing — pass `-f` in
scripts and cron.

```sh
printf 'AKIA...\n' | secrets enc work/aws
secrets ls
# => work/aws
```

Secrets are opaque byte blobs: `secrets dec` returns exactly what you piped
into `secrets enc` — single values, multi-line files, or binary data — with
no parsing or format assumptions. Compose with standard tools instead, e.g.
the `pass`(1) convention of "first line is the password, the rest is
metadata" — which passage and pago follow — is just:

```sh
printf 'hunter2\nuser: enrique\nurl: example.com\n' | secrets enc example
secrets dec example | head -n 1        # -> hunter2
secrets dec example | tail -n +2       # -> the metadata
```

## Store layout

```
$SECRETS_DIR/                  base directory        (default ~/.secrets)
├── identities                 private key(s)        $SECRETS_IDENTITY
└── store/                     entries               $SECRETS_STORE
    ├── .age-recipients        public keys           $SECRETS_RECIPIENTS
    ├── github.age
    └── work/
        ├── .age-recipients    optional, overrides for this subtree
        └── aws.age
```

This is passage's `~/.passage` and pago's `~/.local/share/pago`, so
`SECRETS_DIR` is all it takes to work in one of theirs:

```sh
secrets ls                                       # your own store
SECRETS_DIR=~/.passage          secrets ls        # a passage store
SECRETS_DIR=~/.local/share/pago secrets ls        # a pago store
```

Nothing is cached between calls, so that also works as an export in your
shell profile if passage or pago is your primary store.

As in passage, the recipients for an entry come from the nearest
`.age-recipients` at or above its directory; a store with none at all
encrypts to the identities file's own public keys. `secrets rekey` and
`secrets rename` both honour that walk, re-encrypting an entry when it
moves across a boundary.

### What "compatible" is tested to mean

`tests/test-interop.sh` drives a single store with `secrets` and with the
real `passage` and `pago` binaries, in both directions: each reads what the
others wrote, `secrets rekey` leaves a passage store readable by passage,
and a `secrets rename` lands where passage looks. CI runs it against
pinned releases of both. Run it yourself with `make test-interop`; each
block skips itself if that program is not on your `PATH`.

Two differences are worth knowing about:

- **pago keeps its identities file encrypted** under a master password.
  `secrets` detects that from the file's own header and asks age to unwrap
  it into a mode-600 temporary file, preferring a tmpfs such as
  `/dev/shm`, removed as soon as the command returns. Writing never needs
  it — encryption only reads `.age-recipients` — but every read prompts,
  because `secrets` has no agent to cache the key in.
- **Git is yours to drive.** passage and pago wrap `git` themselves;
  `secrets` does not, so commit `$SECRETS_DIR` yourself if you want
  history. The directory holds only ciphertext, so that is safe.

### Migrating from a pre-0.2 store

Before 0.2 the store was flat: blobs, `identity.txt` and `recipients.txt`
all sat directly in `$SECRETS_DIR`. `secrets` refuses to run against one
rather than quietly starting an empty store beside it (exit code 4). One
command converts it in place, moving the blobs into `store/` and renaming
the two key files:

```sh
secrets migrate
```

Nothing is re-encrypted, so it is fast and your identity is unchanged.

### Exit codes

| Code | Meaning                                                  |
| ---- | -------------------------------------------------------- |
| `0`  | success                                                   |
| `1`  | the operation failed                                      |
| `2`  | usage error, or an invalid secret name                    |
| `3`  | no usable identity or recipients                          |
| `4`  | the store is a pre-0.2 layout; run `secrets migrate`      |

### Configuration

| Variable             | Default                          | Meaning                          |
| -------------------- | -------------------------------- | -------------------------------- |
| `SECRETS_AGE`        | auto (`age`, then `rage`)        | backend binary name or path      |
| `SECRETS_DIR`        | `~/.secrets`                     | base directory                   |
| `SECRETS_STORE`      | `$SECRETS_DIR/store`             | entries directory                |
| `SECRETS_IDENTITY`   | `$SECRETS_DIR/identities`        | private key(s) (decrypt)         |
| `SECRETS_RECIPIENTS` | the `.age-recipients` walk       | pin one recipients file          |
| `SECRETS_ARMOR`      | `0`                              | `1` = ASCII-armored `.age` files |
| `SECRETS_LIB`        | search path (see Install)        | library location, CLI only       |

`SECRETS_STORE` and `SECRETS_IDENTITY` are derived from `SECRETS_DIR` on
every call, so overriding just `SECRETS_DIR` moves the whole store.
Setting `SECRETS_RECIPIENTS` pins one file for every entry, the way
`PASSAGE_RECIPIENTS_FILE` does for passage, and disables the walk.

`SECRETS_ARMOR=1` stays interoperable in both directions: age and rage
detect armor when decrypting, pago writes armored entries itself, and
`secrets` reads either.

Because `secrets` is a separate process, these variables must be
**exported** to take effect. An unexported `SECRETS_DIR=...` is silently
ignored and the default store is used instead. Sourcing the library
directly does not have this constraint.

### Use it as a library

`secrets` is a thin wrapper around a sourceable POSIX `sh` file. Scripts
that want the dispatcher in-process can source it directly and skip the
extra process:

```sh
#!/bin/sh
set -eu
. ~/.local/share/secrets/secrets-lib.sh
GITHUB_TOKEN=$(secrets dec github)
export GITHUB_TOKEN
```

Adjust the path above to wherever you installed the library — this
example matches `PREFIX="$HOME/.local"`, but a default `make install` puts it
under `/usr/local/share/secrets/secrets-lib.sh` instead. Sourcing sets no
variables and the functions have subshell bodies, so nothing leaks into
your shell. This also works from your `.bashrc` if you prefer the function
over the command.

### Using existing SSH keys

No new key material to manage:

```sh
export SECRETS_IDENTITY=~/.ssh/id_ed25519
cp ~/.ssh/id_ed25519.pub "$SECRETS_DIR/store/.age-recipients"
```

### Adding a second machine

```sh
machine-b$ secrets init                                     # prints its public key
machine-a$ echo 'age1...' >> ~/.secrets/store/.age-recipients
machine-a$ secrets rekey                                    # re-encrypts to both keys
machine-a$ rsync -a ~/.secrets/ b:.secrets/                 # ciphertext only
```

Removing a machine is the reverse: delete its line, `secrets rekey`. Note
rekeying does not retroactively protect secrets a removed key already saw —
rotate those values.

## Testing

```sh
make test                                      # autodetected backend
sh tests/test-secrets.sh                       # same thing
SECRETS_AGE=rage dash tests/test-secrets.sh    # pin backend and shell

make test-interop                              # against real passage/pago
```

`make test-interop` exits non-zero if neither passage nor pago is on your
`PATH` — a run that verified nothing is not a pass.

The main suite is 252 checks as an ordinary user, 248 as root. Blocks skip
themselves when they cannot run: four need a non-root user (rekey's
install-rollback check turns on a directory permission root ignores), five
need `script`(1) to hand age a pty, eleven need `make`, two need no
system-wide library installed, and one needs `zsh`.

It covers roundtrips, binary payloads, hierarchical names, the
`.age-recipients` walk and its store-root boundary, tamper rejection,
path-escape attempts, clobber protection, write-only operation, rekey's
atomicity across both its staging and install passes, armor preservation,
armor mode, encrypted identities, migration from a pre-0.2 store, shell
completions driven the way readline drives them, variable-leak detection,
CLI library discovery, and install staging via `make install`/`make
uninstall`. CI runs it across {dash, bash, zsh} × {age, rage}, plus the
interop suite against pinned passage and pago releases.

## Threat model

Protects secrets **at rest** from anyone who can read the files but not the
identity. It does not protect against an attacker with your running session
(who can call `secrets dec` like you can), and the store leaks metadata:
secret *names* and file sizes are plaintext. Back up the identity file
offline — without it the store is unrecoverable.

Unwrapping a pago-style encrypted identities file writes the private key to
a temporary file for the length of one command, because age needs a real
file to read an identity from. It goes to `/dev/shm` where that exists,
mode 600, and is removed when the command returns — but on a system with
no tmpfs it lands in `$TMPDIR`, and a crash between the two can leave it
behind.

## License

MIT, see [LICENSE](LICENSE).
