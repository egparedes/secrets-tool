# secrets

A tiny secret store for the shell, built on [age](https://age-encryption.org)
or its Rust implementation [rage](https://github.com/str4d/rage). A POSIX
`sh` library plus a small CLI that wraps it, no daemon, no config format.

```console
$ secrets init
secrets: backend    age
secrets: public key age1levmga375nt6rjs69al874uh4xjpmdng87up5g7v9u2vhu3hmddqtt9d4r
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
  `recipients.txt`, so a machine or CI job can *write* secrets it cannot
  read.
- **Portable.** Strictly POSIX `sh` (sole exception: `mktemp`, which is
  universal in practice). Tested under dash, bash, and zsh, against both
  age v1.3.1 and rage v0.11.1. One store, either binary.
- **Multi-machine.** Append another machine's public key to
  `recipients.txt`, run `secrets rekey`, sync the directory (ciphertext
  only — safe for git/rsync).

## Install

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
secrets rm   NAME            delete a secret
secrets rename [-f] OLD NEW  rename a secret
secrets recipients           show who can decrypt
secrets rekey                re-encrypt everything to current recipients
secrets completions SHELL    emit completions (bash | zsh | fish)
```

Secrets are opaque byte blobs: `secrets dec` returns exactly what you piped
into `secrets enc` — single values, multi-line files, or binary data — with
no parsing or format assumptions. Compose with standard tools instead, e.g.
the `pass`(1) convention of "first line is the password, the rest is
metadata" is just:

```sh
printf 'hunter2\nuser: enrique\nurl: example.com\n' | secrets enc example
secrets dec example | head -n 1        # -> hunter2
secrets dec example | tail -n +2       # -> the metadata
```

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

### Configuration

| Variable             | Default                          | Meaning                          |
| -------------------- | -------------------------------- | -------------------------------- |
| `SECRETS_AGE`        | auto (`age`, then `rage`)        | backend binary name or path      |
| `SECRETS_DIR`        | `~/.secrets`                     | store location                   |
| `SECRETS_IDENTITY`   | `$SECRETS_DIR/identity.txt`      | private key (decrypt)            |
| `SECRETS_RECIPIENTS` | `$SECRETS_DIR/recipients.txt`    | public keys (encrypt)            |
| `SECRETS_ARMOR`      | `0`                              | `1` = ASCII-armored `.age` files |
| `SECRETS_LIB`        | search path (see Install)        | library location, CLI only       |

Because `secrets` is a separate process, these variables must be
**exported** to take effect. An unexported `SECRETS_DIR=...` is silently
ignored and the default store is used instead. Sourcing the library
directly does not have this constraint.

### Using existing SSH keys

No new key material to manage:

```sh
export SECRETS_IDENTITY=~/.ssh/id_ed25519
cp ~/.ssh/id_ed25519.pub "$SECRETS_DIR/recipients.txt"
```

### Adding a second machine

```sh
machine-b$ secrets init                      # prints its public key
machine-a$ echo 'age1...' >> ~/.secrets/recipients.txt
machine-a$ secrets rekey                     # re-encrypts to both keys
machine-a$ rsync -a ~/.secrets/ b:.secrets/ # ciphertext only
```

Removing a machine is the reverse: delete its line, `secrets rekey`. Note
rekeying does not retroactively protect secrets a removed key already saw —
rotate those values.

## Testing

```sh
make test                                      # autodetected backend
sh tests/test-secrets.sh                       # same thing
SECRETS_AGE=rage dash tests/test-secrets.sh    # pin backend and shell
```

The suite (97 checks on a typical machine — a couple are skipped if a
system-wide library is already installed, and one if `zsh` isn't present)
covers roundtrips, binary payloads, tamper rejection, name-injection
attempts, clobber protection, write-only operation, atomic rekey, armor
mode, completions, variable-leak detection, CLI library discovery, and
install staging via `make install`/`make uninstall`. CI runs it across
{dash, bash, zsh} × {age, rage}.

## Threat model

Protects secrets **at rest** from anyone who can read the files but not the
identity. It does not protect against an attacker with your running session
(who can call `secrets dec` like you can), and the store leaks metadata:
secret *names* and file sizes are plaintext. Back up the identity file
offline — without it the store is unrecoverable.

## License

MIT, see [LICENSE](LICENSE).
