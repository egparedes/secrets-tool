# secret.sh

A tiny secret store for the shell, built on [age](https://age-encryption.org)
or its Rust implementation [rage](https://github.com/str4d/rage). One
sourceable POSIX `sh` file, no daemon, no config format.

```console
$ secret init
secret: backend    age
secret: public key age1levmga375nt6rjs69al874uh4xjpmdng87up5g7v9u2vhu3hmddqtt9d4r
$ printf 'ghp_abc123\n' | secret enc github
$ secret dec github
ghp_abc123
$ export GITHUB_TOKEN="$(secret dec github)"
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
  `recipients.txt`, run `secret rekey`, sync the directory (ciphertext
  only — safe for git/rsync).

## Install

Requires `age` (or `rage`) — single static binaries, also in most package
managers (`apt install age`, `brew install age`, `pacman -S age`, ...).

No clone needed — fetch the one file that matters and source it:

```sh
mkdir -p ~/.local/share/secret-sh
curl -fsSL https://raw.githubusercontent.com/OWNER/secret-sh/main/secret.sh \
    -o ~/.local/share/secret-sh/secret.sh

# bash/zsh/dash — add to your shell rc:
echo '. "$HOME/.local/share/secret-sh/secret.sh"' >> ~/.bashrc
```

(Replace `OWNER` with the GitHub owner after pushing; or pin a tag/commit
instead of `main` for reproducible installs.)

Then, optionally, tab completion:

```sh
# bash (.bashrc):            eval "$(secret completions bash)"
# zsh  (.zshrc, after compinit):  eval "$(secret completions zsh)"
# fish:  secret completions fish > ~/.config/fish/completions/secret.fish
```

## Usage

```
secret init                 create the store, generate an identity
secret enc  [-f] NAME       encrypt stdin -> NAME.age  (-f overwrites)
secret dec  NAME            decrypt to stdout, verbatim
secret ls                   list stored names
secret rm   NAME            delete a secret
secret rename [-f] OLD NEW  rename a secret
secret recipients           show who can decrypt
secret rekey                re-encrypt everything to current recipients
secret completions SHELL    emit completions (bash | zsh | fish)
```

Secrets are opaque byte blobs: `secret dec` returns exactly what you piped
into `secret enc` — single values, multi-line files, or binary data — with
no parsing or format assumptions. Compose with standard tools instead, e.g.
the `pass`(1) convention of "first line is the password, the rest is
metadata" is just:

```sh
printf 'hunter2\nuser: enrique\nurl: example.com\n' | secret enc example
secret dec example | head -n 1        # -> hunter2
secret dec example | tail -n +2       # -> the metadata
```

### Configuration

| Variable             | Default                          | Meaning                          |
| -------------------- | -------------------------------- | -------------------------------- |
| `SECRETS_AGE`        | auto (`age`, then `rage`)        | backend binary name or path      |
| `SECRETS_DIR`        | `~/.secrets`                     | store location                   |
| `SECRETS_IDENTITY`   | `$SECRETS_DIR/identity.txt`      | private key (decrypt)            |
| `SECRETS_RECIPIENTS` | `$SECRETS_DIR/recipients.txt`    | public keys (encrypt)            |
| `SECRETS_ARMOR`      | `0`                              | `1` = ASCII-armored `.age` files |

### Using existing SSH keys

No new key material to manage:

```sh
export SECRETS_IDENTITY=~/.ssh/id_ed25519
cp ~/.ssh/id_ed25519.pub "$SECRETS_DIR/recipients.txt"
```

### Adding a second machine

```sh
machine-b$ secret init                      # prints its public key
machine-a$ echo 'age1...' >> ~/.secrets/recipients.txt
machine-a$ secret rekey                     # re-encrypts to both keys
machine-a$ rsync -a ~/.secrets/ b:.secrets/ # ciphertext only
```

Removing a machine is the reverse: delete its line, `secret rekey`. Note
rekeying does not retroactively protect secrets a removed key already saw —
rotate those values.

## Testing

```sh
sh tests/test-secret.sh                       # autodetected backend
SECRETS_AGE=rage dash tests/test-secret.sh    # pin backend and shell
```

The suite (79 checks) covers roundtrips, binary payloads, tamper rejection,
name-injection attempts, clobber protection, write-only operation, atomic
rekey, armor mode, completions, and variable-leak detection. CI runs it
across {dash, bash, zsh} × {age, rage}.

## Threat model

Protects secrets **at rest** from anyone who can read the files but not the
identity. It does not protect against an attacker with your running session
(who can call `secret dec` like you can), and the store leaks metadata:
secret *names* and file sizes are plaintext. Back up the identity file
offline — without it the store is unrecoverable.

## License

MIT, see [LICENSE](LICENSE).
