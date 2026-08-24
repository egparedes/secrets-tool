# Changelog

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
- 104-check test suite run in CI across {dash, bash, zsh} x {age, rage}.
