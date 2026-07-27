# Changelog

## [0.1.0] - unreleased

Initial release.

- POSIX `sh` secret store sourced as a single file; `secret` dispatcher
  with `init`, `enc`, `dec`, `ls`, `rm`, `rename`, `recipients`,
  `rekey`, `completions`, `help` subcommands.
- Interchangeable age / rage backends, auto-detected, pinnable via
  `SECRETS_AGE`.
- Asymmetric encryption against a recipients file; write-only operation
  without the identity present; SSH keys usable as identities.
- Atomic, all-or-nothing `rekey`; tamper rejection via age's authenticated
  encryption; strict secret-name validation.
- Shell completions for bash, zsh, and fish.
- Format-agnostic storage: secrets are opaque byte blobs, decrypted
  verbatim with no KEY=value or other content conventions.
- 79-check test suite run in CI across {dash, bash, zsh} x {age, rage}.
