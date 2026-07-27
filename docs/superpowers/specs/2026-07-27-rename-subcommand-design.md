# Design: `secret rename [-f] OLD NEW`

Date: 2026-07-27
Status: approved

## Purpose

Add a subcommand that renames a stored secret without touching its
contents. Today the only way to rename is `secret dec OLD | secret enc
NEW && secret rm OLD`, which round-trips plaintext through the user's
shell and loses the original on a typo.

## Semantics

`secret rename [-f] OLD NEW` moves `$SECRETS_DIR/OLD.age` to
`$SECRETS_DIR/NEW.age`.

This is a pure filesystem operation: age does not bind the filename into
the ciphertext, so no decryption, re-encryption, identity, or recipients
file is involved. Renaming works on a write-only machine (no identity
present) and on a store with no recipients file.

## Error handling

Mirrors the existing subcommands exactly:

| Condition                  | Behavior                                                        | Exit |
| -------------------------- | --------------------------------------------------------------- | ---- |
| `OLD` or `NEW` invalid     | `secret: invalid name: X` (via `_secret_name`)                   | 2    |
| `OLD` missing              | `secret: no such secret: OLD` (same wording as `dec`/`rm`)       | 1    |
| `NEW` exists, no `-f`      | `secret: .../NEW.age already exists (use -f to overwrite)`       | 1    |
| `OLD` = `NEW`              | rejected as a no-op error                                        | 1    |
| success                    | silent, like `enc`                                               | 0    |

## Implementation

- New `_secret_rename` function with a subshell body `f() (...)`, matching
  every other subcommand so no variables leak into the sourcing shell.
- Final operation is a single `mv -f --` within `$SECRETS_DIR` (atomic on
  the same filesystem; the store is always one directory).
- Dispatcher gains a `rename)` case.

## Touch points

Everything that enumerates subcommands stays in sync:

- `secret.sh`: header comment listing, `_secret_rename`, `_secret_help`
  text, dispatcher, and all three completion scripts. `rename` completes
  stored names for its arguments plus `-f`, like `enc`.
- `tests/test-secret.sh`: new section covering successful rename (old
  gone, new decrypts to the same plaintext), missing `OLD`, clobber
  refusal without `-f`, `-f` overwrite, invalid-name rejection for both
  positions, self-rename rejection, and additions to the variable-leak
  check for any new locals.
- `README.md`: usage block and updated test-count sentence.
- `CHANGELOG.md`: bullet under 0.1.0 (unreleased), including the updated
  check count.

## Out of scope

No flags beyond `-f`, no cross-store moves, no copy variant, no directory
support (names cannot contain `/` by validation).
