# shellcheck shell=sh
# ── secrets ──────────────────────────────────────────────────────────────────
# Tiny secret store built on age(1) or its Rust implementation rage(1).
# The two produce interchangeable files; the backend is detected automatically
# and can be pinned with SECRETS_AGE. POSIX sh: sourceable from dash, ash,
# busybox sh, bash, zsh, and anything else claiming sh compatibility.
#
#   secrets init                 create the store, generate an identity
#   secrets enc  [-f] NAME       encrypt stdin -> $SECRETS_STORE/NAME.age
#   secrets dec  NAME            decrypt -> stdout, plaintext verbatim
#   secrets ls                   list stored names
#   secrets rm   [-f] NAME       delete a secret (-f skips the prompt)
#   secrets rename [-f] OLD NEW  rename a secret
#   secrets recipients [NAME]    show who can decrypt
#   secrets rekey                re-encrypt everything to current recipients
#   secrets migrate              convert a pre-0.2 flat store to the new layout
#   secrets completions SHELL    emit completion script (bash | zsh | fish)
#   secrets help                 this listing
#
# ── Store layout ─────────────────────────────────────────────────────────────
# Byte-for-byte the layout of passage (https://github.com/FiloSottile/passage)
# and pago (https://github.com/dbohdan/pago), so the same directory can be
# driven by any of the three:
#
#   $SECRETS_DIR/                  base directory      (default ~/.secrets)
#   ├── identities                 private key(s)      $SECRETS_IDENTITY
#   └── store/                     entries             $SECRETS_STORE
#       ├── .age-recipients        public keys         $SECRETS_RECIPIENTS
#       ├── github.age
#       └── work/
#           ├── .age-recipients    optional, overrides for this subtree
#           └── aws.age
#
# Point SECRETS_DIR at somebody else's store and nothing else changes:
#   export SECRETS_DIR=~/.passage             # a passage store
#   export SECRETS_DIR=~/.local/share/pago    # a pago store
#
# Names are hierarchical: `work/aws` is $SECRETS_STORE/work/aws.age. As in
# passage, the recipients used for an entry come from the nearest
# .age-recipients at or above its directory, and fall back to the identities
# file when the store has none.
#
# ── Config (all overridable) ─────────────────────────────────────────────────
#   SECRETS_AGE         age binary: 'age', 'rage', or a path   (auto-detected)
#   SECRETS_DIR         base directory             (default ~/.secrets)
#   SECRETS_STORE       entries directory          (default $SECRETS_DIR/store)
#   SECRETS_IDENTITY    private key(s), decrypt    (default $SECRETS_DIR/identities)
#   SECRETS_RECIPIENTS  pin one recipients file    (default: the .age-recipients walk)
#   SECRETS_ARMOR       1 = ASCII-armored output   (default 0, binary)
#   SECRETS_LIB         library path, CLI only     (search order: bin/secrets)
#
# The keygen tool is derived from the backend name: age -> age-keygen,
# rage -> rage-keygen, /opt/age -> /opt/age-keygen.
#
# Encryption is asymmetric: it needs only the public recipients file, so a
# machine or CI job can write secrets it cannot read. To use existing SSH
# keys instead of a dedicated age identity:
#   export SECRETS_IDENTITY=~/.ssh/id_ed25519
#   cp ~/.ssh/id_ed25519.pub "$SECRETS_STORE/.age-recipients"
#
# pago keeps its identities file encrypted under a master passphrase. That is
# detected from the file's own header and handled: age is asked to decrypt it
# (prompting on the terminal) into a mode-600 temporary file, preferring a
# tmpfs such as /dev/shm, which is removed when the command returns. There is
# no agent, so each command that needs the private key prompts again.
#
# Adding a second machine: run `secrets init` there, append its printed public
# key to $SECRETS_STORE/.age-recipients here, run `secrets rekey`, then sync
# $SECRETS_DIR (ciphertext only; safe for git/rsync).
#
# Completions:  eval "$(secrets completions bash)"     # bash, in .bashrc
#               eval "$(secrets completions zsh)"      # zsh, after compinit
#               secrets completions fish > ~/.config/fish/completions/secrets.fish
#
# Two ways in: run the `secrets` command, which finds and sources this file,
# or source this file yourself and call the `secrets` function directly.
# Sourcing leaks nothing -- helper functions use subshell bodies `f() (...)`.
#
# CI runs the suite across {dash, bash, zsh} x {age, rage}, and the
# interop suite against pinned passage and pago releases.
# ─────────────────────────────────────────────────────────────────────────────

# Sourcing must always succeed and must set nothing: SECRETS_STORE and
# SECRETS_IDENTITY are derived from SECRETS_DIR by the dispatcher, once per
# call, inside its subshell. Deriving them here instead would freeze them at
# source time, so `SECRETS_DIR=~/.passage secrets ls` would read the passage
# store's entries with this store's identity. SECRETS_RECIPIENTS is left
# unset on purpose: recipients are resolved per entry by walking up from its
# directory to the store root, and setting it pins one file for the whole
# store, the way PASSAGE_RECIPIENTS_FILE does for passage.

# --- internal helpers (subshell bodies: nothing leaks) -----------------------

# Print the backend binary to use, or fail.
_secrets_age() (
    if [ -n "${SECRETS_AGE-}" ]; then
        if command -v "$SECRETS_AGE" >/dev/null 2>&1; then
            printf '%s\n' "$SECRETS_AGE"; exit 0
        fi
        printf 'secrets: SECRETS_AGE=%s not found in PATH\n' "$SECRETS_AGE" >&2
        exit 127
    fi
    for bin in age rage; do
        if command -v "$bin" >/dev/null 2>&1; then
            printf '%s\n' "$bin"; exit 0
        fi
    done
    printf 'secrets: neither age nor rage found in PATH (https://age-encryption.org)\n' >&2
    exit 127
)

# Print the matching keygen tool (age-keygen / rage-keygen), or fail.
_secrets_keygen() (
    agebin=$(_secrets_age) || exit $?
    keygen="${agebin}-keygen"
    if command -v "$keygen" >/dev/null 2>&1; then
        printf '%s\n' "$keygen"; exit 0
    fi
    printf 'secrets: %s not found in PATH\n' "$keygen" >&2
    exit 127
)

# Reject names that could escape the store or collide with its dot-files.
# Slashes are allowed -- passage and pago names are hierarchical -- but no
# component may be empty or start with a dot, which rules out `..`, `.git`
# and `.age-recipients` in one pattern. Everything else a passage store can
# hold (spaces, '@', '+', ';', '$') is accepted: names only ever reach other
# programs as quoted path arguments, never as shell input.
_secrets_name() (
    case "${1-}" in
        '' | /* | */ | *//* | .* | */.* | *[[:cntrl:]]*)
            printf 'secrets: invalid name: %s\n' "${1:-<empty>}" >&2
            exit 2
            ;;
    esac
)

# Print a name's directory relative to the store; empty at the store root.
_secrets_subdir() (
    case "${1-}" in
        */*) printf '%s\n' "${1%/*}" ;;
    esac
)

# Print the .age-recipients that governs the store-relative directory $1, or
# nothing when the store has none. Mirrors passage's set_age_recipients: the
# nearest file at or above the entry wins, and SECRETS_RECIPIENTS pins one.
_secrets_recipients_for() (
    if [ -n "${SECRETS_RECIPIENTS:-}" ]; then
        printf '%s\n' "$SECRETS_RECIPIENTS"
        exit 0
    fi
    dir="$SECRETS_STORE${1:+/$1}"
    while :; do
        if [ -f "$dir/.age-recipients" ]; then
            printf '%s\n' "$dir/.age-recipients"
            exit 0
        fi
        [ "$dir" = "$SECRETS_STORE" ] && exit 0
        case $dir in
            */?*) dir=${dir%/*} ;;
            *)    exit 0 ;;
        esac
    done
)

# Encryption needs either a recipients file or an identity to derive one from.
_secrets_need_recipients() (
    rf=$(_secrets_recipients_for "${1-}")
    [ -n "$rf" ] && [ -s "$rf" ] && exit 0
    [ -r "$SECRETS_IDENTITY" ] && exit 0
    printf 'secrets: no recipients under %s and no identity at %s (run: secrets init)\n' \
        "$SECRETS_STORE" "$SECRETS_IDENTITY" >&2
    exit 3
)

_secrets_need_identity() (
    if [ ! -r "$SECRETS_IDENTITY" ]; then
        printf 'secrets: identity not readable: %s (run: secrets init)\n' \
            "$SECRETS_IDENTITY" >&2
        exit 3
    fi
)

# Print a path to a *plaintext* identity file. Usually that is
# $SECRETS_IDENTITY itself. A pago store keeps it encrypted under a master
# passphrase, and age needs a real file, so decrypt it into a mode-600
# temporary -- on a tmpfs where the platform has one. The caller compares the
# printed path against $SECRETS_IDENTITY and removes it when they differ.
_secrets_identity_open() (
    _secrets_need_identity || exit $?
    case $(head -n 1 "$SECRETS_IDENTITY" 2>/dev/null) in
        'age-encryption.org/v1' | '-----BEGIN AGE ENCRYPTED FILE-----') ;;
        *) printf '%s\n' "$SECRETS_IDENTITY"; exit 0 ;;
    esac

    agebin=$(_secrets_age) || exit $?
    tmp=''
    # Armed before mktemp: everything from the moment the file has a name is
    # covered. The gap left is the command substitution itself, in which the
    # file exists but is still empty.
    trap '[ -z "$tmp" ] || rm -f "$tmp"; exit 1' HUP INT TERM
    for dir in /dev/shm "${TMPDIR:-/tmp}"; do
        if [ -d "$dir" ] && [ -w "$dir" ]; then
            tmp=$(mktemp "$dir/.secrets-id.XXXXXX" 2>/dev/null) && break
            tmp=''
        fi
    done
    if [ -z "$tmp" ]; then
        printf 'secrets: cannot create a temporary file for the identity\n' >&2
        exit 1
    fi
    chmod 600 "$tmp" || { rm -f "$tmp"; exit 1; }

    # Prompting happens on the terminal; stdout here is a command substitution.
    if "$agebin" -d -o "$tmp" "$SECRETS_IDENTITY"; then
        printf '%s\n' "$tmp"
    else
        rm -f "$tmp"
        printf 'secrets: could not decrypt the identities file %s\n' \
            "$SECRETS_IDENTITY" >&2
        exit 3
    fi
)

# Encrypt stdin to the file $1. $2 is the entry's store-relative directory,
# which selects the .age-recipients to use; $3 is an already-opened plaintext
# identity to fall back on when no recipients file governs that directory
# (passing it keeps rekey from re-prompting once per entry).
# Print 1 when the age file $1 is ASCII-armored, 0 otherwise. pago writes
# armored entries; rekey uses this to keep each entry in the format it is
# already in instead of converting the whole store.
_secrets_armor_of() (
    case $(head -n 1 "$1" 2>/dev/null) in
        '-----BEGIN AGE ENCRYPTED FILE-----') printf '1\n' ;;
        *) printf '0\n' ;;
    esac
)

_secrets_encrypt_to() (
    out=$1
    sub=${2-}
    idf=${3-}
    armor=${4-${SECRETS_ARMOR:-0}}

    agebin=$(_secrets_age) || exit $?
    rf=$(_secrets_recipients_for "$sub")
    if [ -n "$rf" ]; then
        set -- -R "$rf"
    else
        if [ -z "$idf" ]; then
            trap '[ -z "$idf" ] || [ "$idf" = "$SECRETS_IDENTITY" ] || rm -f "$idf"' EXIT
            trap 'exit 1' HUP INT TERM
            idf=$(_secrets_identity_open) || exit $?
        fi
        set -- -i "$idf"
    fi
    if [ "$armor" = 1 ]; then
        set -- -a "$@"
    fi
    "$agebin" -e "$@" -o "$out"
)

# Remove each non-empty argument. Used from EXIT traps, where the paths must
# be expanded when the trap fires, not when it is installed -- a store path
# holding a quote would otherwise break the trap's own quoting.
_secrets_scrub() (
    for f in "$@"; do
        [ -n "$f" ] && rm -f -- "$f"
    done
    exit 0
)

# Remove the directories a deleted entry leaves empty, up to the store root.
_secrets_prune() (
    dir=${1%/*}
    while [ "$dir" != "$SECRETS_STORE" ] && [ -d "$dir" ]; do
        rmdir "$dir" 2>/dev/null || exit 0
        dir=${dir%/*}
    done
    exit 0
)

# True when $SECRETS_DIR still holds a pre-0.2 flat store's artifacts: blobs,
# identity.txt or recipients.txt sitting directly in the base directory.
_secrets_has_legacy() (
    [ -e "$SECRETS_DIR/identity.txt" ] && exit 0
    [ -e "$SECRETS_DIR/recipients.txt" ] && exit 0
    # find, not a glob: zsh makes an unmatched glob a fatal error rather than
    # leaving it literal, which would kill every subcommand on a fresh store.
    [ -n "$(find "$SECRETS_DIR" -maxdepth 1 -type f -name '*.age' 2>/dev/null |
            head -n 1)" ] && exit 0
    exit 1
)

# Refuse to run against a pre-0.2 store rather than silently starting a second,
# empty one beside it. Deliberately keyed on the leftover artifacts and not on
# whether store/ exists: a migrate that failed part way leaves both, and this
# has to keep firing until the last artifact is gone, or that half-migrated
# store would look empty and healthy.
_secrets_legacy_guard() (
    _secrets_has_legacy || exit 0
    printf 'secrets: %s holds pre-0.2 files (run: secrets migrate):\n' \
        "$SECRETS_DIR" >&2
    [ -e "$SECRETS_DIR/identity.txt" ] &&
        printf 'secrets:   identity.txt\n' >&2
    [ -e "$SECRETS_DIR/recipients.txt" ] &&
        printf 'secrets:   recipients.txt\n' >&2
    find "$SECRETS_DIR" -maxdepth 1 -type f -name '*.age' 2>/dev/null |
        while IFS= read -r f; do
            [ -n "$f" ] && printf 'secrets:   %s\n' "${f##*/}" >&2
        done
    exit 4
)

# --- subcommands -------------------------------------------------------------

_secrets_init() (
    keygen=$(_secrets_keygen) || exit $?

    ( umask 077 && mkdir -p "$SECRETS_DIR" "$SECRETS_STORE" ) || exit 1
    chmod 700 "$SECRETS_DIR" "$SECRETS_STORE" || exit 1

    if [ -e "$SECRETS_IDENTITY" ]; then
        printf 'secrets: identity already exists: %s (refusing to overwrite)\n' \
            "$SECRETS_IDENTITY" >&2
        exit 1
    fi

    # Both age-keygen and rage-keygen create the file with mode 600.
    "$keygen" -o "$SECRETS_IDENTITY" >/dev/null 2>&1 || {
        printf 'secrets: %s failed\n' "$keygen" >&2
        exit 1
    }

    pub=$("$keygen" -y "$SECRETS_IDENTITY") || exit 1
    rf=${SECRETS_RECIPIENTS:-$SECRETS_STORE/.age-recipients}
    ( umask 077
      printf '# %s (added %s)\n%s\n' \
          "$(uname -n 2>/dev/null || echo host)" \
          "$(date -u +%Y-%m-%d)" "$pub" >> "$rf" ) 2>/dev/null || {
        printf 'secrets: cannot write recipients to %s\n' "$rf" >&2
        exit 1
    }

    printf 'secrets: backend    %s\n' "$(_secrets_age)" >&2
    printf 'secrets: store      %s\n' "$SECRETS_STORE" >&2
    printf 'secrets: identity   %s\n' "$SECRETS_IDENTITY" >&2
    printf 'secrets: recipients %s\n' "$rf" >&2
    printf 'secrets: public key %s\n' "$pub" >&2
    printf 'secrets: back up the identity -- without it every .age file is unrecoverable\n' >&2
)

_secrets_enc() (
    force=0
    if [ "${1-}" = "-f" ]; then force=1; shift; fi

    _secrets_name "${1-}" || exit $?
    sub=$(_secrets_subdir "$1")
    _secrets_need_recipients "$sub" || exit $?

    out="$SECRETS_STORE/$1.age"
    if [ -e "$out" ] && [ "$force" -eq 0 ]; then
        printf 'secrets: %s already exists (use -f to overwrite)\n' "$out" >&2
        exit 1
    fi
    [ -t 0 ] && printf 'secrets: reading plaintext from stdin, end with Ctrl-D\n' >&2

    ( umask 077 && mkdir -p "${out%/*}" ) || exit 1
    tmp=''
    trap '[ -z "$tmp" ] || rm -f "$tmp"' EXIT
    trap 'exit 1' HUP INT TERM
    tmp=$(mktemp "${out%/*}/.tmp.XXXXXX") || exit 1
    if ! _secrets_encrypt_to "$tmp" "$sub"; then
        printf 'secrets: encryption failed, %s left untouched\n' "$out" >&2
        exit 1
    fi
    if ! chmod 600 "$tmp" || ! mv -f -- "$tmp" "$out"; then
        printf 'secrets: could not install %s, left untouched\n' "$out" >&2
        exit 1
    fi
    tmp=''
)

_secrets_dec() (
    agebin=$(_secrets_age) || exit $?
    _secrets_name "${1-}" || exit $?
    _secrets_need_identity || exit $?

    in="$SECRETS_STORE/$1.age"
    if [ ! -r "$in" ]; then
        printf 'secrets: no such secret: %s\n' "$1" >&2
        exit 1
    fi
    idf=''
    trap '[ -z "$idf" ] || [ "$idf" = "$SECRETS_IDENTITY" ] || rm -f "$idf"' EXIT
    trap 'exit 1' HUP INT TERM
    idf=$(_secrets_identity_open) || exit $?
    "$agebin" -d -i "$idf" "$in"
)

# Recurse: passage and pago names are hierarchical. Dot-directories are
# pruned, which keeps .git, a staging directory and .age-recipients out.
_secrets_ls() (
    [ -d "$SECRETS_STORE" ] || exit 0
    CDPATH='' cd -- "$SECRETS_STORE" || exit 1
    # find runs on its own, not as the head of a pipeline: POSIX sh has no
    # pipefail, so piping it would report sort's status and a directory find
    # could not read would come back as a silently short list. rekey builds
    # its whole work list from here -- a short list there means entries keep
    # a recipient the user believes they revoked.
    found=$(find -L . -name '.?*' -prune -o -type f -name '*.age' -print) || {
        printf 'secrets: cannot list %s in full\n' "$SECRETS_STORE" >&2
        exit 1
    }
    [ -n "$found" ] || exit 0
    printf '%s\n' "$found" | sed -e 's|^\./||' -e 's|\.age$||' | LC_ALL=C sort
)

# Interactive by default, as before. `rm -i` reads its confirmation from
# stdin, so with stdin at EOF -- a script, cron, CI, xargs -- it declines and
# still exits 0: the old code reported success having deleted nothing. Off a
# terminal we now require -f rather than guess, and either way we verify the
# file is actually gone before reporting success.
_secrets_rm() (
    force=0
    if [ "${1-}" = "-f" ]; then force=1; shift; fi

    _secrets_name "${1-}" || exit $?
    f="$SECRETS_STORE/$1.age"
    if [ ! -e "$f" ]; then
        printf 'secrets: no such secret: %s\n' "$1" >&2
        exit 1
    fi

    if [ "$force" -eq 1 ]; then
        rm -f -- "$f"
    elif [ -t 0 ]; then
        rm -i -- "$f"
    else
        printf 'secrets: rm needs a terminal to confirm; use: secrets rm -f %s\n' \
            "$1" >&2
        exit 1
    fi

    # The single arbiter for both branches: `rm -i` reports success when the
    # user declines, and rm's own failures (a read-only directory, EIO) leave
    # the file in place, so the file being gone is the only proof it went.
    if [ -e "$f" ]; then
        printf 'secrets: %s was not removed\n' "$1" >&2
        exit 1
    fi
    _secrets_prune "$f"
    exit 0
)

# A plain move when both ends encrypt to the same recipients -- that needs no
# private key, as before. When they differ (only possible once a subtree has
# its own .age-recipients) passage re-encrypts, and so do we.
_secrets_rename() (
    force=0
    if [ "${1-}" = "-f" ]; then force=1; shift; fi

    _secrets_name "${1-}" || exit $?
    _secrets_name "${2-}" || exit $?

    src="$SECRETS_STORE/$1.age"
    dst="$SECRETS_STORE/$2.age"
    if [ ! -e "$src" ]; then
        printf 'secrets: no such secret: %s\n' "$1" >&2
        exit 1
    fi
    if [ "$1" = "$2" ]; then
        printf 'secrets: %s is already named %s\n' "$1" "$2" >&2
        exit 1
    fi
    if [ -e "$dst" ] && [ "$force" -eq 0 ]; then
        printf 'secrets: %s already exists (use -f to overwrite)\n' "$dst" >&2
        exit 1
    fi

    sub=$(_secrets_subdir "$2")
    ( umask 077 && mkdir -p "${dst%/*}" ) || exit 1

    if [ "$(_secrets_recipients_for "$(_secrets_subdir "$1")")" = \
         "$(_secrets_recipients_for "$sub")" ]; then
        mv -f -- "$src" "$dst" || exit 1
        _secrets_prune "$src"
        exit 0
    fi

    agebin=$(_secrets_age) || exit $?
    idf=''
    tmp=''
    st=''
    trap '_secrets_scrub "$tmp" "$st"
          [ -z "$idf" ] || [ "$idf" = "$SECRETS_IDENTITY" ] || rm -f "$idf"' EXIT
    trap 'exit 1' HUP INT TERM
    idf=$(_secrets_identity_open) || exit $?

    tmp=$(mktemp "${dst%/*}/.tmp.XXXXXX") || exit 1
    st=$(mktemp "${dst%/*}/.st.XXXXXX") || exit 1
    # POSIX has no pipefail, and encrypting a failed decrypt's empty output
    # still yields a valid, non-empty age file -- which would look like a
    # clean re-encryption and cost the source. Funnel the producer's status
    # through a file instead.
    { "$agebin" -d -i "$idf" "$src" || echo fail > "$st"; } \
        | _secrets_encrypt_to "$tmp" "$sub" "$idf" "$(_secrets_armor_of "$src")"
    if [ ! -s "$st" ] && [ -s "$tmp" ]; then
        chmod 600 "$tmp" && mv -f -- "$tmp" "$dst" || exit 1
        tmp=''
        rm -f -- "$src"
        _secrets_prune "$src"
    else
        printf 'secrets: re-encryption failed, %s left in place\n' "$1" >&2
        exit 1
    fi
)

_secrets_recipients() (
    if [ "$#" -gt 0 ]; then
        _secrets_name "$1" || exit $?
        sub=$(_secrets_subdir "$1")
    else
        sub=''
    fi
    rf=$(_secrets_recipients_for "$sub")
    if [ -n "$rf" ] && [ -s "$rf" ]; then
        cat "$rf"
        exit 0
    fi
    # No recipients file: passage encrypts to the identities file's own public
    # keys, so those are the recipients. Derive and print them.
    if [ -r "$SECRETS_IDENTITY" ]; then
        keygen=$(_secrets_keygen) || exit $?
        idf=''
        trap '[ -z "$idf" ] || [ "$idf" = "$SECRETS_IDENTITY" ] || rm -f "$idf"' EXIT
        trap 'exit 1' HUP INT TERM
        idf=$(_secrets_identity_open) || exit $?
        printf '# derived from %s (no .age-recipients in the store)\n' \
            "$SECRETS_IDENTITY"
        "$keygen" -y "$idf"
        exit $?
    fi
    printf 'secrets: no recipients under %s and no identity at %s\n' \
        "$SECRETS_STORE" "$SECRETS_IDENTITY" >&2
    exit 3
)

# Re-encrypt every secret to the recipients that currently govern it. All-or-
# nothing: stages into a temp dir and only swaps in once every blob re-
# encrypted cleanly. Plaintext stays in a pipe; it never touches disk.
_secrets_rekey() (
    agebin=$(_secrets_age) || exit $?
    _secrets_need_identity || exit $?
    _secrets_need_recipients || exit $?

    [ -d "$SECRETS_STORE" ] || { printf 'secrets: no secrets to rekey\n' >&2; exit 0; }
    stage=''
    idf=''
    # One trap for every exit path, success included: the staging tree and any
    # unwrapped identity are temporaries, and no branch below may outlive them.
    trap '[ -z "$stage" ] || rm -rf "$stage"
          [ -z "$idf" ] || [ "$idf" = "$SECRETS_IDENTITY" ] || rm -f "$idf"' EXIT
    # An interrupt rolls nothing back -- it just stops. No entry can be lost,
    # but the store may be left half on the new recipients and half on the
    # old, which matters most to the very workflow rekey exists for.
    trap 'printf "secrets: interrupted; the store may be partly rekeyed -- re-run: secrets rekey\n" >&2
          exit 1' HUP INT TERM
    stage=$(mktemp -d "$SECRETS_STORE/.rekey.XXXXXX") || exit 1
    idf=$(_secrets_identity_open) || exit 3

    # The listing has to be taken before anything is staged, and re-read
    # afterwards for the install pass; a file is the only POSIX-sh "array".
    list="$stage/.list"
    _secrets_ls > "$list" || exit 1

    n=0
    st="$stage/.st"
    while IFS= read -r name; do
        [ -n "$name" ] || continue
        sub=$(_secrets_subdir "$name")
        [ -z "$sub" ] || mkdir -p "$stage/$sub" || exit 1
        # POSIX has no pipefail; funnel the producer's status through a file.
        { "$agebin" -d -i "$idf" "$SECRETS_STORE/$name.age" || echo fail > "$st"; } \
            | _secrets_encrypt_to "$stage/$name.age" "$sub" "$idf" \
                  "$(_secrets_armor_of "$SECRETS_STORE/$name.age")"
        if [ -f "$st" ] || [ ! -s "$stage/$name.age" ]; then
            printf 'secrets: rekey failed on %s, nothing changed\n' "$name" >&2
            exit 1
        fi
        n=$((n + 1))
    done < "$list"

    if [ "$n" -eq 0 ]; then
        printf 'secrets: no secrets to rekey\n' >&2
        exit 0
    fi

    # Installing is the other half of all-or-nothing. Each original is hard
    # LINKED into the staging tree, never moved into it: the entry keeps
    # existing at its real path the whole time, so an interrupt that deletes
    # the staging tree cannot destroy it, and a failure part way through can
    # still put every already-installed entry back. $stage lives inside the
    # store, so the link is always within one filesystem.
    mkdir -p "$stage/.orig" || exit 1
    done_list="$stage/.done"
    : > "$done_list" || exit 1
    failed_at=''
    while IFS= read -r name; do
        [ -n "$name" ] || continue
        sub=$(_secrets_subdir "$name")
        if [ -n "$sub" ] && ! mkdir -p "$stage/.orig/$sub"; then
            failed_at=$name; break
        fi
        if ! ln -- "$SECRETS_STORE/$name.age" "$stage/.orig/$name.age" 2>/dev/null &&
           ! cp -p -- "$SECRETS_STORE/$name.age" "$stage/.orig/$name.age"; then
            failed_at=$name; break
        fi
        # Only this rename touches the live entry, and it is atomic: it either
        # names the old blob or the new one, never nothing.
        if ! chmod 600 "$stage/$name.age" ||
           ! mv -f -- "$stage/$name.age" "$SECRETS_STORE/$name.age"; then
            failed_at=$name; break
        fi
        printf '%s\n' "$name" >> "$done_list"
    done < "$list"

    if [ -n "$failed_at" ]; then
        restored=1
        while IFS= read -r name; do
            [ -n "$name" ] || continue
            # A failed restore is the one case worth shouting about: the old
            # blob then exists only inside the staging tree.
            if ! mv -f -- "$stage/.orig/$name.age" "$SECRETS_STORE/$name.age"; then
                restored=0
                printf 'secrets: could not restore %s\n' "$name" >&2
            fi
        done < "$done_list"
        if [ "$restored" -eq 1 ]; then
            printf 'secrets: failed to install %s, rolled back, nothing changed\n' \
                "$failed_at" >&2
        else
            printf 'secrets: failed to install %s and could not roll back; the\n' \
                "$failed_at" >&2
            printf 'secrets: originals are kept in %s/.orig -- restore them by\n' \
                "$stage" >&2
            printf 'secrets: hand, then delete that directory: it holds blobs on the\n' >&2
            printf 'secrets: old recipients, which is what this rekey was retiring\n' >&2
            stage=''                 # keep it: it holds the only copy
        fi
        exit 1
    fi
    printf 'secrets: rekeyed %d secret(s)\n' "$n" >&2
)

# Convert a pre-0.2 flat store into the passage/pago layout. Re-runnable: it
# keys off the leftover artifacts, so a run that failed part way (a bad mv, a
# read-only base directory) can simply be run again to finish the job.
_secrets_migrate() (
    if [ ! -d "$SECRETS_DIR" ]; then
        printf 'secrets: no store at %s\n' "$SECRETS_DIR" >&2
        exit 1
    fi
    if ! _secrets_has_legacy; then
        printf 'secrets: nothing to migrate in %s\n' "$SECRETS_DIR" >&2
        exit 1
    fi

    list="$SECRETS_DIR/.migrate.list"
    trap 'rm -f "$list"' EXIT
    trap 'exit 1' HUP INT TERM

    ( umask 077 && mkdir -p "$SECRETS_STORE" ) || exit 1
    chmod 700 "$SECRETS_STORE" || exit 1

    n=0
    find "$SECRETS_DIR" -maxdepth 1 -type f -name '*.age' 2>/dev/null > "$list" || exit 1
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        # A pre-0.2 blob must never overwrite a live entry of the same name:
        # a stale one restored from a backup would silently replace it.
        if [ -e "$SECRETS_STORE/${f##*/}" ]; then
            printf 'secrets: %s already exists in the store\n' \
                "$SECRETS_STORE/${f##*/}" >&2
            printf 'secrets: move or delete %s by hand, then run: secrets migrate\n' \
                "$f" >&2
            exit 1
        fi
        mv -- "$f" "$SECRETS_STORE/${f##*/}" || exit 1
        n=$((n + 1))
    done < "$list"

    rf=${SECRETS_RECIPIENTS:-$SECRETS_STORE/.age-recipients}
    if [ -e "$SECRETS_DIR/identity.txt" ] && [ -e "$SECRETS_IDENTITY" ]; then
        printf 'secrets: both %s and %s exist\n' \
            "$SECRETS_DIR/identity.txt" "$SECRETS_IDENTITY" >&2
        printf 'secrets: move or delete the old identity.txt by hand, then run: secrets migrate\n' >&2
        exit 1
    fi
    if [ -e "$SECRETS_DIR/identity.txt" ]; then
        mv -- "$SECRETS_DIR/identity.txt" "$SECRETS_IDENTITY" || exit 1
    fi
    if [ -e "$SECRETS_DIR/recipients.txt" ] && [ -e "$rf" ]; then
        printf 'secrets: both %s and %s exist\n' \
            "$SECRETS_DIR/recipients.txt" "$rf" >&2
        printf 'secrets: move or delete the old recipients.txt by hand, then run: secrets migrate\n' >&2
        exit 1
    fi
    if [ -e "$SECRETS_DIR/recipients.txt" ]; then
        mv -- "$SECRETS_DIR/recipients.txt" "$rf" || exit 1
    fi

    # A directory called NAME.age is not an entry; say so rather than leaving
    # it behind silently for the guard to keep tripping over.
    find "$SECRETS_DIR" -maxdepth 1 -mindepth 1 -type d -name '*.age' 2>/dev/null |
        while IFS= read -r f; do
            [ -n "$f" ] || continue
            printf 'secrets: left %s alone: it is a directory, not an entry\n' \
                "$f" >&2
        done

    # Exiting 0 has to mean the guard will not refuse the store on the next
    # command; anything still here would otherwise lock it out silently.
    if _secrets_has_legacy; then
        printf 'secrets: migration incomplete, %s still holds pre-0.2 files\n' \
            "$SECRETS_DIR" >&2
        exit 1
    fi

    printf 'secrets: moved %d secret(s) into %s\n' "$n" "$SECRETS_STORE" >&2
    printf 'secrets: identity   %s\n' "$SECRETS_IDENTITY" >&2
    printf 'secrets: recipients %s\n' "$rf" >&2
)

_secrets_completions() (
    case "${1-}" in
    bash) cat <<'EOF'
_secrets_complete() {
    local cur="${COMP_WORDS[COMP_CWORD]}" pfx='' typed line i
    COMPREPLY=()
    if [ "$COMP_CWORD" -eq 1 ]; then
        COMPREPLY=($(compgen -W "init enc dec ls rm rename recipients rekey migrate completions help" -- "$cur"))
        return
    fi
    case "${COMP_WORDS[1]}" in
        dec|rm|recipients|enc|rename) ;;
        completions) COMPREPLY=($(compgen -W "bash zsh fish" -- "$cur")); return ;;
        *) return ;;
    esac

    # A stored name may hold ':', which bash counts as a word break: the word
    # the user typed is then spread across several COMP_WORDS and only the
    # last one gets replaced. Rejoin the earlier pieces to match against, and
    # trim them back off each candidate so the line does not gain a second
    # copy of what is already on it.
    for (( i = 2; i < COMP_CWORD; i++ )); do
        [[ ${COMP_WORDS[i]} == -f ]] && continue
        pfx+="${COMP_WORDS[i]}"
    done
    # An escaped space reaches us as a backslash the stored name lacks.
    typed="$pfx${cur//\\/}"

    [[ ${COMP_WORDS[1]} == @(enc|rename|rm) && -z $typed ]] && COMPREPLY+=(-f)
    # One name per line: names may contain spaces and shell metacharacters,
    # so `compgen -W` would word-split and expand them. Quote what goes back,
    # or bash inserts `with space` as two arguments.
    while IFS= read -r line; do
        [[ $line == "$typed"* ]] || continue
        COMPREPLY+=("$(printf '%q' "${line#"$pfx"}")")
    done < <(secrets ls 2>/dev/null)
}
complete -F _secrets_complete secrets
EOF
        ;;
    zsh) cat <<'EOF'
_secrets() {
    local -a subcmds
    subcmds=(init enc dec ls rm rename recipients rekey migrate completions help)
    if (( CURRENT == 2 )); then
        _describe 'subcommand' subcmds
        return
    fi
    case "$words[2]" in
        dec|recipients)     compadd -- ${(f)"$(secrets ls 2>/dev/null)"} ;;
        enc|rename|rm)      compadd -- -f ${(f)"$(secrets ls 2>/dev/null)"} ;;
        completions)        compadd bash zsh fish ;;
    esac
}
compdef _secrets secrets
EOF
        ;;
    fish) cat <<'EOF'
complete -c secrets -f
complete -c secrets -n '__fish_use_subcommand' -a 'init enc dec ls rm rename recipients rekey migrate completions help'
complete -c secrets -n '__fish_seen_subcommand_from dec rm enc rename recipients' -a '(secrets ls 2>/dev/null)'
complete -c secrets -n '__fish_seen_subcommand_from enc rename' -s f -d 'overwrite existing secret'
complete -c secrets -n '__fish_seen_subcommand_from rm' -s f -d 'delete without confirming'
complete -c secrets -n '__fish_seen_subcommand_from completions' -a 'bash zsh fish'
EOF
        ;;
    *)
        printf 'usage: secrets completions {bash|zsh|fish}\n' >&2
        exit 2
        ;;
    esac
)

_secrets_help() (
    cat <<'EOF'
usage: secrets <subcommand> [args]

  init                 create the store and generate an identity
  enc  [-f] NAME       encrypt stdin -> NAME.age  (-f overwrites)
  dec  NAME            decrypt to stdout, verbatim
  ls                   list stored names
  rm   [-f] NAME       delete a secret (-f skips the prompt)
  rename [-f] OLD NEW  rename a secret (-f overwrites)
  recipients [NAME]    show who can decrypt
  rekey                re-encrypt everything to current recipients
  migrate              convert a pre-0.2 flat store to the current layout
  completions SHELL    emit completions (bash | zsh | fish)

exit: 0 ok  1 failed  2 usage/invalid name  3 no identity or recipients
      4 store needs `secrets migrate`

NAME may contain '/': `work/aws` is $SECRETS_STORE/work/aws.age.

The store is laid out exactly as passage's and pago's, so SECRETS_DIR can
point at either of theirs:
  $SECRETS_DIR/identities            private key(s)
  $SECRETS_DIR/store/.age-recipients public keys
  $SECRETS_DIR/store/NAME.age        entries

env: SECRETS_AGE SECRETS_DIR SECRETS_STORE SECRETS_IDENTITY SECRETS_RECIPIENTS
     SECRETS_ARMOR
EOF
)

# --- dispatcher --------------------------------------------------------------

# A subshell body, like the helpers': it resolves the store paths for this one
# call and cannot leak them back into a shell that sourced the library.
secrets() (
    if [ -z "${SECRETS_DIR:-}" ] && [ -n "${HOME:-}" ]; then
        SECRETS_DIR="$HOME/.secrets"
    fi
    if [ -z "${SECRETS_DIR:-}" ]; then
        printf 'secrets: neither SECRETS_DIR nor HOME is set; export SECRETS_DIR to pick a store\n' >&2
        exit 2
    fi
    : "${SECRETS_STORE:=$SECRETS_DIR/store}"
    : "${SECRETS_IDENTITY:=$SECRETS_DIR/identities}"
    : "${SECRETS_RECIPIENTS:=}"
    : "${SECRETS_ARMOR:=0}"

    case "${1-help}" in
        help|-h|--help) _secrets_help; exit $? ;;
        completions)    shift; _secrets_completions "$@"; exit $? ;;
        migrate)        shift; _secrets_migrate "$@"; exit $? ;;
    esac
    _secrets_legacy_guard || exit $?
    case "$1" in
        init)        shift; _secrets_init "$@" ;;
        enc)         shift; _secrets_enc "$@" ;;
        dec)         shift; _secrets_dec "$@" ;;
        ls)          shift; _secrets_ls "$@" ;;
        rm)          shift; _secrets_rm "$@" ;;
        rename)      shift; _secrets_rename "$@" ;;
        recipients)  shift; _secrets_recipients "$@" ;;
        rekey)       shift; _secrets_rekey "$@" ;;
        *)
            printf 'secrets: unknown subcommand: %s (try: secrets help)\n' "$1" >&2
            exit 2
            ;;
    esac
)
