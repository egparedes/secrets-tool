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
#   secrets rm   NAME            delete a secret
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
#   SECRETS_LIB         library path, CLI only     (see search order in README)
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
# Tested with age v1.3.1 and rage v0.11.1 under dash, bash, and zsh.
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
_secrets_encrypt_to() (
    out=$1
    sub=${2-}
    idf=${3-}

    agebin=$(_secrets_age) || exit $?
    rf=$(_secrets_recipients_for "$sub")
    if [ -n "$rf" ]; then
        set -- -R "$rf"
    else
        if [ -z "$idf" ]; then
            trap '[ -z "$idf" ] || [ "$idf" = "$SECRETS_IDENTITY" ] || rm -f "$idf"' \
                EXIT HUP INT TERM
            idf=$(_secrets_identity_open) || exit $?
        fi
        set -- -i "$idf"
    fi
    if [ "${SECRETS_ARMOR:-0}" = 1 ]; then
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

# A store written before 0.2 keeps blobs, identity.txt and recipients.txt
# directly in $SECRETS_DIR. Refuse to run against one rather than silently
# starting a second, empty store beside it.
_secrets_legacy_guard() (
    [ -d "$SECRETS_STORE" ] && exit 0
    legacy=''
    [ -e "$SECRETS_DIR/identity.txt" ] && legacy=1
    [ -e "$SECRETS_DIR/recipients.txt" ] && legacy=1
    for f in "$SECRETS_DIR"/*.age; do
        [ -e "$f" ] && legacy=1
        break
    done
    [ -n "$legacy" ] || exit 0
    printf 'secrets: %s holds a pre-0.2 flat store (run: secrets migrate)\n' \
        "$SECRETS_DIR" >&2
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
          "$(date -u +%Y-%m-%d)" "$pub" >> "$rf" ) || exit 1

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
    tmp=$(mktemp "${out%/*}/.tmp.XXXXXX") || exit 1
    if _secrets_encrypt_to "$tmp" "$sub"; then
        chmod 600 "$tmp" && mv -f -- "$tmp" "$out"
    else
        rm -f "$tmp"
        printf 'secrets: encryption failed, %s left untouched\n' "$out" >&2
        exit 1
    fi
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
    trap '[ -z "$idf" ] || [ "$idf" = "$SECRETS_IDENTITY" ] || rm -f "$idf"' \
        EXIT HUP INT TERM
    idf=$(_secrets_identity_open) || exit $?
    "$agebin" -d -i "$idf" "$in"
)

# Recurse: passage and pago names are hierarchical. Dot-directories are
# pruned, which keeps .git, a staging directory and .age-recipients out.
_secrets_ls() (
    [ -d "$SECRETS_STORE" ] || exit 0
    CDPATH='' cd -- "$SECRETS_STORE" || exit 1
    find -L . -name '.?*' -prune -o -type f -name '*.age' -print 2>/dev/null |
        sed -e 's|^\./||' -e 's|\.age$||' |
        LC_ALL=C sort
)

_secrets_rm() (
    _secrets_name "${1-}" || exit $?
    f="$SECRETS_STORE/$1.age"
    if [ ! -e "$f" ]; then
        printf 'secrets: no such secret: %s\n' "$1" >&2
        exit 1
    fi
    rm -i -- "$f" || exit $?
    [ -e "$f" ] || _secrets_prune "$f"
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
    trap '_secrets_scrub "$tmp" "$st"; [ -z "$idf" ] || [ "$idf" = "$SECRETS_IDENTITY" ] || rm -f "$idf"' \
        EXIT HUP INT TERM
    idf=$(_secrets_identity_open) || exit $?

    tmp=$(mktemp "${dst%/*}/.tmp.XXXXXX") || exit 1
    st=$(mktemp "${dst%/*}/.st.XXXXXX") || exit 1
    # POSIX has no pipefail, and encrypting a failed decrypt's empty output
    # still yields a valid, non-empty age file -- which would look like a
    # clean re-encryption and cost the source. Funnel the producer's status
    # through a file instead.
    { "$agebin" -d -i "$idf" "$src" || echo fail > "$st"; } \
        | _secrets_encrypt_to "$tmp" "$sub" "$idf"
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
    if [ -n "${1-}" ]; then
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
        trap '[ -z "$idf" ] || [ "$idf" = "$SECRETS_IDENTITY" ] || rm -f "$idf"' \
            EXIT HUP INT TERM
        idf=$(_secrets_identity_open) || exit $?
        printf '# derived from %s (no .age-recipients in the store)\n' \
            "$SECRETS_IDENTITY"
        "$keygen" -y "$idf"
        exit $?
    fi
    printf 'secrets: no recipients under %s\n' "$SECRETS_STORE" >&2
    exit 1
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
          [ -z "$idf" ] || [ "$idf" = "$SECRETS_IDENTITY" ] || rm -f "$idf"' \
        EXIT HUP INT TERM
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
            | _secrets_encrypt_to "$stage/$name.age" "$sub" "$idf"
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

    while IFS= read -r name; do
        [ -n "$name" ] || continue
        if ! chmod 600 "$stage/$name.age" ||
           ! mv -f -- "$stage/$name.age" "$SECRETS_STORE/$name.age"; then
            printf 'secrets: failed to install %s\n' "$name" >&2
            exit 1
        fi
    done < "$list"
    printf 'secrets: rekeyed %d secret(s)\n' "$n" >&2
)

# One-shot conversion of a pre-0.2 flat store into the passage/pago layout.
_secrets_migrate() (
    if [ -d "$SECRETS_STORE" ]; then
        printf 'secrets: %s already exists, nothing to migrate\n' "$SECRETS_STORE" >&2
        exit 1
    fi
    if [ ! -d "$SECRETS_DIR" ]; then
        printf 'secrets: no store at %s\n' "$SECRETS_DIR" >&2
        exit 1
    fi

    ( umask 077 && mkdir -p "$SECRETS_STORE" ) || exit 1
    chmod 700 "$SECRETS_STORE" || exit 1

    n=0
    for f in "$SECRETS_DIR"/*.age; do
        [ -e "$f" ] || continue
        mv -- "$f" "$SECRETS_STORE/${f##*/}" || exit 1
        n=$((n + 1))
    done

    if [ -e "$SECRETS_DIR/identity.txt" ] && [ ! -e "$SECRETS_IDENTITY" ]; then
        mv -- "$SECRETS_DIR/identity.txt" "$SECRETS_IDENTITY" || exit 1
    fi
    rf=${SECRETS_RECIPIENTS:-$SECRETS_STORE/.age-recipients}
    if [ -e "$SECRETS_DIR/recipients.txt" ] && [ ! -e "$rf" ]; then
        mv -- "$SECRETS_DIR/recipients.txt" "$rf" || exit 1
    fi

    printf 'secrets: moved %d secret(s) into %s\n' "$n" "$SECRETS_STORE" >&2
    printf 'secrets: identity   %s\n' "$SECRETS_IDENTITY" >&2
    printf 'secrets: recipients %s\n' "$rf" >&2
)

_secrets_completions() (
    case "${1-}" in
    bash) cat <<'EOF'
_secrets_complete() {
    local cur="${COMP_WORDS[COMP_CWORD]}" line
    COMPREPLY=()
    if [ "$COMP_CWORD" -eq 1 ]; then
        COMPREPLY=($(compgen -W "init enc dec ls rm rename recipients rekey migrate completions help" -- "$cur"))
        return
    fi
    case "${COMP_WORDS[1]}" in
        dec|rm|recipients|enc|rename)
            [[ ${COMP_WORDS[1]} == @(enc|rename) && -z $cur ]] && COMPREPLY+=(-f)
            # Read names one per line: a stored name may contain spaces or
            # shell metacharacters, and `compgen -W` would expand them.
            while IFS= read -r line; do
                [[ $line == "$cur"* ]] && COMPREPLY+=("$line")
            done < <(secrets ls 2>/dev/null)
            ;;
        completions)  COMPREPLY=($(compgen -W "bash zsh fish" -- "$cur")) ;;
    esac
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
        dec|rm|recipients)  compadd -- ${(f)"$(secrets ls 2>/dev/null)"} ;;
        enc|rename)         compadd -- -f ${(f)"$(secrets ls 2>/dev/null)"} ;;
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
  rm   NAME            delete a secret
  rename [-f] OLD NEW  rename a secret (-f overwrites)
  recipients [NAME]    show who can decrypt
  rekey                re-encrypt everything to current recipients
  migrate              convert a pre-0.2 flat store to the current layout
  completions SHELL    emit completions (bash | zsh | fish)

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
