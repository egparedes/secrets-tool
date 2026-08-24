# shellcheck shell=sh
# ── secrets ──────────────────────────────────────────────────────────────────
# Tiny secret store built on age(1) or its Rust implementation rage(1).
# The two produce interchangeable files; the backend is detected automatically
# and can be pinned with SECRETS_AGE. POSIX sh: sourceable from dash, ash,
# busybox sh, bash, zsh, and anything else claiming sh compatibility.
#
#   secrets init                 create the store, generate an identity
#   secrets enc  [-f] NAME       encrypt stdin -> $SECRETS_DIR/NAME.age
#   secrets dec  NAME            decrypt -> stdout, plaintext verbatim
#   secrets ls                   list stored names
#   secrets rm   NAME            delete a secret
#   secrets rename [-f] OLD NEW  rename a secret
#   secrets recipients           show who can decrypt
#   secrets rekey                re-encrypt everything to current recipients
#   secrets completions SHELL    emit completion script (bash | zsh | fish)
#   secrets help                 this listing
#
# Config (all overridable):
#   SECRETS_AGE         age binary: 'age', 'rage', or a path   (auto-detected)
#   SECRETS_DIR         store location             (default ~/.secrets)
#   SECRETS_IDENTITY    private key, for decrypt   (default $SECRETS_DIR/identity.txt)
#   SECRETS_RECIPIENTS  public keys, for encrypt   (default $SECRETS_DIR/recipients.txt)
#   SECRETS_ARMOR       1 = ASCII-armored output   (default 0, binary)
#
# The keygen tool is derived from the backend name: age -> age-keygen,
# rage -> rage-keygen, /opt/age -> /opt/age-keygen.
#
# Encryption is asymmetric: it needs only the public recipients file, so a
# machine or CI job can write secrets it cannot read. To use existing SSH
# keys instead of a dedicated age identity:
#   export SECRETS_IDENTITY=~/.ssh/id_ed25519
#   cp ~/.ssh/id_ed25519.pub "$SECRETS_DIR/recipients.txt"
#
# Adding a second machine: run `secrets init` there, append its printed public
# key to $SECRETS_RECIPIENTS here, run `secrets rekey`, then sync $SECRETS_DIR
# (ciphertext only; safe for git/rsync).
#
# Completions:  eval "$(secrets completions bash)"     # bash, in .bashrc
#               eval "$(secrets completions zsh)"      # zsh, after compinit
#               secrets completions fish > ~/.config/fish/completions/secrets.fish
#
# Portability notes: strictly POSIX except mktemp(1), which is not in POSIX
# but is universal (coreutils, busybox, BSD, macOS) and has no safe
# POSIX-only substitute. Helper functions use subshell bodies `f() (...)` --
# valid POSIX -- so no variables leak into the sourcing shell.
#
# Tested with age v1.3.1 and rage v0.11.1 under dash, bash, and zsh.
# ─────────────────────────────────────────────────────────────────────────────

: "${SECRETS_DIR:=$HOME/.secrets}"
: "${SECRETS_IDENTITY:=$SECRETS_DIR/identity.txt}"
: "${SECRETS_RECIPIENTS:=$SECRETS_DIR/recipients.txt}"
: "${SECRETS_ARMOR:=0}"

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

# Reject names that could escape $SECRETS_DIR or create hidden files.
_secrets_name() (
    case "${1-}" in
        '' | */* | .* | *[!A-Za-z0-9._-]*)
            printf 'secrets: invalid name: %s\n' "${1:-<empty>}" >&2
            exit 2
            ;;
    esac
)

_secrets_need_recipients() (
    if [ ! -s "$SECRETS_RECIPIENTS" ]; then
        printf 'secrets: no recipients at %s (run: secrets init)\n' \
            "$SECRETS_RECIPIENTS" >&2
        exit 3
    fi
)

_secrets_need_identity() (
    if [ ! -r "$SECRETS_IDENTITY" ]; then
        printf 'secrets: identity not readable: %s (run: secrets init)\n' \
            "$SECRETS_IDENTITY" >&2
        exit 3
    fi
)

# Encrypt stdin to file $1 using the recipients file.
_secrets_encrypt_to() (
    agebin=$(_secrets_age) || exit $?
    if [ "${SECRETS_ARMOR:-0}" = 1 ]; then
        "$agebin" -a -R "$SECRETS_RECIPIENTS" -o "$1"
    else
        "$agebin" -R "$SECRETS_RECIPIENTS" -o "$1"
    fi
)

# --- subcommands -------------------------------------------------------------

_secrets_init() (
    keygen=$(_secrets_keygen) || exit $?

    ( umask 077 && mkdir -p "$SECRETS_DIR" ) || exit 1
    chmod 700 "$SECRETS_DIR" || exit 1

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
    ( umask 077
      printf '# %s (added %s)\n%s\n' \
          "$(uname -n 2>/dev/null || echo host)" \
          "$(date -u +%Y-%m-%d)" "$pub" >> "$SECRETS_RECIPIENTS" ) || exit 1

    printf 'secrets: backend    %s\n' "$(_secrets_age)" >&2
    printf 'secrets: identity   %s\n' "$SECRETS_IDENTITY" >&2
    printf 'secrets: public key %s\n' "$pub" >&2
    printf 'secrets: back up the identity -- without it every .age file is unrecoverable\n' >&2
)

_secrets_enc() (
    force=0
    if [ "${1-}" = "-f" ]; then force=1; shift; fi

    _secrets_name "${1-}" || exit $?
    _secrets_need_recipients || exit $?

    out="$SECRETS_DIR/$1.age"
    if [ -e "$out" ] && [ "$force" -eq 0 ]; then
        printf 'secrets: %s already exists (use -f to overwrite)\n' "$out" >&2
        exit 1
    fi
    [ -t 0 ] && printf 'secrets: reading plaintext from stdin, end with Ctrl-D\n' >&2

    tmp=$(mktemp "$SECRETS_DIR/.$1.XXXXXX") || exit 1
    if _secrets_encrypt_to "$tmp"; then
        chmod 600 "$tmp" && mv -f "$tmp" "$out"
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

    in="$SECRETS_DIR/$1.age"
    if [ ! -r "$in" ]; then
        printf 'secrets: no such secret: %s\n' "$1" >&2
        exit 1
    fi
    exec "$agebin" -d -i "$SECRETS_IDENTITY" "$in"
)

_secrets_ls() (
    [ -d "$SECRETS_DIR" ] || exit 0
    for f in "$SECRETS_DIR"/*.age; do
        [ -e "$f" ] || continue            # no matches -> literal glob
        name=${f##*/}
        printf '%s\n' "${name%.age}"
    done
)

_secrets_rm() (
    _secrets_name "${1-}" || exit $?
    f="$SECRETS_DIR/$1.age"
    if [ ! -e "$f" ]; then
        printf 'secrets: no such secret: %s\n' "$1" >&2
        exit 1
    fi
    rm -i -- "$f"
)

_secrets_rename() (
    force=0
    if [ "${1-}" = "-f" ]; then force=1; shift; fi

    _secrets_name "${1-}" || exit $?
    _secrets_name "${2-}" || exit $?

    src="$SECRETS_DIR/$1.age"
    dst="$SECRETS_DIR/$2.age"
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
    mv -f -- "$src" "$dst"
)

_secrets_recipients() (
    if [ ! -s "$SECRETS_RECIPIENTS" ]; then
        printf 'secrets: no recipients at %s\n' "$SECRETS_RECIPIENTS" >&2
        exit 1
    fi
    cat "$SECRETS_RECIPIENTS"
)

# Re-encrypt every secret to the current recipients. All-or-nothing: stages
# into a temp dir and only swaps in once every blob re-encrypted cleanly.
# Plaintext stays in a pipe; it never touches disk.
_secrets_rekey() (
    agebin=$(_secrets_age) || exit $?
    _secrets_need_identity || exit $?
    _secrets_need_recipients || exit $?

    stage=$(mktemp -d "$SECRETS_DIR/.rekey.XXXXXX") || exit 1
    trap 'rm -rf "$stage"' INT TERM

    n=0
    for f in "$SECRETS_DIR"/*.age; do
        [ -e "$f" ] || continue
        name=${f##*/}
        # POSIX has no pipefail; funnel age's status through the FIFO-free
        # trick of checking the producer via a status file.
        st="$stage/.st"
        { "$agebin" -d -i "$SECRETS_IDENTITY" "$f" || echo fail > "$st"; } \
            | _secrets_encrypt_to "$stage/$name"
        if [ -f "$st" ] || [ ! -s "$stage/$name" ]; then
            rm -rf "$stage"
            printf 'secrets: rekey failed on %s, nothing changed\n' "$name" >&2
            exit 1
        fi
        n=$((n + 1))
    done

    if [ "$n" -eq 0 ]; then
        rm -rf "$stage"
        printf 'secrets: no secrets to rekey\n' >&2
        exit 0
    fi

    for f in "$stage"/*.age; do
        name=${f##*/}
        if ! chmod 600 "$f" || ! mv -f "$f" "$SECRETS_DIR/$name"; then
            printf 'secrets: failed to install %s\n' "$name" >&2
            exit 1
        fi
    done
    rm -rf "$stage"
    printf 'secrets: rekeyed %d secret(s)\n' "$n" >&2
)

_secrets_completions() (
    case "${1-}" in
    bash) cat <<'EOF'
_secrets_complete() {
    local cur="${COMP_WORDS[COMP_CWORD]}"
    if [ "$COMP_CWORD" -eq 1 ]; then
        COMPREPLY=($(compgen -W "init enc dec ls rm rename recipients rekey completions help" -- "$cur"))
        return
    fi
    case "${COMP_WORDS[1]}" in
        dec|rm)   COMPREPLY=($(compgen -W "$(secrets ls 2>/dev/null)" -- "$cur")) ;;
        enc|rename)   COMPREPLY=($(compgen -W "-f $(secrets ls 2>/dev/null)" -- "$cur")) ;;
        completions)  COMPREPLY=($(compgen -W "bash zsh fish" -- "$cur")) ;;
    esac
}
complete -F _secrets_complete secrets
EOF
        ;;
    zsh) cat <<'EOF'
_secrets() {
    local -a subcmds
    subcmds=(init enc dec ls rm rename recipients rekey completions help)
    if (( CURRENT == 2 )); then
        _describe 'subcommand' subcmds
        return
    fi
    case "$words[2]" in
        dec|rm)   compadd -- ${(f)"$(secrets ls 2>/dev/null)"} ;;
        enc|rename)   compadd -- -f ${(f)"$(secrets ls 2>/dev/null)"} ;;
        completions)  compadd bash zsh fish ;;
    esac
}
compdef _secrets secrets
EOF
        ;;
    fish) cat <<'EOF'
complete -c secrets -f
complete -c secrets -n '__fish_use_subcommand' -a 'init enc dec ls rm rename recipients rekey completions help'
complete -c secrets -n '__fish_seen_subcommand_from dec rm enc rename' -a '(secrets ls 2>/dev/null)'
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
  recipients           show who can decrypt
  rekey                re-encrypt everything to current recipients
  completions SHELL    emit completions (bash | zsh | fish)

env: SECRETS_AGE SECRETS_DIR SECRETS_IDENTITY SECRETS_RECIPIENTS SECRETS_ARMOR
EOF
)

# --- dispatcher --------------------------------------------------------------

secrets() {
    case "${1-help}" in
        init)        shift; _secrets_init "$@" ;;
        enc)         shift; _secrets_enc "$@" ;;
        dec)         shift; _secrets_dec "$@" ;;
        ls)          shift; _secrets_ls "$@" ;;
        rm)          shift; _secrets_rm "$@" ;;
        rename)      shift; _secrets_rename "$@" ;;
        recipients)  shift; _secrets_recipients "$@" ;;
        rekey)       shift; _secrets_rekey "$@" ;;
        completions) shift; _secrets_completions "$@" ;;
        help|-h|--help) _secrets_help ;;
        *)
            printf 'secrets: unknown subcommand: %s (try: secrets help)\n' "$1" >&2
            return 2
            ;;
    esac
}
