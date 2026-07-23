# shellcheck shell=sh
# ── secret ───────────────────────────────────────────────────────────────────
# Tiny secret store built on age(1) or its Rust implementation rage(1).
# The two produce interchangeable files; the backend is detected automatically
# and can be pinned with SECRETS_AGE. POSIX sh: sourceable from dash, ash,
# busybox sh, bash, zsh, and anything else claiming sh compatibility.
#
#   secret init                 create the store, generate an identity
#   secret enc  [-f] NAME       encrypt stdin -> $SECRETS_DIR/NAME.age
#   secret dec  NAME            decrypt -> stdout, plaintext verbatim
#   secret ls                   list stored names
#   secret rm   NAME            delete a secret
#   secret recipients           show who can decrypt
#   secret rekey                re-encrypt everything to current recipients
#   secret completions SHELL    emit completion script (bash | zsh | fish)
#   secret help                 this listing
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
# Adding a second machine: run `secret init` there, append its printed public
# key to $SECRETS_RECIPIENTS here, run `secret rekey`, then sync $SECRETS_DIR
# (ciphertext only; safe for git/rsync).
#
# Completions:  eval "$(secret completions bash)"     # bash, in .bashrc
#               eval "$(secret completions zsh)"      # zsh, after compinit
#               secret completions fish > ~/.config/fish/completions/secret.fish
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
_secret_age() (
    if [ -n "${SECRETS_AGE-}" ]; then
        if command -v "$SECRETS_AGE" >/dev/null 2>&1; then
            printf '%s\n' "$SECRETS_AGE"; exit 0
        fi
        printf 'secret: SECRETS_AGE=%s not found in PATH\n' "$SECRETS_AGE" >&2
        exit 127
    fi
    for bin in age rage; do
        if command -v "$bin" >/dev/null 2>&1; then
            printf '%s\n' "$bin"; exit 0
        fi
    done
    printf 'secret: neither age nor rage found in PATH (https://age-encryption.org)\n' >&2
    exit 127
)

# Print the matching keygen tool (age-keygen / rage-keygen), or fail.
_secret_keygen() (
    agebin=$(_secret_age) || exit $?
    keygen="${agebin}-keygen"
    if command -v "$keygen" >/dev/null 2>&1; then
        printf '%s\n' "$keygen"; exit 0
    fi
    printf 'secret: %s not found in PATH\n' "$keygen" >&2
    exit 127
)

# Reject names that could escape $SECRETS_DIR or create hidden files.
_secret_name() (
    case "${1-}" in
        '' | */* | .* | *[!A-Za-z0-9._-]*)
            printf 'secret: invalid name: %s\n' "${1:-<empty>}" >&2
            exit 2
            ;;
    esac
)

_secret_need_recipients() (
    if [ ! -s "$SECRETS_RECIPIENTS" ]; then
        printf 'secret: no recipients at %s (run: secret init)\n' \
            "$SECRETS_RECIPIENTS" >&2
        exit 3
    fi
)

_secret_need_identity() (
    if [ ! -r "$SECRETS_IDENTITY" ]; then
        printf 'secret: identity not readable: %s (run: secret init)\n' \
            "$SECRETS_IDENTITY" >&2
        exit 3
    fi
)

# Encrypt stdin to file $1 using the recipients file.
_secret_encrypt_to() (
    agebin=$(_secret_age) || exit $?
    if [ "${SECRETS_ARMOR:-0}" = 1 ]; then
        "$agebin" -a -R "$SECRETS_RECIPIENTS" -o "$1"
    else
        "$agebin" -R "$SECRETS_RECIPIENTS" -o "$1"
    fi
)

# --- subcommands -------------------------------------------------------------

_secret_init() (
    keygen=$(_secret_keygen) || exit $?

    ( umask 077 && mkdir -p "$SECRETS_DIR" ) || exit 1
    chmod 700 "$SECRETS_DIR" || exit 1

    if [ -e "$SECRETS_IDENTITY" ]; then
        printf 'secret: identity already exists: %s (refusing to overwrite)\n' \
            "$SECRETS_IDENTITY" >&2
        exit 1
    fi

    # Both age-keygen and rage-keygen create the file with mode 600.
    "$keygen" -o "$SECRETS_IDENTITY" >/dev/null 2>&1 || {
        printf 'secret: %s failed\n' "$keygen" >&2
        exit 1
    }

    pub=$("$keygen" -y "$SECRETS_IDENTITY") || exit 1
    ( umask 077
      printf '# %s (added %s)\n%s\n' \
          "$(uname -n 2>/dev/null || echo host)" \
          "$(date -u +%Y-%m-%d)" "$pub" >> "$SECRETS_RECIPIENTS" ) || exit 1

    printf 'secret: backend    %s\n' "$(_secret_age)" >&2
    printf 'secret: identity   %s\n' "$SECRETS_IDENTITY" >&2
    printf 'secret: public key %s\n' "$pub" >&2
    printf 'secret: back up the identity -- without it every .age file is unrecoverable\n' >&2
)

_secret_enc() (
    force=0
    if [ "${1-}" = "-f" ]; then force=1; shift; fi

    _secret_name "${1-}" || exit $?
    _secret_need_recipients || exit $?

    out="$SECRETS_DIR/$1.age"
    if [ -e "$out" ] && [ "$force" -eq 0 ]; then
        printf 'secret: %s already exists (use -f to overwrite)\n' "$out" >&2
        exit 1
    fi
    [ -t 0 ] && printf 'secret: reading plaintext from stdin, end with Ctrl-D\n' >&2

    tmp=$(mktemp "$SECRETS_DIR/.$1.XXXXXX") || exit 1
    if _secret_encrypt_to "$tmp"; then
        chmod 600 "$tmp" && mv -f "$tmp" "$out"
    else
        rm -f "$tmp"
        printf 'secret: encryption failed, %s left untouched\n' "$out" >&2
        exit 1
    fi
)

_secret_dec() (
    agebin=$(_secret_age) || exit $?
    _secret_name "${1-}" || exit $?
    _secret_need_identity || exit $?

    in="$SECRETS_DIR/$1.age"
    if [ ! -r "$in" ]; then
        printf 'secret: no such secret: %s\n' "$1" >&2
        exit 1
    fi
    exec "$agebin" -d -i "$SECRETS_IDENTITY" "$in"
)

_secret_ls() (
    [ -d "$SECRETS_DIR" ] || exit 0
    for f in "$SECRETS_DIR"/*.age; do
        [ -e "$f" ] || continue            # no matches -> literal glob
        name=${f##*/}
        printf '%s\n' "${name%.age}"
    done
)

_secret_rm() (
    _secret_name "${1-}" || exit $?
    f="$SECRETS_DIR/$1.age"
    if [ ! -e "$f" ]; then
        printf 'secret: no such secret: %s\n' "$1" >&2
        exit 1
    fi
    rm -i -- "$f"
)

_secret_recipients() (
    if [ ! -s "$SECRETS_RECIPIENTS" ]; then
        printf 'secret: no recipients at %s\n' "$SECRETS_RECIPIENTS" >&2
        exit 1
    fi
    cat "$SECRETS_RECIPIENTS"
)

# Re-encrypt every secret to the current recipients. All-or-nothing: stages
# into a temp dir and only swaps in once every blob re-encrypted cleanly.
# Plaintext stays in a pipe; it never touches disk.
_secret_rekey() (
    agebin=$(_secret_age) || exit $?
    _secret_need_identity || exit $?
    _secret_need_recipients || exit $?

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
            | _secret_encrypt_to "$stage/$name"
        if [ -f "$st" ] || [ ! -s "$stage/$name" ]; then
            rm -rf "$stage"
            printf 'secret: rekey failed on %s, nothing changed\n' "$name" >&2
            exit 1
        fi
        n=$((n + 1))
    done

    if [ "$n" -eq 0 ]; then
        rm -rf "$stage"
        printf 'secret: no secrets to rekey\n' >&2
        exit 0
    fi

    for f in "$stage"/*.age; do
        name=${f##*/}
        if ! chmod 600 "$f" || ! mv -f "$f" "$SECRETS_DIR/$name"; then
            printf 'secret: failed to install %s\n' "$name" >&2
            exit 1
        fi
    done
    rm -rf "$stage"
    printf 'secret: rekeyed %d secret(s)\n' "$n" >&2
)

_secret_completions() (
    case "${1-}" in
    bash) cat <<'EOF'
_secret_complete() {
    local cur="${COMP_WORDS[COMP_CWORD]}"
    if [ "$COMP_CWORD" -eq 1 ]; then
        COMPREPLY=($(compgen -W "init enc dec ls rm recipients rekey completions help" -- "$cur"))
        return
    fi
    case "${COMP_WORDS[1]}" in
        dec|rm)   COMPREPLY=($(compgen -W "$(secret ls 2>/dev/null)" -- "$cur")) ;;
        enc)          COMPREPLY=($(compgen -W "-f $(secret ls 2>/dev/null)" -- "$cur")) ;;
        completions)  COMPREPLY=($(compgen -W "bash zsh fish" -- "$cur")) ;;
    esac
}
complete -F _secret_complete secret
EOF
        ;;
    zsh) cat <<'EOF'
_secret() {
    local -a subcmds
    subcmds=(init enc dec ls rm recipients rekey completions help)
    if (( CURRENT == 2 )); then
        _describe 'subcommand' subcmds
        return
    fi
    case "$words[2]" in
        dec|rm)   compadd -- ${(f)"$(secret ls 2>/dev/null)"} ;;
        enc)          compadd -- -f ${(f)"$(secret ls 2>/dev/null)"} ;;
        completions)  compadd bash zsh fish ;;
    esac
}
compdef _secret secret
EOF
        ;;
    fish) cat <<'EOF'
complete -c secret -f
complete -c secret -n '__fish_use_subcommand' -a 'init enc dec ls rm recipients rekey completions help'
complete -c secret -n '__fish_seen_subcommand_from dec rm enc' -a '(secret ls 2>/dev/null)'
complete -c secret -n '__fish_seen_subcommand_from enc' -s f -d 'overwrite existing secret'
complete -c secret -n '__fish_seen_subcommand_from completions' -a 'bash zsh fish'
EOF
        ;;
    *)
        printf 'usage: secret completions {bash|zsh|fish}\n' >&2
        exit 2
        ;;
    esac
)

_secret_help() (
    cat <<'EOF'
usage: secret <subcommand> [args]

  init                 create the store and generate an identity
  enc  [-f] NAME       encrypt stdin -> NAME.age  (-f overwrites)
  dec  NAME            decrypt to stdout, verbatim
  ls                   list stored names
  rm   NAME            delete a secret
  recipients           show who can decrypt
  rekey                re-encrypt everything to current recipients
  completions SHELL    emit completions (bash | zsh | fish)

env: SECRETS_AGE SECRETS_DIR SECRETS_IDENTITY SECRETS_RECIPIENTS SECRETS_ARMOR
EOF
)

# --- dispatcher --------------------------------------------------------------

secret() {
    case "${1-help}" in
        init)        shift; _secret_init "$@" ;;
        enc)         shift; _secret_enc "$@" ;;
        dec)         shift; _secret_dec "$@" ;;
        ls)          shift; _secret_ls "$@" ;;
        rm)          shift; _secret_rm "$@" ;;
        recipients)  shift; _secret_recipients "$@" ;;
        rekey)       shift; _secret_rekey "$@" ;;
        completions) shift; _secret_completions "$@" ;;
        help|-h|--help) _secret_help ;;
        *)
            printf 'secret: unknown subcommand: %s (try: secret help)\n' "$1" >&2
            return 2
            ;;
    esac
}
