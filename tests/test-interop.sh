#!/bin/sh
# Interoperability suite: drives a single store with `secrets` and with the
# real passage(1) and pago(1), in both directions.
#
# Both are optional. Each block skips itself when its program is not on PATH,
# so this runs clean on a machine that has neither; CI installs both.
#   passage  https://github.com/FiloSottile/passage   (a bash script)
#   pago     https://github.com/dbohdan/pago          (go install ...)
#
# shellcheck disable=SC2015  # ok/bad never fail

pass=0; fail=0
ok()   { pass=$((pass+1)); printf '  ok   %s\n' "$1"; }
failed=''
bad()  { fail=$((fail+1)); failed="$failed
  $1"; printf '  FAIL %s\n' "$1"; }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (want [$2] got [$3])"; fi; }

T=$(mktemp -d /tmp/secrets-interop.XXXXXX)
trap 'rm -rf "$T"' EXIT INT TERM
CLI=$(dirname "$0")/../bin/secrets
SECRETS_LIB=${SECRETS_LIB:-$(dirname "$0")/../lib/secrets-lib.sh}
export SECRETS_LIB

echo "== passage =="
if command -v passage >/dev/null 2>&1; then
    # One directory, two tools: $SECRETS_DIR is passage's home, so
    # $SECRETS_STORE is $PASSAGE_DIR and $SECRETS_IDENTITY is its identities.
    H="$T/passage"
    SECRETS_DIR="$H"; export SECRETS_DIR
    PASSAGE_DIR="$H/store"; export PASSAGE_DIR
    PASSAGE_IDENTITIES_FILE="$H/identities"; export PASSAGE_IDENTITIES_FILE

    "$CLI" init >/dev/null 2>&1
    check "secrets init builds a store passage accepts" "1" \
        "$([ -f "$PASSAGE_IDENTITIES_FILE" ] && [ -f "$PASSAGE_DIR/.age-recipients" ] && echo 1)"

    # secrets writes -> passage reads
    printf 'hunter2\nuser: enrique\n' | "$CLI" enc web/example.com
    check "passage shows a flat field of a secrets entry" "hunter2" \
        "$(passage show web/example.com 2>/dev/null | head -n 1)"
    check "passage shows the whole secrets entry" "hunter2
user: enrique" "$(passage show web/example.com 2>/dev/null)"

    # passage writes -> secrets reads
    printf 'from-passage\n' | passage insert -m -f deep/nest/thing >/dev/null 2>&1
    check "secrets decrypts a passage entry" "from-passage" "$("$CLI" dec deep/nest/thing)"
    check "secrets ls sees the passage entry" "1" \
        "$("$CLI" ls | grep -cx 'deep/nest/thing')"

    # secrets rekey must leave every entry readable by passage
    passage generate gen/pw 16 >/dev/null 2>&1
    i_before=$(passage show gen/pw 2>/dev/null)
    "$CLI" rekey >/dev/null 2>&1
    check "rekey rc" "0" "$?"
    check "passage still reads a secrets-rekeyed entry" "$i_before" \
        "$(passage show gen/pw 2>/dev/null)"

    # and a secrets rename must land where passage looks
    "$CLI" rename web/example.com sites/example
    check "passage shows a secrets-renamed entry" "hunter2" \
        "$(passage show sites/example 2>/dev/null | head -n 1)"

    # passage's own move must stay visible to secrets
    passage mv -f sites/example moved/example >/dev/null 2>&1
    check "secrets sees a passage-moved entry" "1" \
        "$("$CLI" ls | grep -cx 'moved/example')"

    unset PASSAGE_DIR PASSAGE_IDENTITIES_FILE
else
    echo "  skip passage checks (passage not on PATH)"
fi

echo "== pago =="
# pago always keeps its identities file encrypted under a master password, so
# reading its store needs a terminal for age's prompt.
if command -v pago >/dev/null 2>&1 && command -v pago-agent >/dev/null 2>&1 &&
   command -v script >/dev/null 2>&1; then
    G="$T/pago"
    mkdir -p "$G"
    PAGO_DIR="$G"; export PAGO_DIR
    PAGO_GIT=0; export PAGO_GIT
    PAGO_MEMLOCK=0; export PAGO_MEMLOCK
    # The agent socket is per user, not per store: without one of its own, an
    # agent left running by another store would answer with that store's
    # identities. pago refuses a socket directory other users can reach.
    mkdir -p "$T/pagosock" && chmod 700 "$T/pagosock"
    PAGO_SOCK="$T/pagosock/socket"; export PAGO_SOCK
    printf 'hunter2\nhunter2\n' > "$T/pw"

    exec 9<"$T/pw"
    PAGO_PASSPHRASE_FD=9 pago init >/dev/null 2>&1
    check "pago init rc" "0" "$?"
    check "pago's layout is the one secrets expects" "1" \
        "$([ -f "$G/identities" ] && [ -f "$G/store/.age-recipients" ] && echo 1)"

    SECRETS_DIR="$G"; export SECRETS_DIR

    # secrets writes -> pago reads. Encrypting needs only .age-recipients, so
    # this side never touches the encrypted identities file.
    printf 'secrets-written\n' | "$CLI" enc svc/api
    check "enc into a pago store needs no master password" "0" "$?"
    exec 9<"$T/pw"
    check "pago shows a secrets entry" "secrets-written" \
        "$(PAGO_PASSPHRASE_FD=9 pago show svc/api 2>/dev/null)"

    # pago writes -> secrets reads, unwrapping the encrypted identities file
    exec 9<"$T/pw"
    printf 'pago-written\n' | PAGO_PASSPHRASE_FD=9 pago add -m work/db >/dev/null 2>&1
    check "secrets ls sees the pago entry" "1" "$("$CLI" ls | grep -cx 'work/db')"
    i_out=$(printf 'hunter2\n' | script -qec \
        "env SECRETS_DIR=$G $CLI dec work/db" /dev/null 2>/dev/null)
    printf '%s' "$i_out" | grep -q 'pago-written'
    check "secrets decrypts through pago's encrypted identities" "0" "$?"

    # a wrong master password must fail, not return garbage
    i_out=$(printf 'wrong\n' | script -qec \
        "env SECRETS_DIR=$G $CLI dec work/db" /dev/null 2>/dev/null)
    printf '%s' "$i_out" | grep -q 'pago-written'
    check "a wrong master password does not decrypt" "1" "$?"

    # the unwrapped identity is a temporary; none may survive the command
    check "no decrypted identity left behind" "0" \
        "$(find /dev/shm "${TMPDIR:-/tmp}" -maxdepth 1 -name '.secrets-id.*' 2>/dev/null | wc -l)"

    pago agent stop >/dev/null 2>&1
    unset PAGO_DIR PAGO_GIT PAGO_MEMLOCK PAGO_SOCK
else
    echo "  skip pago checks (pago, pago-agent or script(1) not on PATH)"
fi

[ "$fail" -eq 0 ] || printf '\nfailed checks:%s\n' "$failed"
printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
