#!/bin/sh
# Test suite for secrets-lib.sh. Parameterized:
# shellcheck disable=SC2015,SC2016,SC2154  # ok/bad never fail; literal $(id) intentional; val assigned via eval
# shellcheck disable=SC2030,SC2031  # scoping SECRETS_DIR to a subshell is the point of those checks
#   TEST_SHELL   sh interpreter to run the assertions under (default: sh)
#   SECRETS_AGE  backend to pin (default: autodetect)
# The suite itself is POSIX sh and re-execs nothing; the caller picks the shell.

pass=0; fail=0
ok()   { pass=$((pass+1)); printf '  ok   %s\n' "$1"; }
failed=''
bad()  { fail=$((fail+1)); failed="$failed
  $1"; printf '  FAIL %s\n' "$1"; }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (want [$2] got [$3])"; fi; }

T=$(mktemp -d /tmp/secrets-test.XXXXXX)
trap 'rm -rf "$T"' EXIT INT TERM

# Only SECRETS_DIR is exported: the point of the passage/pago layout is that
# everything else falls out of it. The uppercase names below are the suite's
# own handles on those derived paths.
SECRETS_DIR="$T/secrets"
export SECRETS_DIR
STORE="$SECRETS_DIR/store"
ID="$SECRETS_DIR/identities"
RCP="$STORE/.age-recipients"

SECRETS_LIB=${SECRETS_LIB:-$(dirname "$0")/../lib/secrets-lib.sh}
# shellcheck disable=SC1090  # path is computed
. "$SECRETS_LIB"

printf 'backend: %s\n' "$(_secrets_age)"
AGEBIN=$(_secrets_age)
KG=$(_secrets_keygen)

echo "== init: passage/pago layout =="
secrets init 2>/dev/null
check "base dir mode 700"    "700" "$(stat -c %a "$SECRETS_DIR")"
check "store dir mode 700"   "700" "$(stat -c %a "$STORE")"
check "identities mode 600"  "600" "$(stat -c %a "$ID")"
check "identities is at \$SECRETS_DIR/identities" "1" "$([ -f "$SECRETS_DIR/identities" ] && echo 1)"
check "recipients is store/.age-recipients"       "1" "$([ -f "$RCP" ] && echo 1)"
check "recipients has 1 key" "1"   "$(grep -c '^age1' "$RCP")"
check "no legacy identity.txt"   "" "$(ls "$SECRETS_DIR"/identity.txt 2>/dev/null)"
check "no legacy recipients.txt" "" "$(ls "$SECRETS_DIR"/recipients.txt 2>/dev/null)"
secrets init >/dev/null 2>&1; check "init refuses to clobber" "1" "$?"

echo "== roundtrip =="
printf 'ghp_abc123\n' | secrets enc github
check "simple roundtrip" "ghp_abc123" "$(secrets dec github)"
check "blob lands in store/" "1" "$([ -f "$STORE/github.age" ] && echo 1)"

echo "== format-agnostic: dec is verbatim, no parsing =="
printf 'eyJhbGci.eyJzdWIi.SflKxwRJ==\n' | secrets enc jwt
check "base64 '==' verbatim" "eyJhbGci.eyJzdWIi.SflKxwRJ==" "$(secrets dec jwt)"
printf 'https://u:p@host/x?a=1&b=2\n' | secrets enc url
check "'=' chars untouched" "https://u:p@host/x?a=1&b=2" "$(secrets dec url)"
printf 'KEY=value\n' | secrets enc kv
check "KEY=value not parsed" "KEY=value" "$(secrets dec kv)"
printf 'secret\nuser: enrique\nurl: example.com\n' | secrets enc passlike
check "pass-style multiline verbatim" "secret
user: enrique
url: example.com" "$(secrets dec passlike)"
check "first line via head" "secret" "$(secrets dec passlike | head -n 1)"
secrets get github >/dev/null 2>&1; check "get subcommand is gone" "2" "$?"

echo "== multiline / binary =="
printf 'A=1\nB=2\nC=3\n' | secrets enc multi
check "multiline preserved" "A=1
B=2
C=3" "$(secrets dec multi)"
head -c 4096 /dev/urandom > "$T/bin.dat"
secrets enc binary < "$T/bin.dat"
secrets dec binary > "$T/bin.out"
if cmp -s "$T/bin.dat" "$T/bin.out"; then ok "4KiB binary byte-identical"; else bad "binary roundtrip"; fi

echo "== hierarchical names (passage/pago style) =="
printf 'AKIA-nested\n' | secrets enc work/aws
check "nested roundtrip" "AKIA-nested" "$(secrets dec work/aws)"
check "nested file path" "1" "$([ -f "$STORE/work/aws.age" ] && echo 1)"
check "nested dir mode 700" "700" "$(stat -c %a "$STORE/work")"
printf 'deep\n' | secrets enc a/b/c/d
check "3-level roundtrip" "deep" "$(secrets dec a/b/c/d)"
check "ls shows nested name" "1" "$(secrets ls | grep -cx 'work/aws')"
check "ls shows deep name"   "1" "$(secrets ls | grep -cx 'a/b/c/d')"
check "ls hides .age-recipients" "0" "$(secrets ls | grep -c 'age-recipients')"
check "ls is sorted" "$(secrets ls | LC_ALL=C sort)" "$(secrets ls)"
mkdir -p "$STORE/.hidden" && printf 'x\n' > "$STORE/.hidden/y.age"
check "ls prunes dot-directories" "0" "$(secrets ls | grep -c hidden)"
rm -rf "$STORE/.hidden"

echo "== exit status propagation =="
v=$(secrets dec nonexistent 2>/dev/null); check "missing secret rc" "1" "$?"
check "missing secret empty" "" "$v"
secrets dec github >/dev/null 2>&1; check "good decrypt rc" "0" "$?"

echo "== integrity =="
cp "$STORE/github.age" "$T/t.age"
printf 'X' | dd of="$STORE/github.age" bs=1 seek=250 conv=notrunc status=none
secrets dec github >/dev/null 2>&1
rc=$?
[ "$rc" -ne 0 ] && ok "tampered blob rejected (rc=$rc)" || bad "tampered blob accepted"
cp "$T/t.age" "$STORE/github.age"

echo "== name validation: escapes and dot-components rejected =="
for t_n in "../../etc/passwd" "" ".hidden" ".." "a/../b" "a/./b" "a/.git/b" \
           "/abs" "a/" "a//b" "$(printf 'ctrl\tchar')"; do
    printf 'x\n' | secrets enc "$t_n" >/dev/null 2>&1
    [ "$?" = "2" ] && ok "rejected: '$t_n'" || bad "accepted: '$t_n'"
done

echo "== name validation: everything a passage store can hold is accepted =="
# passage entry names are free-form; they only ever reach other programs as
# quoted path arguments, so metacharacters are data, not code.
for t_n in 'x$(id)' 'a;b' 'mail@example.com' 'with space' 'a+b' 'Ünïcøde'; do
    printf 'ok-%s\n' "$t_n" | secrets enc "$t_n" >/dev/null 2>&1
    check "accepted and roundtrips: '$t_n'" "ok-$t_n" "$(secrets dec "$t_n" 2>/dev/null)"
    yes | secrets rm "$t_n" >/dev/null 2>&1
done

echo "== clobber protection =="
printf 'v1\n' | secrets enc dup >/dev/null 2>&1
printf 'v2\n' | secrets enc dup >/dev/null 2>&1; check "second enc refused" "1" "$?"
check "original intact" "v1" "$(secrets dec dup)"
printf 'v2\n' | secrets enc -f dup; check "-f overwrites" "v2" "$(secrets dec dup)"

echo "== asymmetric: encrypt without the private key =="
mv "$ID" "$T/id.bak"
printf 'WRITE_ONLY=yes\n' | secrets enc writeonly; check "enc with no identity" "0" "$?"
secrets dec writeonly >/dev/null 2>&1;             check "dec with no identity" "3" "$?"
mv "$T/id.bak" "$ID"
check "readable once identity back" "WRITE_ONLY=yes" "$(secrets dec writeonly)"

echo "== rekey to a second recipient =="
"$KG" -o "$T/id2.txt" 2>/dev/null
"$KG" -y "$T/id2.txt" >> "$RCP"
t_before=$(secrets dec github)
secrets rekey 2>/dev/null; check "rekey rc" "0" "$?"
check "old identity still works" "$t_before" "$(secrets dec github)"
check "new identity works" "$t_before" "$("$AGEBIN" -d -i "$T/id2.txt" "$STORE/github.age")"
check "rekey covers nested entries" "AKIA-nested" \
    "$("$AGEBIN" -d -i "$T/id2.txt" "$STORE/work/aws.age")"
check "no stage dirs left" "0" "$(find "$SECRETS_DIR" -name '.rekey.*' | wc -l)"

echo "== rekey is all-or-nothing =="
printf 'corrupt-me\n' > "$STORE/broken.age"
secrets rekey >/dev/null 2>&1; check "rekey aborts on bad blob" "1" "$?"
check "github untouched after abort" "$t_before" "$(secrets dec github)"
check "no stage dir after abort" "0" "$(find "$SECRETS_DIR" -name '.rekey.*' | wc -l)"
check "no identity temporaries after abort" "0" \
    "$(find /dev/shm "${TMPDIR:-/tmp}" -maxdepth 1 -name '.secrets-id.*' 2>/dev/null | wc -l)"
rm -f "$STORE/broken.age"

echo "== per-subtree .age-recipients (passage's walk) =="
# proj/ gets the store's own recipients plus one extra key, so the subtree is
# a genuinely different recipient set that the root identity can still read.
"$KG" -o "$T/id3.txt" 2>/dev/null
mkdir -p "$STORE/proj"
cat "$RCP" > "$STORE/proj/.age-recipients"
"$KG" -y "$T/id3.txt" >> "$STORE/proj/.age-recipients"
check "recipients walk finds the nearest file" "$STORE/proj/.age-recipients" \
    "$(SECRETS_STORE=$STORE _secrets_recipients_for proj)"
check "recipients walk falls back to the root" "$RCP" \
    "$(SECRETS_STORE=$STORE _secrets_recipients_for '')"
check "walk from a deeper dir climbs to proj" "$STORE/proj/.age-recipients" \
    "$(SECRETS_STORE=$STORE _secrets_recipients_for proj/sub)"
printf 'subtree-value\n' | secrets enc proj/key
check "subtree entry readable by the subtree-only key" "subtree-value" \
    "$("$AGEBIN" -d -i "$T/id3.txt" "$STORE/proj/key.age")"
check "subtree entry readable by the store identity" "subtree-value" "$(secrets dec proj/key)"
check "recipients NAME reports the subtree file" \
    "$(cat "$STORE/proj/.age-recipients")" "$(secrets recipients proj/key)"
check "recipients with no arg reports the root file" \
    "$(cat "$RCP")" "$(secrets recipients)"

echo "== rename re-encrypts across a recipients boundary =="
secrets rename proj/key movedout
check "rename out of the subtree rc" "0" "$?"
check "moved entry readable with the store identity" "subtree-value" "$(secrets dec movedout)"
"$AGEBIN" -d -i "$T/id3.txt" "$STORE/movedout.age" >/dev/null 2>&1
check "moved entry no longer readable by the subtree-only key" "1" "$?"
check "source entry gone" "0" "$(secrets ls | grep -cx 'proj/key')"
# proj/ is not pruned: it still holds the .age-recipients that governs it.
check "subtree kept while it still holds .age-recipients" "1" \
    "$([ -f "$STORE/proj/.age-recipients" ] && echo 1 || echo 0)"

# A failed decrypt must not read as a clean re-encryption: encrypting the
# empty output of a failed `age -d` still yields a valid, non-empty age file,
# and POSIX sh has no pipefail to notice. Getting this wrong destroys the
# source and leaves an empty secret in its place.
printf 'not-an-age-file\n' > "$STORE/proj/broken.age"
secrets rename proj/broken rescued >/dev/null 2>&1
check "rename of an undecryptable entry fails" "1" "$?"
check "its source survives" "1" "$([ -f "$STORE/proj/broken.age" ] && echo 1 || echo 0)"
check "no empty destination left" "0" "$([ -e "$STORE/rescued.age" ] && echo 1 || echo 0)"
check "no rename temporaries left" "0" \
    "$(find "$STORE" \( -name '.tmp.*' -o -name '.st.*' \) | wc -l)"
rm -f "$STORE/proj/broken.age"

rm -rf "$STORE/proj"
yes | secrets rm movedout >/dev/null 2>&1

echo "== rm prunes the directories it empties =="
printf 'x\n' | secrets enc p/q/r
yes | secrets rm p/q/r >/dev/null 2>&1
check "p/q/r gone"    "0" "$(secrets ls | grep -cx 'p/q/r')"
check "empty p/q gone" "0" "$([ -d "$STORE/p/q" ] && echo 1 || echo 0)"
check "empty p gone"   "0" "$([ -d "$STORE/p" ] && echo 1 || echo 0)"
check "store itself survives" "1" "$([ -d "$STORE" ] && echo 1 || echo 0)"

echo "== armor mode =="
printf 'ARMORED=yes\n' | SECRETS_ARMOR=1 secrets enc armored
check "armor header" "1" "$(head -1 "$STORE/armored.age" | grep -c 'BEGIN AGE ENCRYPTED FILE')"
check "armor decrypts" "ARMORED=yes" "$(secrets dec armored)"

echo "== ls / rm / recipients / help / dispatcher =="
check "ls finds github" "1" "$(secrets ls | grep -cx github)"
check "recipients count" "2" "$(secrets recipients | grep -c '^age1')"
yes | secrets rm dup >/dev/null 2>&1
check "rm removed it" "0" "$(secrets ls | grep -cx dup)"
secrets help >/dev/null; check "help rc" "0" "$?"
secrets bogus >/dev/null 2>&1; check "unknown subcommand rc" "2" "$?"

echo "== rename =="
printf 'moved\n' | secrets enc oldname
secrets rename oldname newname; check "rename rc" "0" "$?"
check "old name gone" "0" "$(secrets ls | grep -cx oldname)"
check "new name decrypts" "moved" "$(secrets dec newname)"
secrets rename missing x >/dev/null 2>&1; check "rename missing rc" "1" "$?"
printf 'other\n' | secrets enc taken
secrets rename newname taken >/dev/null 2>&1; check "rename clobber refused" "1" "$?"
check "clobber target intact" "other" "$(secrets dec taken)"
secrets rename -f newname taken; check "rename -f rc" "0" "$?"
check "rename -f overwrote" "moved" "$(secrets dec taken)"
secrets rename taken taken >/dev/null 2>&1; check "self-rename refused" "1" "$?"
secrets rename '../x' ok2 >/dev/null 2>&1; check "bad OLD rejected" "2" "$?"
secrets rename taken '.hidden' >/dev/null 2>&1; check "bad NEW rejected" "2" "$?"
secrets rename taken 'deep/dest'; check "rename into a new subdir rc" "0" "$?"
check "renamed into subdir decrypts" "moved" "$(secrets dec deep/dest)"
secrets rename deep/dest taken; check "rename back out rc" "0" "$?"
check "subdir pruned after moving out" "0" "$([ -d "$STORE/deep" ] && echo 1 || echo 0)"

# ── interoperability ─────────────────────────────────────────────────────────
# passage and pago are not installed in CI, so drive their exact file layout
# and age invocations directly. That is the whole contract: same paths, same
# .age-recipients semantics, plain age ciphertext.

echo "== interop: a store secrets wrote is readable the passage way =="
# passage: $PASSAGE_DIR/<name>.age, decrypted with -i $PASSAGE_IDENTITIES_FILE
check "passage-style read of a flat entry" "ghp_abc123" \
    "$("$AGEBIN" -d -i "$ID" "$STORE/github.age")"
check "passage-style read of a nested entry" "AKIA-nested" \
    "$("$AGEBIN" -d -i "$ID" "$STORE/work/aws.age")"

echo "== interop: secrets reads a store written the passage way =="
"$AGEBIN" -e -R "$RCP" -o "$STORE/from-passage.age" <<'EOF'
written-by-passage
EOF
mkdir -p "$STORE/nested/by/passage"
"$AGEBIN" -e -R "$RCP" -o "$STORE/nested/by/passage/entry.age" <<'EOF'
nested-by-passage
EOF
check "reads a flat passage entry"   "written-by-passage" "$(secrets dec from-passage)"
check "reads a nested passage entry" "nested-by-passage"  "$(secrets dec nested/by/passage/entry)"
check "ls sees the passage entries" "1" "$(secrets ls | grep -cx 'nested/by/passage/entry')"
yes | secrets rm from-passage >/dev/null 2>&1
yes | secrets rm nested/by/passage/entry >/dev/null 2>&1

echo "== interop: a passage store with no .age-recipients =="
# passage falls back to encrypting to the identities file's own public keys.
P="$T/passage"
mkdir -p "$P/store"
"$KG" -o "$P/identities" 2>/dev/null
check "no recipients file present" "" \
    "$(SECRETS_STORE=$P/store _secrets_recipients_for '')"
printf 'fallback\n' | ( SECRETS_DIR="$P"; secrets enc fb )
check "enc falls back to the identities file" "0" "$?"
check "fallback entry decrypts with age -i" "fallback" \
    "$("$AGEBIN" -d -i "$P/identities" "$P/store/fb.age")"
check "SECRETS_DIR alone reaches a passage store" "fallback" \
    "$( SECRETS_DIR="$P"; secrets dec fb )"
check "recipients derives keys from the identity" "1" \
    "$( SECRETS_DIR="$P"; secrets recipients | grep -c '^age1' )"

echo "== interop: pago's passphrase-encrypted identities file =="
# pago always keeps identities encrypted; age only prompts on a terminal, so
# these checks need script(1) to hand it a pty.
if command -v script >/dev/null 2>&1 &&
   printf 'pw\npw\n' | script -qec \
       "$AGEBIN -a -e -p -o $T/id.enc $T/id2.txt" /dev/null >/dev/null 2>&1 &&
   [ -s "$T/id.enc" ]; then
    G="$T/pago"
    mkdir -p "$G/store"
    cp "$T/id.enc" "$G/identities"
    "$KG" -y "$T/id2.txt" > "$G/store/.age-recipients"
    printf 'pago-secret\n' | ( SECRETS_DIR="$G"; secrets enc svc )
    check "enc needs no passphrase (recipients file only)" "0" "$?"
    check "pago-style blob is plain age" "1" \
        "$("$AGEBIN" -d -i "$T/id2.txt" "$G/store/svc.age" | grep -c 'pago-secret')"
    t_out=$(printf 'pw\n' | script -qec \
        "env SECRETS_DIR=$G $(dirname "$0")/../bin/secrets dec svc" /dev/null 2>/dev/null)
    printf '%s' "$t_out" | grep -q 'pago-secret'
    check "dec decrypts the encrypted identities file" "0" "$?"
    check "no decrypted identity left in /dev/shm" "0" \
        "$(find /dev/shm -maxdepth 1 -name '.secrets-id.*' 2>/dev/null | wc -l)"
    check "no decrypted identity left in TMPDIR" "0" \
        "$(find "${TMPDIR:-/tmp}" -maxdepth 1 -name '.secrets-id.*' 2>/dev/null | wc -l)"
else
    echo "  skip pago encrypted-identities checks (no script(1) pty available)"
fi

echo "== migrating a pre-0.2 flat store =="
L="$T/legacy"
mkdir -p "$L"
cp "$ID" "$L/identity.txt"
"$KG" -y "$L/identity.txt" > "$L/recipients.txt"
"$AGEBIN" -e -R "$L/recipients.txt" -o "$L/old.age" <<'EOF'
legacy-value
EOF
( SECRETS_DIR="$L"; secrets ls ) >/dev/null 2>&1
check "legacy store is refused, not silently replaced" "4" "$?"
( SECRETS_DIR="$L"; secrets ls ) 2>&1 | grep -q 'secrets migrate'
check "refusal points at secrets migrate" "0" "$?"
( SECRETS_DIR="$L"; secrets migrate ) >/dev/null 2>&1
check "migrate rc" "0" "$?"
check "blob moved into store/" "1" "$([ -f "$L/store/old.age" ] && echo 1)"
check "identity.txt -> identities" "1" "$([ -f "$L/identities" ] && echo 1)"
check "recipients.txt -> store/.age-recipients" "1" \
    "$([ -f "$L/store/.age-recipients" ] && echo 1)"
check "migrated secret decrypts" "legacy-value" "$( SECRETS_DIR="$L"; secrets dec old )"
( SECRETS_DIR="$L"; secrets migrate ) >/dev/null 2>&1
check "migrate refuses to run twice" "1" "$?"

echo "== completions emit and parse =="
secrets completions bash > "$T/c.bash"; check "bash emit rc" "0" "$?"
bash -n "$T/c.bash"; check "bash completion parses" "0" "$?"
secrets completions zsh > "$T/c.zsh"; check "zsh emit rc" "0" "$?"
if command -v zsh >/dev/null 2>&1; then
    zsh -n "$T/c.zsh"; check "zsh completion parses" "0" "$?"
fi
secrets completions fish > "$T/c.fish"; check "fish emit rc" "0" "$?"
secrets completions powershell >/dev/null 2>&1; check "unknown shell rc" "2" "$?"
grep -qw rename "$T/c.bash"; check "bash completes rename" "0" "$?"
grep -qw rename "$T/c.zsh";  check "zsh completes rename" "0" "$?"
grep -qw rename "$T/c.fish"; check "fish completes rename" "0" "$?"
grep -qw migrate "$T/c.bash"; check "bash completes migrate" "0" "$?"
grep -qw migrate "$T/c.zsh";  check "zsh completes migrate" "0" "$?"
grep -qw migrate "$T/c.fish"; check "fish completes migrate" "0" "$?"
# names are free-form now, so the bash completion must never expand them
grep -q 'compgen -W "$(secrets ls' "$T/c.bash"
check "bash completion does not expand stored names" "1" "$?"

echo "== cli wrapper =="
CLI=$(dirname "$0")/../bin/secrets
# `env VAR= cmd` below is needed only for empty-value overrides -- the bare
# `VAR= cmd` form trips shellcheck's SC1007 on an empty value. Non-empty
# overrides (e.g. `SECRETS_LIB=/path cmd`) don't trip it and don't need `env`.

# [3] resolution straight from a git checkout: $dir/../lib/secrets-lib.sh
check "cli: checkout resolution" "ghp_abc123" "$(env SECRETS_LIB= "$CLI" dec github)"

# [2] resolution from an installed prefix: $dir/../share/secrets/secrets-lib.sh
mkdir -p "$T/pfx/bin" "$T/pfx/share/secrets"
cp "$CLI" "$T/pfx/bin/secrets"
cp "$SECRETS_LIB" "$T/pfx/share/secrets/secrets-lib.sh"
check "cli: prefix/share resolution" "ghp_abc123" \
    "$(env SECRETS_LIB= HOME=/nonexistent "$T/pfx/bin/secrets" dec github)"

# [2] beats [3]: a decoy at $dir/../lib must not shadow the installed
# $dir/../share library -- regression coverage for the fix that swapped
# their resolution order (see the whole-branch review, 2026-08-24).
mkdir -p "$T/pfx/lib"
printf '%s\n' 'secrets() { printf "DECOY-SHADOWED-LIBRARY"; }' > "$T/pfx/lib/secrets-lib.sh"
check "cli: share/ not shadowed by lib/ decoy" "ghp_abc123" \
    "$(env SECRETS_LIB= HOME=/nonexistent "$T/pfx/bin/secrets" dec github)"

# [4] resolution with both files in one directory
mkdir -p "$T/same"
cp "$CLI" "$SECRETS_LIB" "$T/same/"
check "cli: same-dir resolution" "ghp_abc123" \
    "$(env SECRETS_LIB= HOME=/nonexistent "$T/same/secrets" dec github)"

# [1] SECRETS_LIB overrides everything, even with no library near the binary
mkdir -p "$T/lone/bin"
cp "$CLI" "$T/lone/bin/secrets"
check "cli: SECRETS_LIB override" "ghp_abc123" \
    "$(SECRETS_LIB="$T/pfx/share/secrets/secrets-lib.sh" HOME=/nonexistent \
       "$T/lone/bin/secrets" dec github)"

# a set-but-unreadable SECRETS_LIB is a hard error, not a silent fall-through
lib_err=$(env SECRETS_LIB=/nonexistent/lib.sh "$CLI" ls 2>&1 >/dev/null)
check "cli: unreadable SECRETS_LIB rc" "127" "$?"
printf '%s' "$lib_err" | grep -q 'SECRETS_LIB'
check "cli: unreadable SECRETS_LIB names it" "0" "$?"

# no library reachable at all -- but candidates [6] and [7] are absolute
# machine-wide paths (Task 3's `make install` defaults PREFIX to /usr/local,
# i.e. candidate [6]), so this library-less state isn't always reachable
if [ -r /usr/local/share/secrets/secrets-lib.sh ] || [ -r /usr/share/secrets/secrets-lib.sh ]; then
    echo "  skip cli: missing lib (system-wide library installed)"
else
    cli_err=$(env SECRETS_LIB= HOME=/nonexistent "$T/lone/bin/secrets" ls 2>&1 >/dev/null)
    check "cli: missing lib rc" "127" "$?"
    printf '%s' "$cli_err" | grep -q 'SECRETS_LIB'
    check "cli: missing lib names SECRETS_LIB" "0" "$?"
fi

# exit codes survive the extra process
env SECRETS_LIB= "$CLI" dec nonexistent >/dev/null 2>&1
check "cli: missing secret rc" "1" "$?"
env SECRETS_LIB= "$CLI" dec '../etc/passwd' >/dev/null 2>&1
check "cli: invalid name rc" "2" "$?"
env SECRETS_LIB= "$CLI" bogus >/dev/null 2>&1
check "cli: unknown subcommand rc" "2" "$?"
env SECRETS_LIB= "$CLI" >/dev/null 2>&1
check "cli: no args is help" "0" "$?"

# exit code 3 (missing identity) also crosses the process boundary; move
# the identity aside and always restore it right after, so a failing
# check here cannot leave the store without its identity file.
mv "$ID" "$T/id.cli.bak"
env SECRETS_LIB= "$CLI" dec github >/dev/null 2>&1
check "cli: missing identity rc" "3" "$?"
mv "$T/id.cli.bak" "$ID"

# stdin flows through the wrapper unchanged
printf 'via-cli\n' | env SECRETS_LIB= "$CLI" enc fromcli
check "cli: stdin pipe roundtrip" "via-cli" "$(env SECRETS_LIB= "$CLI" dec fromcli)"

# completions emitted by the CLI name the new command
env SECRETS_LIB= "$CLI" completions bash > "$T/cli.bash"
grep -q 'complete -F _secrets_complete secrets' "$T/cli.bash"
check "cli: bash completion registers secrets" "0" "$?"
# bash-only: the fish completion legitimately contains the prose word
# "secret" (`-d 'overwrite existing secret'`), so this stale-name check
# would false-positive there.
grep -qw 'secret' "$T/cli.bash"
check "cli: no stale 'secret' in bash completion" "1" "$?"

# SECRETS_LIB must name a readable regular FILE: a directory is readable, and
# sourcing one yields a raw shell error rather than a branded one
env SECRETS_LIB="$T" "$CLI" ls >/dev/null 2>&1
check "cli: SECRETS_LIB as directory rc" "127" "$?"
cli_err=$(env SECRETS_LIB="$T" "$CLI" ls 2>&1 >/dev/null)
printf '%s' "$cli_err" | grep -q 'not a readable file'
check "cli: SECRETS_LIB as directory is branded" "0" "$?"

# a readable file that simply is not the library
printf 'unrelated_var=1\n' > "$T/notlib.sh"
env SECRETS_LIB="$T/notlib.sh" "$CLI" ls >/dev/null 2>&1
check "cli: non-library file rc" "127" "$?"
cli_err=$(env SECRETS_LIB="$T/notlib.sh" "$CLI" ls 2>&1 >/dev/null)
printf '%s' "$cli_err" | grep -q 'did not define the secrets() function'
check "cli: non-library file is branded" "0" "$?"

# neither SECRETS_DIR nor HOME: a branded message and rc 2, not a raw
# "HOME: parameter not set" from the library's own set -u expansion
cli_err=$( unset HOME SECRETS_DIR; "$CLI" ls 2>&1 >/dev/null )
check "cli: no HOME/SECRETS_DIR rc" "2" "$?"
printf '%s' "$cli_err" | grep -q '^secrets: neither SECRETS_DIR nor HOME'
check "cli: no HOME/SECRETS_DIR is branded" "0" "$?"

# SECRETS_DIR alone selects a whole foreign store, layout and all
check "cli: SECRETS_DIR alone reaches the passage store" "fallback" \
    "$(env SECRETS_LIB= SECRETS_DIR="$P" "$CLI" dec fb)"

# a staged `make install` tree resolves via the prefix-relative candidate
if command -v make >/dev/null 2>&1; then
    make -C "$(dirname "$0")/.." install DESTDIR="$T/dest" PREFIX=/usr/local >/dev/null 2>&1
    check "make install rc" "0" "$?"
    check "installed bin mode" "755" "$(stat -c %a "$T/dest/usr/local/bin/secrets" 2>/dev/null)"
    check "installed lib mode" "644" \
        "$(stat -c %a "$T/dest/usr/local/share/secrets/secrets-lib.sh" 2>/dev/null)"
    check "installed cli works" "ghp_abc123" \
        "$(env SECRETS_LIB= HOME=/nonexistent "$T/dest/usr/local/bin/secrets" dec github)"
    check "two files staged before uninstall" "2" \
        "$(find "$T/dest" -type f 2>/dev/null | wc -l)"
    make -C "$(dirname "$0")/.." uninstall DESTDIR="$T/dest" PREFIX=/usr/local >/dev/null 2>&1
    check "uninstall removes both" "0" "$(find "$T/dest" -type f 2>/dev/null | wc -l)"

    # the `-` on rmdir is deliberate: uninstall must succeed, and leave the
    # directory alone, when it still holds a file the user put there
    make -C "$(dirname "$0")/.." install DESTDIR="$T/keep" PREFIX=/usr/local >/dev/null 2>&1
    printf 'mine\n' > "$T/keep/usr/local/share/secrets/notes.txt"
    make -C "$(dirname "$0")/.." uninstall DESTDIR="$T/keep" PREFIX=/usr/local >/dev/null 2>&1
    check "uninstall rc with a user file present" "0" "$?"
    check "user file survives uninstall" "mine" \
        "$(cat "$T/keep/usr/local/share/secrets/notes.txt" 2>/dev/null)"

    # install must not hand the caller's umask to the directories it creates:
    # under `umask 077` a root install would otherwise be unreadable to every
    # other user. Covers intermediate components, not just the leaf.
    ( umask 077
      make -C "$(dirname "$0")/.." install DESTDIR="$T/um" PREFIX=/opt/x ) >/dev/null 2>&1
    check "install dir mode under umask 077" "755" \
        "$(stat -c %a "$T/um/opt/x/share/secrets" 2>/dev/null)"
    check "intermediate dir mode under umask 077" "755" \
        "$(stat -c %a "$T/um/opt/x/share" 2>/dev/null)"

    # and it must leave the mode of a directory it did not create alone
    mkdir -p "$T/pre/usr/local/bin" && chmod 2775 "$T/pre/usr/local/bin"
    make -C "$(dirname "$0")/.." install DESTDIR="$T/pre" PREFIX=/usr/local >/dev/null 2>&1
    check "pre-existing dir mode preserved" "2775" \
        "$(stat -c %a "$T/pre/usr/local/bin" 2>/dev/null)"
else
    echo "  skip make-based checks (make not found)"
fi

echo "== no variable leakage into sourcing shell (subshell bodies) =="
for var in agebin keygen out tmp in name f n stage st pub force src dst \
           bin dir sub idf rf list legacy; do
    eval "val=\${$var-__UNSET__}"
    [ "$val" = "__UNSET__" ] && ok "no leak: \$$var" || bad "leaked: \$$var=[$val]"
done

echo "== permissions / no plaintext left behind =="
check "all blobs 600" "0" "$(find "$STORE" -name '*.age' ! -perm 600 | wc -l)"
check "no staging temp files left" "0" "$(find "$STORE" -name '.tmp.*' | wc -l)"
if grep -rIl 'ghp_abc123' "$SECRETS_DIR" 2>/dev/null | grep -q .; then
    bad "plaintext found in store"
else ok "no plaintext in store"; fi

# List failures before the tally so `... | tail -1` still shows the summary
# while a captured run says which checks failed.
[ "$fail" -eq 0 ] || printf '\nfailed checks:%s\n' "$failed"
printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
