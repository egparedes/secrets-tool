#!/bin/sh
# Test suite for secrets-lib.sh. Parameterized:
# shellcheck disable=SC2015,SC2016,SC2154  # ok/bad never fail; literal $(id) intentional; val assigned via eval
#   TEST_SHELL   sh interpreter to run the assertions under (default: sh)
#   SECRETS_AGE  backend to pin (default: autodetect)
# The suite itself is POSIX sh and re-execs nothing; the caller picks the shell.

pass=0; fail=0
ok()   { pass=$((pass+1)); printf '  ok   %s\n' "$1"; }
bad()  { fail=$((fail+1)); printf '  FAIL %s\n' "$1"; }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (want [$2] got [$3])"; fi; }

T=$(mktemp -d /tmp/secrets-test.XXXXXX)
trap 'rm -rf "$T"' EXIT INT TERM
SECRETS_DIR="$T/store"
SECRETS_IDENTITY="$SECRETS_DIR/identity.txt"
SECRETS_RECIPIENTS="$SECRETS_DIR/recipients.txt"
export SECRETS_DIR SECRETS_IDENTITY SECRETS_RECIPIENTS

SECRETS_LIB=${SECRETS_LIB:-$(dirname "$0")/../lib/secrets-lib.sh}
# shellcheck disable=SC1090  # path is computed
. "$SECRETS_LIB"

printf 'backend: %s\n' "$(_secrets_age)"

echo "== init =="
secrets init 2>/dev/null
check "store dir mode 700"   "700" "$(stat -c %a "$SECRETS_DIR")"
check "identity mode 600"    "600" "$(stat -c %a "$SECRETS_IDENTITY")"
check "recipients has 1 key" "1"   "$(grep -c '^age1' "$SECRETS_RECIPIENTS")"
secrets init >/dev/null 2>&1; check "init refuses to clobber" "1" "$?"

echo "== roundtrip =="
printf 'ghp_abc123\n' | secrets enc github
check "simple roundtrip" "ghp_abc123" "$(secrets dec github)"

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

echo "== exit status propagation =="
v=$(secrets dec nonexistent 2>/dev/null); check "missing secret rc" "1" "$?"
check "missing secret empty" "" "$v"
secrets dec github >/dev/null 2>&1; check "good decrypt rc" "0" "$?"

echo "== integrity =="
cp "$SECRETS_DIR/github.age" "$T/t.age"
printf 'X' | dd of="$SECRETS_DIR/github.age" bs=1 seek=250 conv=notrunc status=none
secrets dec github >/dev/null 2>&1
rc=$?
[ "$rc" -ne 0 ] && ok "tampered blob rejected (rc=$rc)" || bad "tampered blob accepted"
cp "$T/t.age" "$SECRETS_DIR/github.age"

echo "== name validation =="
for t_n in "../../etc/passwd" "" "a/b" ".hidden" 'x$(id)' "a;b"; do
    printf 'x\n' | secrets enc "$t_n" >/dev/null 2>&1
    [ "$?" = "2" ] && ok "rejected: '$t_n'" || bad "accepted: '$t_n'"
done

echo "== clobber protection =="
printf 'v1\n' | secrets enc dup >/dev/null 2>&1
printf 'v2\n' | secrets enc dup >/dev/null 2>&1; check "second enc refused" "1" "$?"
check "original intact" "v1" "$(secrets dec dup)"
printf 'v2\n' | secrets enc -f dup; check "-f overwrites" "v2" "$(secrets dec dup)"

echo "== asymmetric: encrypt without the private key =="
mv "$SECRETS_IDENTITY" "$T/id.bak"
printf 'WRITE_ONLY=yes\n' | secrets enc writeonly; check "enc with no identity" "0" "$?"
secrets dec writeonly >/dev/null 2>&1;             check "dec with no identity" "3" "$?"
mv "$T/id.bak" "$SECRETS_IDENTITY"
check "readable once identity back" "WRITE_ONLY=yes" "$(secrets dec writeonly)"

echo "== rekey to a second recipient =="
KG=$(_secrets_keygen)
"$KG" -o "$T/id2.txt" 2>/dev/null
"$KG" -y "$T/id2.txt" >> "$SECRETS_RECIPIENTS"
t_before=$(secrets dec github)
secrets rekey 2>/dev/null; check "rekey rc" "0" "$?"
check "old identity still works" "$t_before" "$(secrets dec github)"
AGEBIN=$(_secrets_age)
check "new identity works" "$t_before" "$("$AGEBIN" -d -i "$T/id2.txt" "$SECRETS_DIR/github.age")"
check "no stage dirs left" "0" "$(find "$SECRETS_DIR" -name '.rekey.*' | wc -l)"

echo "== rekey is all-or-nothing =="
printf 'corrupt-me\n' > "$SECRETS_DIR/broken.age"
secrets rekey >/dev/null 2>&1; check "rekey aborts on bad blob" "1" "$?"
check "github untouched after abort" "$t_before" "$(secrets dec github)"
check "no stage dir after abort" "0" "$(find "$SECRETS_DIR" -name '.rekey.*' | wc -l)"
rm -f "$SECRETS_DIR/broken.age"

echo "== armor mode =="
printf 'ARMORED=yes\n' | SECRETS_ARMOR=1 secrets enc armored
check "armor header" "1" "$(head -1 "$SECRETS_DIR/armored.age" | grep -c 'BEGIN AGE ENCRYPTED FILE')"
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
secrets rename taken 'a/b' >/dev/null 2>&1; check "bad NEW rejected" "2" "$?"

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
mv "$SECRETS_IDENTITY" "$T/id.cli.bak"
env SECRETS_LIB= "$CLI" dec github >/dev/null 2>&1
check "cli: missing identity rc" "3" "$?"
mv "$T/id.cli.bak" "$SECRETS_IDENTITY"

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

# a staged `make install` tree resolves via the prefix-relative candidate
if command -v make >/dev/null 2>&1; then
    make -C "$(dirname "$0")/.." install DESTDIR="$T/dest" PREFIX=/usr/local >/dev/null 2>&1
    check "make install rc" "0" "$?"
    check "installed bin mode" "755" "$(stat -c %a "$T/dest/usr/local/bin/secrets" 2>/dev/null)"
    check "installed lib mode" "644" \
        "$(stat -c %a "$T/dest/usr/local/share/secrets/secrets-lib.sh" 2>/dev/null)"
    check "installed cli works" "ghp_abc123" \
        "$(env SECRETS_LIB= HOME=/nonexistent "$T/dest/usr/local/bin/secrets" dec github)"
    make -C "$(dirname "$0")/.." uninstall DESTDIR="$T/dest" PREFIX=/usr/local >/dev/null 2>&1
    check "uninstall removes both" "0" "$(find "$T/dest" -type f 2>/dev/null | wc -l)"
else
    echo "  skip make-based checks (make not found)"
fi

echo "== no variable leakage into sourcing shell (subshell bodies) =="
for var in agebin keygen out tmp in name f n stage st pub force src dst; do
    eval "val=\${$var-__UNSET__}"
    [ "$val" = "__UNSET__" ] && ok "no leak: \$$var" || bad "leaked: \$$var=[$val]"
done

echo "== permissions / no plaintext left behind =="
check "all blobs 600" "0" "$(find "$SECRETS_DIR" -name '*.age' ! -perm 600 | wc -l)"
if grep -rIl 'ghp_abc123' "$SECRETS_DIR" 2>/dev/null | grep -q .; then
    bad "plaintext found in store"
else ok "no plaintext in store"; fi

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
