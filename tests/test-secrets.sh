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

BINDIR=$(cd "$(dirname "$0")/../bin" && pwd)
SECRETS_LIB=${SECRETS_LIB:-$(dirname "$0")/../lib/secrets-lib.sh}
# shellcheck disable=SC1090  # path is computed
. "$SECRETS_LIB"

# Unwrapped identities land in a shared directory (/dev/shm or $TMPDIR), so
# asserting a global count of zero makes these checks hostage to anything
# else on the machine. Compare against the count taken just before instead.
# Unwrapped identities land in a shared directory (/dev/shm or $TMPDIR), so
# a bare count there is hostage to anything else on the machine -- including
# another copy of this suite, whose in-flight identity file is legitimately
# non-empty and would read as one we stranded. Scope every check to files
# created after a marker taken just before the command under test. (This
# still assumes the suite is not run concurrently with itself; CI runs one
# job at a time.)
#
# What must never survive is a file holding key material. An interrupt can
# strand an *empty* one: mktemp creates the file inside a command
# substitution, before the shell can record its name to trap on, and POSIX
# sh cannot close that window -- so -size +0c is the property asserted.
t_idmark() { : > "$T/idmark.$1"; }
t_idnew() {
    find /dev/shm "${TMPDIR:-/tmp}" -maxdepth 1 -name '.secrets-id.*' \
        -newer "$T/idmark.$1" -size +0c 2>/dev/null | wc -l | tr -d ' '
}

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
    secrets rm -f "$t_n" >/dev/null 2>&1
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
t_idmark abort
printf 'corrupt-me\n' > "$STORE/broken.age"
secrets rekey >/dev/null 2>&1; check "rekey aborts on bad blob" "1" "$?"
check "github untouched after abort" "$t_before" "$(secrets dec github)"
check "no stage dir after abort" "0" "$(find "$SECRETS_DIR" -name '.rekey.*' | wc -l)"
check "no identity temporaries after abort" "0" "$(t_idnew abort)"
rm -f "$STORE/broken.age"

echo "== rekey's install pass rolls back =="
# Staging is only half of all-or-nothing; installing is the other half. Root
# ignores directory permissions, so this can only be provoked as a normal
# user -- which is what CI runs as.
if [ "$(id -u)" -ne 0 ]; then
    t_rb="$T/rollback"
    ( SECRETS_DIR="$t_rb"; secrets init ) >/dev/null 2>&1
    printf 'A\n' | ( SECRETS_DIR="$t_rb"; secrets enc a )
    printf 'B\n' | ( SECRETS_DIR="$t_rb"; secrets enc d/b )
    printf 'Z\n' | ( SECRETS_DIR="$t_rb"; secrets enc z )
    "$KG" -y "$T/id2.txt" >> "$t_rb/store/.age-recipients"
    chmod 500 "$t_rb/store/d"
    ( SECRETS_DIR="$t_rb"; secrets rekey ) >/dev/null 2>&1
    check "rekey fails when an entry cannot be installed" "1" "$?"
    chmod 700 "$t_rb/store/d"
    check "no entry was left rekeyed" "0" \
        "$("$AGEBIN" -d -i "$T/id2.txt" "$t_rb/store/a.age" >/dev/null 2>&1; \
           echo $? | grep -c '^0$')"
    check "every entry still decrypts" "A B Z" \
        "$( SECRETS_DIR="$t_rb"; printf '%s %s %s' "$(secrets dec a)" \
            "$(secrets dec d/b)" "$(secrets dec z)" )"
    check "no stage dir left after the rollback" "0" \
        "$(find "$t_rb" -name '.rekey.*' | wc -l)"
else
    echo "  skip rekey install-rollback checks (running as root)"
fi

echo "== rekey's install pass never lets an entry stop existing =="
# The install pass hard-LINKS each original into the staging tree rather than
# moving it there, so the entry keeps existing at its real path throughout.
# A shim on chmod -- which the library calls unqualified -- makes the install
# fail after the link is in place, which is the branch that would otherwise
# lose the in-flight entry.
t_ln="$T/linkinstall"
mkdir -p "$T/shim"
t_realchmod=$(command -v chmod)
cat > "$T/shim/chmod" <<SHIM
#!/bin/sh
case "\$*" in *ccc*) : > "$T/shim-fired"; echo "chmod: simulated failure" >&2; exit 1 ;; esac
exec $t_realchmod "\$@"
SHIM
chmod 755 "$T/shim/chmod"
( SECRETS_DIR="$t_ln"; secrets init ) >/dev/null 2>&1
for t_n in aaa bbb ccc ddd; do
    printf 'V-%s\n' "$t_n" | ( SECRETS_DIR="$t_ln"; secrets enc "$t_n" )
done
"$KG" -y "$T/id2.txt" >> "$t_ln/store/.age-recipients"
rm -f "$T/shim-fired"
( SECRETS_DIR="$t_ln"; PATH="$T/shim:$PATH"; secrets rekey ) >/dev/null 2>&1
check "rekey fails when an install step fails" "1" "$?"
check "the shim actually fired" "1" "$([ -f "$T/shim-fired" ] && echo 1 || echo 0)"
check "the in-flight entry still exists" "1" \
    "$([ -f "$t_ln/store/ccc.age" ] && echo 1 || echo 0)"
check "every entry still decrypts" "V-aaa V-bbb V-ccc V-ddd" \
    "$( SECRETS_DIR="$t_ln"
        printf '%s %s %s %s' "$(secrets dec aaa)" "$(secrets dec bbb)" \
            "$(secrets dec ccc)" "$(secrets dec ddd)" )"
check "and none was left rekeyed" "0" \
    "$("$AGEBIN" -d -i "$T/id2.txt" "$t_ln/store/aaa.age" >/dev/null 2>&1 && echo 1 || echo 0)"
check "no stage dir left" "0" "$(find "$t_ln" -name '.rekey.*' | wc -l)"

echo "== rekey survives a store with no hard links =="
# $stage is inside the store, so the original is linked aside rather than
# copied. On a filesystem without hard links (FAT, some network mounts) the
# cp fallback has to carry it.
mkdir -p "$T/shimln"
cat > "$T/shimln/ln" <<SHIM
#!/bin/sh
: > "$T/ln-refused"
exit 1
SHIM
chmod 755 "$T/shimln/ln"
t_nl="$T/nolinks"
( SECRETS_DIR="$t_nl"; secrets init ) >/dev/null 2>&1
printf 'NL\n' | ( SECRETS_DIR="$t_nl"; secrets enc solo )
"$KG" -y "$T/id2.txt" >> "$t_nl/store/.age-recipients"
rm -f "$T/ln-refused"
( SECRETS_DIR="$t_nl"; PATH="$T/shimln:$PATH"; secrets rekey ) >/dev/null 2>&1
check "rekey succeeds without hard links" "0" "$?"
check "the ln refusal actually happened" "1" \
    "$([ -f "$T/ln-refused" ] && echo 1 || echo 0)"
check "the entry still decrypts" "NL" "$( SECRETS_DIR="$t_nl"; secrets dec solo )"
check "and it was rekeyed" "NL" "$("$AGEBIN" -d -i "$T/id2.txt" "$t_nl/store/solo.age")"

echo "== a rollback that itself fails keeps the originals and says so =="
# The highest-consequence branch in the file: if the restore cannot run, the
# staging tree holds the only copy of the old blobs and must NOT be deleted.
mkdir -p "$T/shimmv"
cat > "$T/shimmv/mv" <<SHIM
#!/bin/sh
case "\$*" in
    *.orig/*)  : > "$T/restore-blocked"; echo "mv: simulated restore failure" >&2; exit 1 ;;
    *ccc*)     echo "mv: simulated install failure" >&2; exit 1 ;;
esac
exec $(command -v mv) "\$@"
SHIM
chmod 755 "$T/shimmv/mv"
t_fr="$T/failedrollback"
( SECRETS_DIR="$t_fr"; secrets init ) >/dev/null 2>&1
for t_n in aaa bbb ccc; do
    printf 'V-%s\n' "$t_n" | ( SECRETS_DIR="$t_fr"; secrets enc "$t_n" )
done
"$KG" -y "$T/id2.txt" >> "$t_fr/store/.age-recipients"
rm -f "$T/restore-blocked"
t_err=$( SECRETS_DIR="$t_fr"; PATH="$T/shimmv:$PATH"; secrets rekey 2>&1 >/dev/null )
check "rekey fails" "1" "$?"
check "the restore really was blocked" "1" \
    "$([ -f "$T/restore-blocked" ] && echo 1 || echo 0)"
printf '%s' "$t_err" | grep -q 'could not restore'
check "it names the entries it could not restore" "0" "$?"
printf '%s' "$t_err" | grep -q 'could not roll back'
check "and does not claim nothing changed" "0" "$?"
printf '%s' "$t_err" | grep -q 'nothing changed'
check "the reassuring message is withheld" "1" "$?"
check "the staging tree is KEPT, not deleted" "1" \
    "$(find "$t_fr" -name '.rekey.*' -type d | wc -l | tr -d ' ')"
check "and it still holds the originals" "1" \
    "$(find "$t_fr" -path '*/.orig/aaa.age' | wc -l | tr -d ' ')"
check "every entry is still decryptable from somewhere" "V-aaa V-bbb V-ccc" \
    "$( SECRETS_DIR="$t_fr"
        printf '%s %s %s' \
            "$("$AGEBIN" -d -i "$t_fr/identities" "$(find "$t_fr" -path '*/.orig/aaa.age')")" \
            "$("$AGEBIN" -d -i "$t_fr/identities" "$(find "$t_fr" -path '*/.orig/bbb.age')")" \
            "$(secrets dec ccc)" )"
rm -rf "$t_fr"

echo "== an interrupted rekey must not destroy an entry =="
# Regression test for a rollback that moved originals out of the store: a
# signal then deleted the staging tree while an entry lived only inside it.
# Needs a pty, so that Ctrl-C reaches the whole process group the way a user's
# would -- a backgrounded job has SIGINT ignored on entry and cannot trap it.
if command -v script >/dev/null 2>&1; then
    t_int="$T/interrupt"
    mkdir -p "$T/shim2"
    cat > "$T/shim2/chmod" <<SHIM
#!/bin/sh
case "\$*" in *ccc*) : > "$T/slow-fired"; sleep 12 ;; esac
exec $t_realchmod "\$@"
SHIM
    chmod 755 "$T/shim2/chmod"
    rm -f "$T/slow-fired"
    ( SECRETS_DIR="$t_int"; secrets init ) >/dev/null 2>&1
    for t_n in aaa bbb ccc ddd; do
        printf 'V-%s\n' "$t_n" | ( SECRETS_DIR="$t_int"; secrets enc "$t_n" )
    done
    "$KG" -y "$T/id2.txt" >> "$t_int/store/.age-recipients"
    { sleep 5; printf '\003'; sleep 3; } | script -qec \
        "env SECRETS_DIR=$t_int PATH=$T/shim2:$BINDIR:$PATH secrets rekey" \
        /dev/null > "$T/int-out" 2>&1
    # Without this the check is vacuous: on a slow runner the rekey can
    # finish before the ^C lands, and every assertion below still passes.
    check "the interrupt landed inside the install pass" "1" \
        "$([ -f "$T/slow-fired" ] && echo 1 || echo 0)"
    check "no entry was destroyed by the interrupt" "4" \
        "$(find "$t_int/store" -maxdepth 1 -name '*.age' | wc -l | tr -d ' ')"
    # Interrupted mid-install the store really can be split, and saying
    # "nothing changed" there would be a lie in the direction that matters.
    grep -q 'may be partly rekeyed' "$T/int-out"
    check "it warns the store may be partly rekeyed" "0" "$?"
    check "and all four still decrypt" "V-aaa V-bbb V-ccc V-ddd" \
        "$( SECRETS_DIR="$t_int"
            printf '%s %s %s %s' "$(secrets dec aaa)" "$(secrets dec bbb)" \
                "$(secrets dec ccc)" "$(secrets dec ddd)" )"
else
    echo "  skip interrupted-rekey check (no script(1) pty available)"
fi

echo "== an interrupt while staging must not claim the store changed =="
# Staging writes only inside the staging tree, so "nothing changed" is the
# truth there -- and staging is the likeliest moment to Ctrl-C. Reporting a
# possibly-part-rekeyed store there trains users to ignore the warning; the
# reverse, reporting "nothing changed" mid-install, is an outright lie.
if command -v script >/dev/null 2>&1; then
    mkdir -p "$T/shimage"
    cat > "$T/shimage/slowage" <<SHIM
#!/bin/sh
for a in "\$@"; do
    case \$a in *sss.age) : > "$T/stage-fired"; sleep 12 ;; esac
done
exec $AGEBIN "\$@"
SHIM
    chmod 755 "$T/shimage/slowage"
    t_stg="$T/staginterrupt"
    ( SECRETS_DIR="$t_stg"; secrets init ) >/dev/null 2>&1
    for t_n in ppp sss; do
        printf 'V-%s\n' "$t_n" | ( SECRETS_DIR="$t_stg"; secrets enc "$t_n" )
    done
    "$KG" -y "$T/id2.txt" >> "$t_stg/store/.age-recipients"
    rm -f "$T/stage-fired"
    { sleep 5; printf '\003'; sleep 3; } | script -qec \
        "env SECRETS_DIR=$t_stg SECRETS_AGE=$T/shimage/slowage $BINDIR/secrets rekey" \
        /dev/null > "$T/stg-out" 2>&1
    check "the interrupt landed during staging" "1" \
        "$([ -f "$T/stage-fired" ] && echo 1 || echo 0)"
    grep -q 'nothing changed' "$T/stg-out"
    check "it reports that nothing changed" "0" "$?"
    grep -q 'may be partly rekeyed' "$T/stg-out"
    check "and does not warn of a part-rekeyed store" "1" "$?"
    check "no entry was rekeyed" "0" \
        "$("$AGEBIN" -d -i "$T/id2.txt" "$t_stg/store/ppp.age" >/dev/null 2>&1 && echo 1 || echo 0)"
    check "both entries still decrypt" "V-ppp V-sss" \
        "$( SECRETS_DIR="$t_stg"; printf '%s %s' "$(secrets dec ppp)" "$(secrets dec sss)" )"
else
    echo "  skip staging-interrupt checks (no script(1) pty available)"
fi

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
# The walk must stop at the store root. Without that boundary it climbs into
# $SECRETS_DIR, then /tmp, then / -- so a .age-recipients anyone could drop in
# a parent directory would silently become the encryption recipient set.
printf '# planted\n' > "$SECRETS_DIR/.age-recipients"
check "walk stops at the store root" "$RCP" \
    "$(SECRETS_STORE=$STORE _secrets_recipients_for '')"
check "walk stops at the root from a subdir too" "$STORE/proj/.age-recipients" \
    "$(SECRETS_STORE=$STORE _secrets_recipients_for proj)"
# The store root having its own .age-recipients stops the walk regardless, so
# the boundary is only really exercised by a store that has none: plant one in
# the parent and it must still not be found.
t_empty="$T/emptystore"
mkdir -p "$t_empty/store"
printf '# planted in the parent\n' > "$t_empty/.age-recipients"
check "a store with no recipients finds none, not its parent's" "" \
    "$(SECRETS_STORE=$t_empty/store _secrets_recipients_for '')"
mkdir -p "$t_empty/store/deep/er"
check "nor from a subdirectory of it" "" \
    "$(SECRETS_STORE=$t_empty/store _secrets_recipients_for deep/er)"
rm -f "$SECRETS_DIR/.age-recipients"
printf 'subtree-value\n' | secrets enc proj/key
check "subtree entry readable by the subtree-only key" "subtree-value" \
    "$("$AGEBIN" -d -i "$T/id3.txt" "$STORE/proj/key.age")"
check "subtree entry readable by the store identity" "subtree-value" "$(secrets dec proj/key)"
check "recipients NAME reports the subtree file" \
    "$(cat "$STORE/proj/.age-recipients")" "$(secrets recipients proj/key)"
check "recipients with no arg reports the root file" \
    "$(cat "$RCP")" "$(secrets recipients)"
secrets recipients '' >/dev/null 2>&1
check "recipients rejects an empty name rather than reporting the root" "2" "$?"
secrets recipients '../escape' >/dev/null 2>&1
check "recipients validates the name" "2" "$?"

echo "== rename re-encrypts across a recipients boundary =="
secrets rename proj/key movedout
check "rename out of the subtree rc" "0" "$?"
check "moved entry readable with the store identity" "subtree-value" "$(secrets dec movedout)"
"$AGEBIN" -d -i "$T/id3.txt" "$STORE/movedout.age" >/dev/null 2>&1
check "moved entry no longer readable by the subtree-only key" "1" "$?"
# rename re-encrypts across a recipients boundary, and must keep the entry in
# the format it found it in, exactly as rekey does.
printf 'ARMOVE\n' | SECRETS_ARMOR=1 secrets enc proj/armmove
check "the source is armored" "1" \
    "$(head -n 1 "$STORE/proj/armmove.age" | grep -c 'BEGIN AGE ENCRYPTED FILE')"
secrets rename proj/armmove armmoved
check "rename across the boundary rc" "0" "$?"
check "the renamed entry is still armored" "1" \
    "$(head -n 1 "$STORE/armmoved.age" | grep -c 'BEGIN AGE ENCRYPTED FILE')"
check "and still decrypts" "ARMOVE" "$(secrets dec armmoved)"
secrets rm -f armmoved >/dev/null 2>&1
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
secrets rm -f movedout >/dev/null 2>&1

echo "== rm prunes the directories it empties =="
printf 'x\n' | secrets enc p/q/r
secrets rm -f p/q/r >/dev/null 2>&1
check "p/q/r gone"    "0" "$(secrets ls | grep -cx 'p/q/r')"
check "empty p/q gone" "0" "$([ -d "$STORE/p/q" ] && echo 1 || echo 0)"
check "empty p gone"   "0" "$([ -d "$STORE/p" ] && echo 1 || echo 0)"
check "store itself survives" "1" "$([ -d "$STORE" ] && echo 1 || echo 0)"

echo "== ls must not turn a find failure into a short list =="
# rekey builds its whole work list from `secrets ls`. A pipeline would report
# sort's status, so a directory find cannot walk would come back as a quietly
# short list -- and rekey would report success while leaving entries holding
# a recipient the user believes they revoked. A symlink cycle makes find fail
# for any user, root included.
t_before_ls=$(secrets ls | wc -l)
ln -s cycleb "$STORE/cyclea"
ln -s cyclea "$STORE/cycleb"
secrets ls >/dev/null 2>&1
check "ls reports a find failure" "1" "$?"
secrets ls 2>&1 >/dev/null | grep -q 'cannot list'
check "and says so, rather than printing a short list" "0" "$?"
secrets rekey >/dev/null 2>&1
check "rekey refuses on an unlistable store" "1" "$?"
check "rekey changed nothing" "$t_before" "$(secrets dec github)"
check "no stage dir left after the refusal" "0" \
    "$(find "$SECRETS_DIR" -name '.rekey.*' 2>/dev/null | wc -l)"
rm -f "$STORE/cyclea" "$STORE/cycleb"
check "ls is whole again once the cycle is gone" "$t_before_ls" "$(secrets ls | wc -l)"

echo "== rekey keeps each entry in the format it found it in =="
# pago writes armored entries; rekeying its store must not silently rewrite
# every file to binary, which would be a whole-store diff in the git history
# the README encourages.
printf 'ARM\n' | SECRETS_ARMOR=1 secrets enc armorkeep
printf 'BIN\n' | secrets enc binkeep
secrets rekey >/dev/null 2>&1
check "rekey rc with mixed formats" "0" "$?"
check "the armored entry stays armored" "1" \
    "$(head -n 1 "$STORE/armorkeep.age" | grep -c 'BEGIN AGE ENCRYPTED FILE')"
check "the binary entry stays binary" "1" \
    "$(head -n 1 "$STORE/binkeep.age" | grep -c 'age-encryption.org')"
check "armored entry still decrypts" "ARM" "$(secrets dec armorkeep)"
check "binary entry still decrypts" "BIN" "$(secrets dec binkeep)"
secrets rm -f armorkeep >/dev/null 2>&1
secrets rm -f binkeep >/dev/null 2>&1

echo "== enc leaves no ciphertext behind when it cannot install the result =="
# A name long enough to make the final mv fail with ENAMETOOLONG: the
# ciphertext temp is hidden from `secrets ls`, so a leak here is invisible.
t_long=$(awk 'BEGIN{ s=""; while (length(s) < 300) s = s "a"; print s }')
printf 'v\n' | secrets enc "$t_long" >/dev/null 2>&1
check "enc fails on an unusable name" "1" "$?"
check "and leaves no temp ciphertext" "0" "$(find "$STORE" -name '.tmp.*' | wc -l)"

echo "== armor mode =="
printf 'ARMORED=yes\n' | SECRETS_ARMOR=1 secrets enc armored
check "armor header" "1" "$(head -1 "$STORE/armored.age" | grep -c 'BEGIN AGE ENCRYPTED FILE')"
check "armor decrypts" "ARMORED=yes" "$(secrets dec armored)"

echo "== ls / rm / recipients / help / dispatcher =="
check "ls finds github" "1" "$(secrets ls | grep -cx github)"
check "recipients count" "2" "$(secrets recipients | grep -c '^age1')"
secrets rm -f dup >/dev/null 2>&1
check "rm removed it" "0" "$(secrets ls | grep -cx dup)"
# `rm -i` reads its confirmation from stdin: at EOF it declines and still
# exits 0, so an unattended `secrets rm` used to report success having
# deleted nothing. Off a terminal it must refuse instead of guessing.
printf 'keepme\n' | secrets enc keepme
secrets rm keepme </dev/null >/dev/null 2>&1
check "rm without a terminal refuses" "1" "$?"
check "and the secret survives" "1" "$(secrets ls | grep -cx keepme)"
secrets rm keepme </dev/null 2>&1 | grep -q 'secrets rm -f'
check "its message names the -f fix" "0" "$?"
secrets rm -f keepme
check "rm -f rc" "0" "$?"
check "rm -f removed it" "0" "$(secrets ls | grep -cx keepme)"
secrets rm -f nosuch >/dev/null 2>&1
check "rm -f of a missing secret still fails" "1" "$?"
secrets rm -f '../escape' >/dev/null 2>&1
check "rm -f still validates the name" "2" "$?"
# The interactive branch needs a terminal, so it needs a pty.
if command -v script >/dev/null 2>&1; then
    printf 'yesplease\n' | secrets enc promptyes
    printf 'y\n' | script -qec \
        "env SECRETS_DIR=$SECRETS_DIR $BINDIR/secrets rm promptyes" /dev/null \
        >/dev/null 2>&1
    check "answering y at the prompt deletes" "0" "$(secrets ls | grep -cx promptyes)"
    printf 'nothanks\n' | secrets enc promptno
    printf 'n\n' | script -qec \
        "env SECRETS_DIR=$SECRETS_DIR $BINDIR/secrets rm promptno" /dev/null \
        >/dev/null 2>&1
    # `rm -i` exits 0 when the user declines, so the status has to come from
    # checking the file is actually gone -- not from rm.
    check "declining at the prompt fails, not succeeds" "1" "$?"
    check "declining at the prompt keeps it" "1" "$(secrets ls | grep -cx promptno)"
    check "and it still decrypts" "nothanks" "$(secrets dec promptno)"
    secrets rm -f promptno >/dev/null 2>&1
else
    echo "  skip rm prompt checks (no script(1) pty available)"
fi
# rm must not report success when the file is still there afterwards. Root
# ignores the directory permission this turns on.
if [ "$(id -u)" -ne 0 ]; then
    t_ro="$T/readonly"
    ( SECRETS_DIR="$t_ro"; secrets init ) >/dev/null 2>&1
    printf 'stuck\n' | ( SECRETS_DIR="$t_ro"; secrets enc stuck )
    chmod 500 "$t_ro/store"
    ( SECRETS_DIR="$t_ro"; secrets rm -f stuck ) >/dev/null 2>&1
    check "rm -f fails when the file cannot be removed" "1" "$?"
    chmod 700 "$t_ro/store"
    check "and the secret is still there" "stuck" "$( SECRETS_DIR="$t_ro"; secrets dec stuck )"
else
    echo "  skip rm-cannot-remove check (running as root)"
fi
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
secrets rm -f from-passage >/dev/null 2>&1
secrets rm -f nested/by/passage/entry >/dev/null 2>&1

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
    t_idmark pago
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
    check "no decrypted identity left behind" "0" "$(t_idnew pago)"
    # Interrupting at the passphrase prompt must not strand the unwrapped
    # identity: the file exists during that whole wait, and the caller's trap
    # cannot cover it ($idf is still empty until the substitution returns).
    G2="$T/pago2"
    mkdir -p "$G2/store"
    cp "$T/id.enc" "$G2/identities"
    "$KG" -y "$T/id2.txt" > "$G2/store/.age-recipients"
    printf 'v\n' | ( SECRETS_DIR="$G2"; secrets enc svc2 )
    t_idmark intr
    { sleep 3; printf '\003'; sleep 2; } | script -qec \
        "env SECRETS_DIR=$G2 $BINDIR/secrets dec svc2" /dev/null >/dev/null 2>&1
    check "an interrupt at the passphrase prompt strands no key material" "0" \
        "$(t_idnew intr)"
else
    echo "  skip pago encrypted-identities checks (no script(1) pty available)"
fi

echo "== an unmatched glob must not be fatal (zsh NO_MATCH) =="
# Every subcommand runs the legacy guard, which used to glob $SECRETS_DIR/*.age.
t_fresh="$T/fresh"
( SECRETS_DIR="$t_fresh"; secrets init ) >/dev/null 2>&1
check "init works on a store that does not exist yet" "0" "$?"
check "and it really created the store" "1" \
    "$([ -d "$t_fresh/store" ] && [ -f "$t_fresh/identities" ] && echo 1)"
( SECRETS_DIR="$t_fresh"; secrets ls ) >/dev/null 2>&1
check "ls on an empty store" "0" "$?"
# a legacy store holding the key files but no blobs at all
t_part="$T/partial"
mkdir -p "$t_part"
cp "$ID" "$t_part/identity.txt"
"$KG" -y "$t_part/identity.txt" > "$t_part/recipients.txt"
( SECRETS_DIR="$t_part"; secrets ls ) >/dev/null 2>&1
check "a blobless legacy store is still refused" "4" "$?"
( SECRETS_DIR="$t_part"; secrets migrate ) >/dev/null 2>&1
check "migrating a blobless legacy store" "0" "$?"
check "its identity moved" "1" "$([ -f "$t_part/identities" ] && echo 1)"
check "its recipients moved" "1" "$([ -f "$t_part/store/.age-recipients" ] && echo 1)"
check "no migrate scratch file left" "0" \
    "$(find "$t_part" -name '.migrate.list' | wc -l)"
# a legacy store detectable only by its blobs -- someone whose identity and
# recipients live elsewhere via SECRETS_IDENTITY/SECRETS_RECIPIENTS
t_blob="$T/bloblegacy"
mkdir -p "$t_blob"
"$AGEBIN" -e -R "$RCP" -o "$t_blob/solo.age" <<'EOF'
blob-only
EOF
( SECRETS_DIR="$t_blob"; secrets ls ) >/dev/null 2>&1
check "a blob-only legacy store is refused" "4" "$?"
( SECRETS_DIR="$t_blob"; secrets migrate ) >/dev/null 2>&1
check "and migrates" "0" "$?"
check "its blob moved into store/" "1" "$([ -f "$t_blob/store/solo.age" ] && echo 1)"
( SECRETS_DIR="$t_blob"; secrets ls ) >/dev/null 2>&1
check "the guard stops firing once migrated" "0" "$?"
# a half-migrated store must keep being refused, not look empty and healthy
printf 'x\n' > "$t_blob/leftover.age"
( SECRETS_DIR="$t_blob"; secrets ls ) >/dev/null 2>&1
check "a half-migrated store is still refused" "4" "$?"
rm -f "$t_blob/leftover.age"

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
( SECRETS_DIR="$L"; secrets ls ) 2>&1 | grep -q 'identity.txt'
check "the refusal lists the files it found" "0" "$?"
( SECRETS_DIR="$L"; secrets ls ) 2>&1 | grep -q 'old.age'
check "including the legacy blobs" "0" "$?"
( SECRETS_DIR="$L"; secrets migrate ) >/dev/null 2>&1
check "migrate rc" "0" "$?"
check "blob moved into store/" "1" "$([ -f "$L/store/old.age" ] && echo 1)"
check "identity.txt -> identities" "1" "$([ -f "$L/identities" ] && echo 1)"
check "recipients.txt -> store/.age-recipients" "1" \
    "$([ -f "$L/store/.age-recipients" ] && echo 1)"
check "migrated secret decrypts" "legacy-value" "$( SECRETS_DIR="$L"; secrets dec old )"
( SECRETS_DIR="$L"; secrets migrate ) >/dev/null 2>&1
check "migrate refuses to run twice" "1" "$?"

echo "== a configured destination is not a leftover to migrate =="
# SECRETS_IDENTITY may legitimately name $SECRETS_DIR/identity.txt, and
# SECRETS_RECIPIENTS may name recipients.txt. Treating those as pre-0.2
# leftovers locked the store out permanently, with migrate comparing a path
# to itself ("both X and X exist") and never able to resolve it.
t_cfg="$T/configured"
mkdir -p "$t_cfg"
t_cfgenv() { export SECRETS_DIR="$t_cfg" SECRETS_IDENTITY="$t_cfg/identity.txt" \
    SECRETS_RECIPIENTS="$t_cfg/recipients.txt"; }
( t_cfgenv; secrets init ) >/dev/null 2>&1
printf 'tok\n' | ( t_cfgenv; secrets enc one )
( t_cfgenv; secrets ls ) >/dev/null 2>&1
check "the guard ignores a configured identity.txt" "0" "$?"
check "and the store works" "tok" \
    "$( t_cfgenv; secrets dec one )"
# The refusal in migrate has to be destination-aware too, not just the guard:
# with a genuine leftover present migrate does run, reaches that refusal, and
# without the check would report "both X and X exist" and brick the store.
# this store pins SECRETS_RECIPIENTS, so its keys are in recipients.txt
"$AGEBIN" -e -R "$t_cfg/recipients.txt" -o "$t_cfg/leftover.age" <<'EOF'
leftover-value
EOF
( t_cfgenv; secrets ls ) >/dev/null 2>&1
check "a real leftover still trips the guard" "4" "$?"
( t_cfgenv; secrets migrate ) >/dev/null 2>&1
check "migrate completes despite the configured identity.txt" "0" "$?"
check "the leftover migrated" "leftover-value" "$( t_cfgenv; secrets dec leftover )"
check "and the configured identity is untouched" "1" \
    "$(grep -c 'AGE-SECRET-KEY' "$t_cfg/identity.txt")"
( t_cfgenv; secrets ls ) >/dev/null 2>&1
check "the store opens afterwards" "0" "$?"

# A top-level *.age that IS the identity must never be filed as an entry:
# migrate would move the live private key into the store, in plaintext, and
# report success -- into the directory the README says holds only ciphertext.
t_ka="$T/keyasage"
mkdir -p "$t_ka"
t_kaenv() { export SECRETS_DIR="$t_ka" SECRETS_IDENTITY="$t_ka/identities.age"; }
( t_kaenv; secrets init ) >/dev/null 2>&1
"$AGEBIN" -e -R "$t_ka/store/.age-recipients" -o "$t_ka/legacy.age" <<'EOF'
legacy-value
EOF
( t_kaenv; secrets migrate ) >/dev/null 2>&1
check "migrate rc with the identity named *.age" "0" "$?"
check "the private key stayed out of the store" "0" \
    "$(grep -c 'AGE-SECRET-KEY-' "$t_ka/store/identities.age" 2>/dev/null || echo 0)"
check "and is not listed as an entry" "0" \
    "$( t_kaenv; secrets ls | grep -cx identities )"
check "the real legacy blob did migrate" "legacy-value" \
    "$( t_kaenv; secrets dec legacy )"

echo "== a configured path is recognised however it is spelled =="
# The destination check compares canonical paths, not strings: a trailing
# slash on SECRETS_DIR spells the same file two ways, and a string compare
# missed it -- filing the live private key in the store as an entry.
t_sl="$T/slash"
mkdir -p "$t_sl"
t_slenv() { export SECRETS_DIR="$t_sl/" SECRETS_IDENTITY="$t_sl//identities.age"; }
( t_slenv; secrets init ) >/dev/null 2>&1
"$AGEBIN" -e -R "$t_sl/store/.age-recipients" -o "$t_sl/genuine.age" <<'EOF'
genuine
EOF
( t_slenv; secrets migrate ) >/dev/null 2>&1
check "migrate rc with a trailing-slash SECRETS_DIR" "0" "$?"
check "the private key stayed out of the store" "0" \
    "$(grep -rl 'AGE-SECRET-KEY-' "$t_sl/store" 2>/dev/null | wc -l | tr -d ' ')"
check "and only the real blob was migrated" "genuine" "$( t_slenv; secrets dec genuine )"

# the same skip has to apply to SECRETS_RECIPIENTS
t_rs="$T/rcpskip"
mkdir -p "$t_rs/store"
t_rsenv() { export SECRETS_DIR="$t_rs" SECRETS_RECIPIENTS="$t_rs/keys.age"; }
"$KG" -y "$ID" > "$t_rs/keys.age"
( t_rsenv; secrets ls ) >/dev/null 2>&1
check "a configured SECRETS_RECIPIENTS is not a leftover" "0" "$?"

# a symlinked base directory must still be scanned, as _secrets_ls does
t_sy="$T/symbase"
mkdir -p "$t_sy/real"
ln -s "$t_sy/real" "$t_sy/link"
cp "$ID" "$t_sy/real/identity.txt"
"$KG" -y "$t_sy/real/identity.txt" > "$t_sy/real/recipients.txt"
"$AGEBIN" -e -R "$t_sy/real/recipients.txt" -o "$t_sy/real/viasym.age" <<'EOF'
via-symlink
EOF
( SECRETS_DIR="$t_sy/link"; secrets ls ) >/dev/null 2>&1
check "a symlinked base dir is still scanned" "4" "$?"
( SECRETS_DIR="$t_sy/link"; secrets migrate ) >/dev/null 2>&1
check "and migrates" "0" "$?"
check "its blob came across" "via-symlink" "$( SECRETS_DIR="$t_sy/link"; secrets dec viasym )"

echo "== identity.txt symlinked to the real identity is not a leftover =="
# _secrets_same_file's inode fallback is what recognises this: the two paths
# canonicalise differently (the symlink's own name is the final component),
# so without it the guard calls identity.txt a pre-0.2 leftover and migrate
# refuses with "both X and Y exist" -- bricking a perfectly good store.
t_st="$T/symtxt"
( SECRETS_DIR="$t_st"; secrets init ) >/dev/null 2>&1
printf 'sv\n' | ( SECRETS_DIR="$t_st"; secrets enc one )
ln -s identities "$t_st/identity.txt"
check "the two paths really do canonicalise differently" "1" \
    "$( a=$(_secrets_canon "$t_st/identity.txt"); b=$(_secrets_canon "$t_st/identities")
        [ "$a" = "$b" ] && echo 0 || echo 1 )"
( SECRETS_DIR="$t_st"; secrets ls ) >/dev/null 2>&1
check "a symlinked identity.txt does not trip the guard" "0" "$?"
check "and the store still works" "sv" "$( SECRETS_DIR="$t_st"; secrets dec one )"
( SECRETS_DIR="$t_st"; secrets migrate ) >/dev/null 2>&1
check "migrate says there is nothing to do" "1" "$?"

echo "== a symlinked configured path is still recognised =="
# _secrets_canon resolves a path's directory but not its final component, so
# a symlink sitting beside its target reads as two paths -- and find -L lists
# both. Without an inode comparison migrate files the live private key in the
# store as an entry, the same consequence as the trailing-slash bug.
t_sl2="$T/symid"
mkdir -p "$t_sl2/store"
t_sl2env() { export SECRETS_DIR="$t_sl2" SECRETS_IDENTITY="$t_sl2/id-link.age"; }
"$KG" -o "$t_sl2/real-id.age" 2>/dev/null
ln -s real-id.age "$t_sl2/id-link.age"
"$KG" -y "$t_sl2/real-id.age" > "$t_sl2/store/.age-recipients"
"$AGEBIN" -e -R "$t_sl2/store/.age-recipients" -o "$t_sl2/blob.age" <<'EOF'
blob-value
EOF
check "find -L really does list both spellings" "2" \
    "$(find -L "$t_sl2" -maxdepth 1 -type f -name '*id*.age' | wc -l | tr -d ' ')"
( t_sl2env; secrets migrate ) >/dev/null 2>&1
check "migrate rc with a symlinked identity" "0" "$?"
check "the private key stayed out of the store" "0" \
    "$(grep -rl 'AGE-SECRET-KEY-' "$t_sl2/store" 2>/dev/null | wc -l | tr -d ' ')"
check "and is not listed as an entry" "0" \
    "$( t_sl2env; secrets ls | grep -cx 'real-id' )"
check "the real blob migrated and decrypts" "blob-value" "$( t_sl2env; secrets dec blob )"

echo "== every way a blob can alias the identity is recognised =="
# The inode comparison is gated on a cheap check for whether aliasing is even
# possible, so each branch of that gate needs its own case: a test that
# happens to satisfy two of them proves nothing about either.

# (a) the configured path is itself a symlink, and no blob is one
t_a1="$T/alias-idsym"
mkdir -p "$t_a1/store"
t_a1env() { export SECRETS_DIR="$t_a1" SECRETS_IDENTITY="$t_a1/idlink"; }
"$KG" -o "$t_a1/real-id.age" 2>/dev/null
ln -s real-id.age "$t_a1/idlink"
"$KG" -y "$t_a1/real-id.age" > "$t_a1/store/.age-recipients"
"$AGEBIN" -e -R "$t_a1/store/.age-recipients" -o "$t_a1/keep1.age" <<'EOF'
keep-one
EOF
check "(a) no blob is a symlink" "0" \
    "$(find "$t_a1" -maxdepth 1 -type l -name '*.age' | wc -l | tr -d ' ')"
( t_a1env; secrets migrate ) >/dev/null 2>&1
check "(a) migrate rc" "0" "$?"
check "(a) no key in the store" "0" \
    "$(grep -rl 'AGE-SECRET-KEY-' "$t_a1/store" 2>/dev/null | wc -l | tr -d ' ')"
check "(a) the real blob migrated" "keep-one" "$( t_a1env; secrets dec keep1 )"

# (b) the configured path is a plain file, and a blob is an absolute symlink
#     to it -- only the blob scan can see this one
t_a2="$T/alias-blobsym"
mkdir -p "$t_a2/store"
t_a2env() { export SECRETS_DIR="$t_a2" SECRETS_IDENTITY="$t_a2/identities"; }
"$KG" -o "$t_a2/identities" 2>/dev/null
"$KG" -y "$t_a2/identities" > "$t_a2/store/.age-recipients"
ln -s "$t_a2/identities" "$t_a2/alias.age"
"$AGEBIN" -e -R "$t_a2/store/.age-recipients" -o "$t_a2/keep2.age" <<'EOF'
keep-two
EOF
check "(b) the configured path is not a symlink" "0" \
    "$([ -h "$t_a2/identities" ] && echo 1 || echo 0)"
( t_a2env; secrets migrate ) >/dev/null 2>&1
check "(b) migrate rc" "0" "$?"
check "(b) no key in the store" "0" \
    "$(grep -rl 'AGE-SECRET-KEY-' "$t_a2/store" 2>/dev/null | wc -l | tr -d ' ')"
check "(b) the key is not listed as an entry" "0" "$( t_a2env; secrets ls | grep -cx alias )"
check "(b) the real blob migrated" "keep-two" "$( t_a2env; secrets dec keep2 )"

# (c) a hard link, with no symlink anywhere -- `ln`, cp -l, rsync
#     --link-dest, a dedup pass
t_a3="$T/alias-hardlink"
mkdir -p "$t_a3/store"
t_a3env() { export SECRETS_DIR="$t_a3" SECRETS_IDENTITY="$t_a3/identities.age"; }
"$KG" -o "$t_a3/identities.age" 2>/dev/null
"$KG" -y "$t_a3/identities.age" > "$t_a3/store/.age-recipients"
ln "$t_a3/identities.age" "$t_a3/backup.age"
"$AGEBIN" -e -R "$t_a3/store/.age-recipients" -o "$t_a3/keep3.age" <<'EOF'
keep-three
EOF
check "(c) there is no symlink to find" "0" \
    "$(find "$t_a3" -maxdepth 1 -type l -name '*.age' | wc -l | tr -d ' ')"
check "(c) but the link count betrays it" "2" \
    "$(find "$t_a3" -maxdepth 1 -type f -name '*.age' -links +1 | wc -l | tr -d ' ')"
( t_a3env; secrets migrate ) >/dev/null 2>&1
check "(c) migrate rc" "0" "$?"
check "(c) no key in the store" "0" \
    "$(grep -rl 'AGE-SECRET-KEY-' "$t_a3/store" 2>/dev/null | wc -l | tr -d ' ')"
check "(c) the key is not listed as an entry" "0" "$( t_a3env; secrets ls | grep -cx backup )"
check "(c) the real blob migrated" "keep-three" "$( t_a3env; secrets dec keep3 )"

echo "== an inode number alone is not proof of identity =="
# Inode numbers are unique only within a filesystem: two fresh tmpfs both
# hand out inode 2. Without a device comparison a genuine secret matches the
# identity by accident and is silently skipped, leaving the store reporting
# empty. Needs mount privileges, so it only runs where those exist.
t_mnt="$T/mounts"
mkdir -p "$t_mnt/one" "$t_mnt/two"
if mount -t tmpfs -o size=1m tmpfs "$t_mnt/one" 2>/dev/null &&
   mount -t tmpfs -o size=1m tmpfs "$t_mnt/two" 2>/dev/null; then
    : > "$t_mnt/one/blob.age"
    : > "$t_mnt/two/identities"
    check "the two inodes really do collide" "0" \
        "$( a=$(_secrets_inode "$t_mnt/one/blob.age")
            b=$(_secrets_inode "$t_mnt/two/identities")
            [ "$a" = "$b" ] && echo 0 || echo 1 )"
    check "and df's source name alone does not separate them" "0" \
        "$( a=$(df -P -- "$t_mnt/one/blob.age" | tail -n 1 | cut -d' ' -f1)
            b=$(df -P -- "$t_mnt/two/identities" | tail -n 1 | cut -d' ' -f1)
            [ "$a" = "$b" ] && echo 0 || echo 1 )"
    _secrets_same_file "$t_mnt/one/blob.age" "$t_mnt/two/identities"
    check "colliding inodes on different filesystems are not one file" "1" "$?"
    ln "$t_mnt/one/blob.age" "$t_mnt/one/hard.age"
    _secrets_same_file "$t_mnt/one/blob.age" "$t_mnt/one/hard.age"
    check "but a hard link on one filesystem still is" "0" "$?"
    umount "$t_mnt/one" 2>/dev/null
    umount "$t_mnt/two" 2>/dev/null
else
    echo "  skip colliding-inode checks (mount not permitted)"
fi

echo "== canonicalisation resolves a symlinked directory =="
# _secrets_canon's `cd -P` is what makes a path reached through a symlinked
# directory compare equal to the same file reached directly.
t_cd="$T/canondir"
mkdir -p "$t_cd/real/store"
ln -s "$t_cd/real" "$t_cd/link"
t_cdenv() { export SECRETS_DIR="$t_cd/link" SECRETS_IDENTITY="$t_cd/real/identities.age"; }
"$KG" -o "$t_cd/real/identities.age" 2>/dev/null
"$KG" -y "$t_cd/real/identities.age" > "$t_cd/real/store/.age-recipients"
"$AGEBIN" -e -R "$t_cd/real/store/.age-recipients" -o "$t_cd/real/keep4.age" <<'EOF'
keep-four
EOF
check "two spellings of one file canonicalise the same" "0" \
    "$( a=$(_secrets_canon "$t_cd/link/identities.age")
        b=$(_secrets_canon "$t_cd/real/identities.age")
        [ "$a" = "$b" ] && echo 0 || echo 1 )"
( t_cdenv; secrets migrate ) >/dev/null 2>&1
check "migrate through the symlinked directory" "0" "$?"
check "no key in the store" "0" \
    "$(grep -rl 'AGE-SECRET-KEY-' "$t_cd/real/store" 2>/dev/null | wc -l | tr -d ' ')"
check "the real blob migrated" "keep-four" "$( t_cdenv; secrets dec keep4 )"

echo "== a base directory that cannot be scanned is refused, not opened =="
# Masking find's status here recreates exactly the "empty and healthy" store
# the backstop exists to prevent. Root ignores the permission, so this needs
# an ordinary user.
if [ "$(id -u)" -ne 0 ]; then
    t_ur="$T/unreadable"
    mkdir -p "$t_ur"
    cp "$ID" "$t_ur/identity.txt"
    "$KG" -y "$t_ur/identity.txt" > "$t_ur/recipients.txt"
    "$AGEBIN" -e -R "$t_ur/recipients.txt" -o "$t_ur/hidden.age" <<'EOF'
hidden
EOF
    # 333, not 733: the owner needs read stripped too, and this block runs
    # as the user that owns the directory.
    chmod 333 "$t_ur"
    ( SECRETS_DIR="$t_ur"; secrets ls ) >/dev/null 2>&1
    check "an unscannable base dir does not report an empty store" "4" "$?"
    ( SECRETS_DIR="$t_ur"; secrets migrate ) >/dev/null 2>&1
    check "and migrate refuses rather than moving nothing" "1" "$?"
    chmod 755 "$t_ur"
    check "the blob was never stranded" "1" \
        "$([ -f "$t_ur/hidden.age" ] && echo 1 || echo 0)"

    # The guard must fail CLOSED when it cannot scan. This needs a store
    # whose only legacy artifacts are blobs: with identity.txt or
    # recipients.txt present those checks fire first and mask the blob scan
    # entirely, so the fail-open direction would look fine.
    t_bo="$T/blobonly"
    mkdir -p "$t_bo"
    "$AGEBIN" -e -R "$RCP" -o "$t_bo/lone.age" <<'EOF'
lone
EOF
    chmod 333 "$t_bo"
    ( SECRETS_DIR="$t_bo"; secrets ls ) >/dev/null 2>&1
    check "an unscannable blob-only store is refused, not reported empty" "4" "$?"
    ( SECRETS_DIR="$t_bo"; secrets ls ) 2>&1 | grep -q 'cannot list'
    check "and says why" "0" "$?"
    chmod 755 "$t_bo"
    check "its blob is still there" "1" \
        "$([ -f "$t_bo/lone.age" ] && echo 1 || echo 0)"
    check "and the store opens once it is readable again" "4" \
        "$( SECRETS_DIR="$t_ur"; secrets ls >/dev/null 2>&1; echo $? )"
else
    echo "  skip unscannable-base-dir checks (running as root)"
fi

echo "== migrate's backstop catches an artifact appearing mid-run =="
# A *.age dropped into $SECRETS_DIR while migrate runs would otherwise leave
# the store silently locked out at exit 0. Simulated with an mv shim rather
# than a race, so it is deterministic.
mkdir -p "$T/shimlate"
cat > "$T/shimlate/mv" <<SHIM
#!/bin/sh
$(command -v mv) "\$@" || exit 1
[ -f "\$LATE_DIR/late.age" ] || printf 'x\n' > "\$LATE_DIR/late.age"
SHIM
chmod 755 "$T/shimlate/mv"
t_late="$T/lateartifact"
mkdir -p "$t_late"
cp "$ID" "$t_late/identity.txt"
"$KG" -y "$t_late/identity.txt" > "$t_late/recipients.txt"
"$AGEBIN" -e -R "$t_late/recipients.txt" -o "$t_late/first.age" <<'EOF'
first
EOF
t_err=$( SECRETS_DIR="$t_late"; LATE_DIR="$t_late"; export LATE_DIR
         PATH="$T/shimlate:$PATH"; secrets migrate 2>&1 >/dev/null )
check "migrate fails when an artifact appears mid-run" "1" "$?"
printf '%s' "$t_err" | grep -q 'migration incomplete'
check "and says the migration is incomplete" "0" "$?"
# The store stays locked out while the late artifact is there, rather than
# looking empty and healthy...
( SECRETS_DIR="$t_late"; secrets ls ) >/dev/null 2>&1
check "the store stays refused until it is dealt with" "4" "$?"
# ...and opens as soon as it is gone, with everything the run did intact.
rm -f "$t_late/late.age"
( SECRETS_DIR="$t_late"; secrets ls ) >/dev/null 2>&1
check "and opens once it is removed" "0" "$?"
check "the migrated entry survived" "first" "$( SECRETS_DIR="$t_late"; secrets dec first )"

echo "== migrate never clobbers, and never claims success while locked out =="
# A stale pre-0.2 blob must not silently replace a live entry of the same
# name -- restoring an old backup beside a migrated store is enough to hit it.
t_cl="$T/clobber"
( SECRETS_DIR="$t_cl"; secrets init ) >/dev/null 2>&1
printf 'LIVE-VALUE\n' | ( SECRETS_DIR="$t_cl"; secrets enc dbpass )
"$AGEBIN" -e -R "$t_cl/store/.age-recipients" -o "$t_cl/dbpass.age" <<'EOF'
STALE-VALUE
EOF
t_err=$( SECRETS_DIR="$t_cl"; secrets migrate 2>&1 >/dev/null )
check "migrate refuses to overwrite a live entry" "1" "$?"
printf '%s' "$t_err" | grep -q 'already exists in the store'
check "and says which entry blocked it" "0" "$?"
rm -f "$t_cl/dbpass.age"
check "the live entry kept its value" "LIVE-VALUE" "$( SECRETS_DIR="$t_cl"; secrets dec dbpass )"

# A stray identity.txt beside a healthy store must not lock it out forever
# with migrate reporting success and changing nothing.
t_id="$T/strayid"
( SECRETS_DIR="$t_id"; secrets init ) >/dev/null 2>&1
printf 'v\n' | ( SECRETS_DIR="$t_id"; secrets enc alpha )
printf 'an old key backup\n' > "$t_id/identity.txt"
( SECRETS_DIR="$t_id"; secrets ls ) >/dev/null 2>&1
check "a stray identity.txt trips the guard" "4" "$?"
t_err=$( SECRETS_DIR="$t_id"; secrets migrate 2>&1 >/dev/null )
check "migrate does not report success for it" "1" "$?"
printf '%s' "$t_err" | grep -q 'identity.txt'
check "and names the file blocking it" "0" "$?"
check "the real identity was not replaced" "1" \
    "$(grep -c 'AGE-SECRET-KEY' "$t_id/identities")"
rm -f "$t_id/identity.txt"
( SECRETS_DIR="$t_id"; secrets ls ) >/dev/null 2>&1
check "removing it unlocks the store" "0" "$?"
check "and the store still works" "v" "$( SECRETS_DIR="$t_id"; secrets dec alpha )"

# same for recipients.txt
t_rc="$T/strayrcp"
( SECRETS_DIR="$t_rc"; secrets init ) >/dev/null 2>&1
printf 'old recipients\n' > "$t_rc/recipients.txt"
( SECRETS_DIR="$t_rc"; secrets migrate ) >/dev/null 2>&1
check "a stray recipients.txt is refused too" "1" "$?"
check "the real recipients file is untouched" "1" \
    "$(grep -c '^age1' "$t_rc/store/.age-recipients")"

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

echo "== bash completion, driven the way bash drives it =="
# Names may now hold '/', ':' and spaces. Build COMP_WORDS the way readline
# would -- bash breaks words at ':' -- and check what the function replies.
cat > "$T/probe.bash" <<'PROBE'
source "$CB"
COMP_WORDS=("$@"); COMP_CWORD=$(( $# - 1 )); COMPREPLY=()
_secrets_complete
printf '%s\n' "${COMPREPLY[*]}"
PROBE
# The completion shells out to `secrets ls`, but this suite drives a sourced
# shell function -- so the probe needs the real CLI on its PATH. $BINDIR is
# resolved at top level: inside a function zsh sets $0 to the function's own
# name, so computing it here would silently yield the wrong directory and
# every probe would come back empty (and two of them would pass vacuously).
t_probe() { CB="$T/c.bash" PATH="$BINDIR:$PATH" bash "$T/probe.bash" "$@"; }

for t_n in 'zz/nested-one' 'zz/nested-two' 'zz:colon' 'zz space'; do
    printf 'v\n' | secrets enc "$t_n"
done
check "completes a nested prefix" "zz/nested-one zz/nested-two" \
    "$(t_probe secrets dec 'zz/n')"
check "completes a nested name uniquely" "zz/nested-one" \
    "$(t_probe secrets dec 'zz/nested-o')"
check "completes past a deeper slash" "zz/nested-one zz/nested-two" \
    "$(t_probe secrets dec 'zz/')"
# ':' is in COMP_WORDBREAKS, so bash hands the word over in pieces and
# replaces only the last: the reply must be trimmed of what is already typed,
# or the line ends up reading 'zz:zz:colon'.
check "trims the colon-broken prefix" "colon" "$(t_probe secrets dec 'zz' ':' 'c')"
check "trims a bare colon-broken prefix" "colon" "$(t_probe secrets dec 'zz' ':' '')"
# a name with a space must come back quoted, or bash inserts two arguments
check "quotes a name containing a space" 'zz\ space' "$(t_probe secrets dec 'zz sp')"
check "matches through an escaped space" 'zz\ space' "$(t_probe secrets dec 'zz\ sp')"
# -f is offered only with no name typed, and never joins the colon prefix
check "offers -f for enc with nothing typed" "1" \
    "$(t_probe secrets enc '' | grep -cw -- '-f')"
check "no -f once a name is being typed" "0" \
    "$(t_probe secrets enc 'zz/n' | grep -cw -- '-f')"
check "-f does not corrupt the colon prefix" "colon" \
    "$(t_probe secrets enc -f 'zz' ':' 'c')"
check "completes names after -f" "zz/nested-one zz/nested-two" \
    "$(t_probe secrets enc -f 'zz/n')"
for t_n in 'zz/nested-one' 'zz/nested-two' 'zz:colon' 'zz space'; do
    secrets rm -f "$t_n" >/dev/null 2>&1
done

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
           bin dir sub idf rf list legacy found armor done_list failed_at; do
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
