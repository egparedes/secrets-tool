#!/bin/sh
# Test suite for secret.sh. Parameterized:
# shellcheck disable=SC2015,SC2016,SC2154  # ok/bad never fail; literal $(id) intentional; val assigned via eval
#   TEST_SHELL   sh interpreter to run the assertions under (default: sh)
#   SECRETS_AGE  backend to pin (default: autodetect)
# The suite itself is POSIX sh and re-execs nothing; the caller picks the shell.

pass=0; fail=0
ok()   { pass=$((pass+1)); printf '  ok   %s\n' "$1"; }
bad()  { fail=$((fail+1)); printf '  FAIL %s\n' "$1"; }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (want [$2] got [$3])"; fi; }

T=$(mktemp -d /tmp/secret-test.XXXXXX)
trap 'rm -rf "$T"' EXIT INT TERM
SECRETS_DIR="$T/store"
SECRETS_IDENTITY="$SECRETS_DIR/identity.txt"
SECRETS_RECIPIENTS="$SECRETS_DIR/recipients.txt"
export SECRETS_DIR SECRETS_IDENTITY SECRETS_RECIPIENTS

# shellcheck disable=SC1090  # path is computed
. "${SECRET_SH:-$(dirname "$0")/../secret.sh}"

printf 'backend: %s\n' "$(_secret_age)"

echo "== init =="
secret init 2>/dev/null
check "store dir mode 700"   "700" "$(stat -c %a "$SECRETS_DIR")"
check "identity mode 600"    "600" "$(stat -c %a "$SECRETS_IDENTITY")"
check "recipients has 1 key" "1"   "$(grep -c '^age1' "$SECRETS_RECIPIENTS")"
secret init >/dev/null 2>&1; check "init refuses to clobber" "1" "$?"

echo "== roundtrip =="
printf 'ghp_abc123\n' | secret enc github
check "simple roundtrip" "ghp_abc123" "$(secret dec github)"

echo "== format-agnostic: dec is verbatim, no parsing =="
printf 'eyJhbGci.eyJzdWIi.SflKxwRJ==\n' | secret enc jwt
check "base64 '==' verbatim" "eyJhbGci.eyJzdWIi.SflKxwRJ==" "$(secret dec jwt)"
printf 'https://u:p@host/x?a=1&b=2\n' | secret enc url
check "'=' chars untouched" "https://u:p@host/x?a=1&b=2" "$(secret dec url)"
printf 'KEY=value\n' | secret enc kv
check "KEY=value not parsed" "KEY=value" "$(secret dec kv)"
printf 'secret\nuser: enrique\nurl: example.com\n' | secret enc passlike
check "pass-style multiline verbatim" "secret
user: enrique
url: example.com" "$(secret dec passlike)"
check "first line via head" "secret" "$(secret dec passlike | head -n 1)"
secret get github >/dev/null 2>&1; check "get subcommand is gone" "2" "$?"

echo "== multiline / binary =="
printf 'A=1\nB=2\nC=3\n' | secret enc multi
check "multiline preserved" "A=1
B=2
C=3" "$(secret dec multi)"
head -c 4096 /dev/urandom > "$T/bin.dat"
secret enc binary < "$T/bin.dat"
secret dec binary > "$T/bin.out"
if cmp -s "$T/bin.dat" "$T/bin.out"; then ok "4KiB binary byte-identical"; else bad "binary roundtrip"; fi

echo "== exit status propagation =="
v=$(secret dec nonexistent 2>/dev/null); check "missing secret rc" "1" "$?"
check "missing secret empty" "" "$v"
secret dec github >/dev/null 2>&1; check "good decrypt rc" "0" "$?"

echo "== integrity =="
cp "$SECRETS_DIR/github.age" "$T/t.age"
printf 'X' | dd of="$SECRETS_DIR/github.age" bs=1 seek=250 conv=notrunc status=none
secret dec github >/dev/null 2>&1
rc=$?
[ "$rc" -ne 0 ] && ok "tampered blob rejected (rc=$rc)" || bad "tampered blob accepted"
cp "$T/t.age" "$SECRETS_DIR/github.age"

echo "== name validation =="
for t_n in "../../etc/passwd" "" "a/b" ".hidden" 'x$(id)' "a;b"; do
    printf 'x\n' | secret enc "$t_n" >/dev/null 2>&1
    [ "$?" = "2" ] && ok "rejected: '$t_n'" || bad "accepted: '$t_n'"
done

echo "== clobber protection =="
printf 'v1\n' | secret enc dup >/dev/null 2>&1
printf 'v2\n' | secret enc dup >/dev/null 2>&1; check "second enc refused" "1" "$?"
check "original intact" "v1" "$(secret dec dup)"
printf 'v2\n' | secret enc -f dup; check "-f overwrites" "v2" "$(secret dec dup)"

echo "== asymmetric: encrypt without the private key =="
mv "$SECRETS_IDENTITY" "$T/id.bak"
printf 'WRITE_ONLY=yes\n' | secret enc writeonly; check "enc with no identity" "0" "$?"
secret dec writeonly >/dev/null 2>&1;             check "dec with no identity" "3" "$?"
mv "$T/id.bak" "$SECRETS_IDENTITY"
check "readable once identity back" "WRITE_ONLY=yes" "$(secret dec writeonly)"

echo "== rekey to a second recipient =="
KG=$(_secret_keygen)
"$KG" -o "$T/id2.txt" 2>/dev/null
"$KG" -y "$T/id2.txt" >> "$SECRETS_RECIPIENTS"
t_before=$(secret dec github)
secret rekey 2>/dev/null; check "rekey rc" "0" "$?"
check "old identity still works" "$t_before" "$(secret dec github)"
AGEBIN=$(_secret_age)
check "new identity works" "$t_before" "$("$AGEBIN" -d -i "$T/id2.txt" "$SECRETS_DIR/github.age")"
check "no stage dirs left" "0" "$(find "$SECRETS_DIR" -name '.rekey.*' | wc -l)"

echo "== rekey is all-or-nothing =="
printf 'corrupt-me\n' > "$SECRETS_DIR/broken.age"
secret rekey >/dev/null 2>&1; check "rekey aborts on bad blob" "1" "$?"
check "github untouched after abort" "$t_before" "$(secret dec github)"
check "no stage dir after abort" "0" "$(find "$SECRETS_DIR" -name '.rekey.*' | wc -l)"
rm -f "$SECRETS_DIR/broken.age"

echo "== armor mode =="
printf 'ARMORED=yes\n' | SECRETS_ARMOR=1 secret enc armored
check "armor header" "1" "$(head -1 "$SECRETS_DIR/armored.age" | grep -c 'BEGIN AGE ENCRYPTED FILE')"
check "armor decrypts" "ARMORED=yes" "$(secret dec armored)"

echo "== ls / rm / recipients / help / dispatcher =="
check "ls finds github" "1" "$(secret ls | grep -cx github)"
check "recipients count" "2" "$(secret recipients | grep -c '^age1')"
yes | secret rm dup >/dev/null 2>&1
check "rm removed it" "0" "$(secret ls | grep -cx dup)"
secret help >/dev/null; check "help rc" "0" "$?"
secret bogus >/dev/null 2>&1; check "unknown subcommand rc" "2" "$?"

echo "== rename =="
printf 'moved\n' | secret enc oldname
secret rename oldname newname; check "rename rc" "0" "$?"
check "old name gone" "0" "$(secret ls | grep -cx oldname)"
check "new name decrypts" "moved" "$(secret dec newname)"
secret rename missing x >/dev/null 2>&1; check "rename missing rc" "1" "$?"
printf 'other\n' | secret enc taken
secret rename newname taken >/dev/null 2>&1; check "rename clobber refused" "1" "$?"
check "clobber target intact" "other" "$(secret dec taken)"
secret rename -f newname taken; check "rename -f rc" "0" "$?"
check "rename -f overwrote" "moved" "$(secret dec taken)"
secret rename taken taken >/dev/null 2>&1; check "self-rename refused" "1" "$?"
secret rename '../x' ok2 >/dev/null 2>&1; check "bad OLD rejected" "2" "$?"
secret rename taken 'a/b' >/dev/null 2>&1; check "bad NEW rejected" "2" "$?"

echo "== completions emit and parse =="
secret completions bash > "$T/c.bash"; check "bash emit rc" "0" "$?"
bash -n "$T/c.bash"; check "bash completion parses" "0" "$?"
secret completions zsh > "$T/c.zsh"; check "zsh emit rc" "0" "$?"
if command -v zsh >/dev/null 2>&1; then
    zsh -n "$T/c.zsh"; check "zsh completion parses" "0" "$?"
fi
secret completions fish > "$T/c.fish"; check "fish emit rc" "0" "$?"
secret completions powershell >/dev/null 2>&1; check "unknown shell rc" "2" "$?"
grep -qw rename "$T/c.bash"; check "bash completes rename" "0" "$?"
grep -qw rename "$T/c.zsh";  check "zsh completes rename" "0" "$?"
grep -qw rename "$T/c.fish"; check "fish completes rename" "0" "$?"

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
