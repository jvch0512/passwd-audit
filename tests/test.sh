#!/bin/sh
# Tests for passwd-audit: a table of small files with the rules that must (or must not) fire.
BIN=build/passwd-audit
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
pass=0
fail=0

ok() { pass=$((pass + 1)); }
bad() { fail=$((fail + 1)); echo "FAIL: $1"; }

# fires NAME RULE CONTENT : the rule must appear
fires() {
    printf '%s\n' "$3" > "$T/f"
    if $BIN "$T/f" --tsv 2>/dev/null | cut -f2 | grep -q "^$2\$"; then ok; else bad "$1 ($2 should fire)"; fi
}
# quiet NAME RULE CONTENT : the rule must not appear
quiet() {
    printf '%s\n' "$3" > "$T/f"
    if $BIN "$T/f" --tsv 2>/dev/null | cut -f2 | grep -q "^$2\$"; then bad "$1 ($2 should not fire)"; else ok; fi
}
count() { # count NAME EXPECTED CONTENT : number of findings
    printf '%s\n' "$3" > "$T/f"
    n=$($BIN "$T/f" --tsv 2>/dev/null | head -1 | sed 's/.*, \([0-9]*\) findings/\1/')
    [ "$n" = "$2" ] && ok || bad "$1 (expected $2 findings, got $n)"
}

# passwd rules
fires  "second uid 0"            PWD001 'root:x:0:0:r:/root:/bin/bash
toor:x:0:0:t:/root:/bin/sh'
quiet  "only root is uid 0"      PWD001 'root:x:0:0:r:/root:/bin/bash'
quiet  "uid 0 root only, other"  PWD001 'alice:x:1000:1000:a:/home/a:/bin/bash'
fires  "empty password"          PWD002 'bob::1000:1000:b:/home/b:/bin/bash'
quiet  "x password"              PWD002 'bob:x:1000:1000:b:/home/b:/bin/bash'
fires  "hash in passwd"          PWD003 'bob:$6$s$h:1000:1000:b:/home/b:/bin/bash'
quiet  "locked in passwd (!)"    PWD003 'bob:!:1000:1000:b:/home/b:/bin/bash'
quiet  "star in passwd"          PWD003 'bob:*:1000:1000:b:/home/b:/bin/bash'
fires  "system account shell"    PWD005 'svc:x:500:500:s:/var/svc:/bin/bash'
fires  "system account sh"       PWD005 'svc:x:500:500:s:/var/svc:/bin/sh'
quiet  "system nologin"          PWD005 'svc:x:500:500:s:/var/svc:/usr/sbin/nologin'
quiet  "system false"            PWD005 'svc:x:500:500:s:/var/svc:/bin/false'
quiet  "system sync"             PWD005 'sync:x:4:65534:s:/bin:/bin/sync'
quiet  "root has a shell"        PWD005 'root:x:0:0:r:/root:/bin/bash'
quiet  "normal user with shell"  PWD005 'alice:x:1000:1000:a:/home/a:/bin/bash'
quiet  "empty shell"             PWD005 'svc:x:500:500:s:/var/svc:'
fires  "duplicate uid"           PWD006 'a:x:1000:1000::/h:/bin/bash
b:x:1000:1001::/h:/bin/bash'
quiet  "distinct uids"           PWD006 'a:x:1000:1000::/h:/bin/bash
b:x:1001:1001::/h:/bin/bash'
fires  "duplicate name"          PWD008 'a:x:1000:1000::/h:/bin/bash
a:x:1001:1001::/h:/bin/bash'
quiet  "distinct names"          PWD008 'a:x:1000:1000::/h:/bin/bash
b:x:1001:1001::/h:/bin/bash'
quiet  "prefix name is not dup"  PWD008 'a:x:1000:1000::/h:/bin/bash
ab:x:1001:1001::/h:/bin/bash'

# shadow rules
fires  "md5 hash"                PWD004 'a:$1$salt$hash:19000:0:90:7:::'
fires  "des hash"                PWD004 'a:aBcDeFgHiJkLm:19000:0:90:7:::'
quiet  "sha512 hash"             PWD004 'a:$6$salt$hash:19000:0:90:7:::'
quiet  "yescrypt hash"           PWD004 'a:$y$j9T$salt$hash:19000:0:90:7:::'
quiet  "locked account"          PWD004 'a:!$1$salt$hash:19000:0:90:7:::'
fires  "empty shadow hash"       PWD002 'a::19000:0:90:7:::'
quiet  "star shadow hash"        PWD002 'a:*:19000:0:99999:7:::'
fires  "never expires 99999"     PWD007 'a:$6$s$h:19000:0:99999:7:::'
fires  "never expires empty"     PWD007 'a:$6$s$h:19000:0::7:::'
quiet  "expires in 90 days"      PWD007 'a:$6$s$h:19000:0:90:7:::'
quiet  "locked never expires"    PWD007 'a:!$6$s$h:19000:0:99999:7:::'
quiet  "star never expires"      PWD007 'a:*:19000:0:99999:7:::'

# parsing
fires  "not an entry"            PWD000 'this is not an entry'
fires  "wrong field count"       PWD000 'a:x:1000:1000'
quiet  "comment line"            PWD000 '# a comment'
count  "blank lines ignored"     0 '

root:x:0:0:r:/root:/bin/bash

'
count  "clean passwd"            0 'root:x:0:0:r:/root:/bin/bash
daemon:x:1:1:d:/usr/sbin:/usr/sbin/nologin
alice:x:1000:1000:a:/home/a:/bin/bash'
count  "clean shadow"            0 'root:$6$s$h:19000:0:90:7:::
daemon:*:19000:0:99999:7:::'
count  "empty file"              0 ''
fires  "non-numeric uid is safe" PWD000 'a:x:abc'
quiet  "non-numeric uid, 7 fields" PWD001 'a:x:abc:1000::/h:/bin/bash'
quiet  "huge uid"                PWD001 'a:x:99999999999999:1000::/h:/bin/bash'

# order, labels and line numbers
printf 'a:x:1000:1000::/h:/bin/bash\n\nbob::1001:1001::/h:/bin/bash\n' > "$T/passwd"
out=$($BIN "$T/passwd" --tsv 2>/dev/null)
echo "$out" | grep -q "PWD002	passwd:3	" && ok || bad "label and line number"
echo "$out" | sed -n 2p | cut -f1 | grep -q '^high$' && ok || bad "severity first in tsv"
echo "$out" | head -1 | grep -q '^# 1 files, 1 findings$' && ok || bad "tsv summary line"
$BIN "$T/passwd" 2>/dev/null | head -1 | grep -q '^1 files, 1 findings$' && ok || bad "text summary line"
$BIN "$T/passwd" 2>/dev/null | sed -n 2p | grep -q '^HIGH     PWD002 passwd:3$' && ok || bad "text format"

# hostile input
head -c 100000 /dev/zero | tr '\0' 'a' > "$T/long"
$BIN "$T/long" >/dev/null 2>&1; [ $? -le 1 ] && ok || bad "very long line"
head -c 20000 /dev/urandom > "$T/bin"
$BIN "$T/bin" >/dev/null 2>&1; [ $? -le 1 ] && ok || bad "binary input"
awk 'BEGIN{for(i=0;i<5000;i++) printf "user%d:x:%d:%d::/h:/bin/sh\n", i, 2000+i, 2000+i}' > "$T/many"
$BIN "$T/many" >/dev/null 2>&1; [ $? -le 1 ] && ok || bad "5000 accounts"
awk 'BEGIN{for(i=0;i<3000;i++) printf ":::::::::::::::\n"}' > "$T/colons"
$BIN "$T/colons" >/dev/null 2>&1; [ $? -le 1 ] && ok || bad "only colons"

# fuzz: 3000 random files, the program must exit 0 or 1 and never crash
fz=0
awk 'BEGIN{srand(42); chars=":::abcxyz$!*0123456789/ \n"; for(n=0;n<3000;n++){f=sprintf("'"$T"'/fz%d",n%50); s=""; len=int(rand()*200); for(i=0;i<len;i++) s=s substr(chars,int(rand()*length(chars))+1,1); print s > f; close(f); print f}}' > "$T/list"
while read f; do
    $BIN "$f" --tsv >/dev/null 2>&1
    rc=$?
    [ $rc -le 1 ] || { fz=$((fz + 1)); echo "fuzz crash rc=$rc on $f"; }
done < "$T/list"
[ $fz -eq 0 ] && ok || bad "fuzzing: $fz crashes"

# CLI
$BIN examples/passwd >/dev/null 2>&1; [ $? -eq 0 ] && ok || bad "exit 0 by default"
$BIN examples/passwd --fail-on high >/dev/null 2>&1; [ $? -eq 1 ] && ok || bad "--fail-on high exits 1"
printf 'root:x:0:0:r:/root:/bin/bash\n' > "$T/clean"
$BIN "$T/clean" --fail-on medium >/dev/null 2>&1; [ $? -eq 0 ] && ok || bad "clean file passes --fail-on"
$BIN /no/such/file >/dev/null 2>&1; [ $? -eq 2 ] && ok || bad "missing file exits 2"
$BIN >/dev/null 2>&1; [ $? -eq 2 ] && ok || bad "no args exits 2"
$BIN examples/passwd --bogus >/dev/null 2>&1; [ $? -eq 2 ] && ok || bad "unknown flag exits 2"
$BIN examples/passwd --fail-on nope >/dev/null 2>&1; [ $? -eq 2 ] && ok || bad "bad --fail-on exits 2"
$BIN examples/passwd --fail-on >/dev/null 2>&1; [ $? -eq 2 ] && ok || bad "--fail-on without value exits 2"
$BIN examples/passwd examples/shadow --tsv 2>/dev/null | head -1 | grep -q '^# 2 files, 13 findings$' && ok || bad "two files in one run"

echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
