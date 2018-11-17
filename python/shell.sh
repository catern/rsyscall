#!/usr/bin/env bash
set -o nounset -o errexit
tmpdir=$(mktemp -d)
ssh-keygen -b 1024 -q -N '' -C '' -f "$tmpdir/key"
ssh -F /dev/null \
    -o LogLevel=QUIET \
    -o IdentityFile="$tmpdir/key" \
    -o BatchMode=yes \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o ProxyCommand="sshd -i -f /dev/null \
-o HostKey=$tmpdir/key \
-o AuthorizedKeysFile=$tmpdir/key.pub \
-o StrictModes=no \
-o PrintLastLog=no \
-o PrintMotd=no \
"\
    localhost
rm "$tmpdir/key" "$tmpdir/key.pub"
rmdir "$tmpdir"
