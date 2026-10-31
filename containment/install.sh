#!/bin/bash
# Installs the containment launchers and the agent hook on this Mac. Run by the owner, in their own
# terminal, outside any sandbox: bash /Users/ryanheffernan/Documents/projects/d1preservation/containment/install.sh
# It runs every Go control, builds the four binaries with this repository's root compiled in,
# installs them root-owned (sudo asks for your password), backs up ~/.claude/settings.json, merges
# the hook and deny rules into it, and prints the check. Running it again is harmless.
set -euo pipefail

root=/Users/ryanheffernan/Documents/projects/d1preservation
install_dir=/usr/local/libexec/d1-agent
settings="$HOME/.claude/settings.json"

cd "$root/containment/go"
# Nothing is built or cached in a directory a contained process can write: both game.sb and local.sb
# allow writes under /private/var/folders (where mktemp -d puts its directory) and under the
# repository, so a process running during the install could have replaced a built binary between
# "go build" and "sudo install", or poisoned the build cache so a failing control passed
# (audit 2026-10-31, N4 and N5). The three directories below are in $HOME, which no agent sandbox
# and no launcher profile allows writing.
work=$(mktemp -d "$HOME/.d1-agent-install.XXXXXX")
trap 'rm -rf "$work"' EXIT
build="$work/build"
control="$work/control"
mkdir "$build" "$control"

export GOCACHE="$work/gocache"
export GOFLAGS=-mod=mod

echo "== controls (every one must pass, none skipped)"
go test -count=1 ./...

echo "== build"
go build -o "$build/d1-nonet" ./cmd/d1-nonet
go build -ldflags "-X main.repositoryRoot=$root" -o "$build/d1-localonly" ./cmd/d1-localonly
go build -ldflags "-X main.repositoryRoot=$root" -o "$build/d1-agent-hook" ./cmd/d1-agent-hook
go build -o "$build/d1-orkey" ./cmd/d1-orkey
# The Keychain hands the key to d1-orkey by its code hash, so nothing may be loaded into it: the
# hardened runtime makes dyld ignore DYLD_INSERT_LIBRARIES and refuses a debugger.
codesign --force --sign - --options runtime "$build/d1-orkey"
"$build/d1-orkey" controls

echo "== d1-orkey injection control (a plain-signed copy loads the library; the installed binary does not)"
printf '#include <stdio.h>\n__attribute__((constructor)) static void injected(void) { fputs("INJECTED\\n", stderr); }\n' > "$build/inject.c"
cc -dynamiclib -o "$build/inject.dylib" "$build/inject.c"
cp "$build/d1-orkey" "$build/d1-orkey-plain"
codesign --force --sign - "$build/d1-orkey-plain"
plain=$(DYLD_INSERT_LIBRARIES="$build/inject.dylib" "$build/d1-orkey-plain" controls 2>&1)
hardened=$(DYLD_INSERT_LIBRARIES="$build/inject.dylib" "$build/d1-orkey" controls 2>&1)
case "$plain" in *INJECTED*) ;; *) echo "FAIL injection control: the plain copy did not load it, so the check proves nothing"; exit 2 ;; esac
case "$hardened" in *INJECTED*) echo "FAIL injection control: a library loaded into d1-orkey"; exit 2 ;; esac
rm "$build/d1-orkey-plain" "$build/inject.dylib" "$build/inject.c"
echo "OK   d1-orkey: hardened runtime, nothing loads into it"

echo "== test gate (every Rust and Go test runs inside the game profile; agent-containment.md, Tests)"
go run ./cmd/d1-testgate-header "$root" > "$build/d1testgate-profile.h"
cc -O2 -Wall -include "$build/d1testgate-profile.h" -Dd1_netgate=d1_testgate_netgate -c ../c/d1netgate.c -o "$build/d1netgate.o"
cc -O2 -Wall -c ../c/d1testgate.c -o "$build/d1testgate.o"
# Apple's linker requires 8-byte-aligned Mach-O members; GNU ar on PATH does not supply them.
/usr/bin/ar rcs "$build/libd1testgate.a" "$build/d1netgate.o" "$build/d1testgate.o"

echo "== install (root-owned, sudo)"
sudo install -d -o root -g wheel -m 0755 "$install_dir"
sudo install -o root -g wheel -m 0755 "$build/d1-nonet" "$build/d1-localonly" "$build/d1-agent-hook" "$build/d1-orkey" "$install_dir/"
# d1-orkey.env names the key in 1Password (a reference, not the key) for op run, only when
# D1_ORKEY_REF is given; otherwise the login Keychain is the source and no env file is written.
if [ -n "${D1_ORKEY_REF:-}" ] && [ ! -f "$install_dir/d1-orkey.env" ]; then
  printf 'OPENROUTER_API_KEY=%s\n' "$D1_ORKEY_REF" > "$build/d1-orkey.env"
  sudo install -o root -g wheel -m 0644 "$build/d1-orkey.env" "$install_dir/"
elif [ -z "${D1_ORKEY_REF:-}" ]; then
  echo "d1-orkey: no D1_ORKEY_REF, so no env file; the key comes from the login Keychain (service d1-orkey, account openrouter)"
fi
sudo install -o root -g wheel -m 0644 "$build/libd1testgate.a" "$install_dir/"
# The Keychain item trusts one d1-orkey build by its code hash; this install made a new one, which
# refuses at start (it shows no dialog) until the key is stored again from it.
echo "d1-orkey: new build; store the key again: $install_dir/d1-orkey store-key, then launchctl kickstart -k gui/$(id -u)/com.d1preservation.orkey"

echo "== test gate control (a test-named binary is contained before main; the same binary named as a tool is not)"
mkdir "$control/deps"
cat > "$control/probe.c" <<'EOF'
#include <errno.h>
#include <stdio.h>
#include <netinet/in.h>
#include <sys/socket.h>
int main(void) {
    struct sockaddr_in a = { .sin_len = sizeof a, .sin_family = AF_INET, .sin_port = htons(9) };
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int s = socket(AF_INET, SOCK_STREAM, 0);
    int refused = s < 0 || connect(s, (struct sockaddr *)&a, sizeof a) != 0;
    puts(refused && (errno == EPERM || errno == EACCES) ? "contained" : "open");
    return 0;
}
EOF
cc -O2 "$control/probe.c" -Wl,-force_load,"$install_dir/libd1testgate.a" -o "$control/deps/probe-0123456789abcdef"
cp "$control/deps/probe-0123456789abcdef" "$control/probe"
test "$("$control/deps/probe-0123456789abcdef")" = contained || { echo "FAIL test gate: a test binary was not contained"; exit 2; }
test "$("$control/probe")" = open || { echo "FAIL test gate: the control binary was contained too, so the probe proves nothing"; exit 2; }
echo "OK   test gate: a test binary is contained before main; the same code named as a tool is not"

echo "== settings (backup, then merge)"
cp "$settings" "$settings.before-d1-agent-hook"
"$install_dir/d1-agent-hook" settings | python3 -c '
import json, sys, os
path = os.path.expanduser("~/.claude/settings.json")
settings = json.load(open(path)); block = json.load(sys.stdin)
pre = settings.setdefault("hooks", {}).setdefault("PreToolUse", [])
pre[:] = [entry for entry in pre if not any(hook.get("command", "").endswith("/d1-agent-hook") for hook in entry.get("hooks", []))]
pre.extend(block["hooks"]["PreToolUse"])
deny = settings.setdefault("permissions", {}).setdefault("deny", [])
deny.extend(rule for rule in block["permissions"]["deny"] if rule not in deny)
json.dump(settings, open(path, "w"), indent=2); open(path, "a").write("\n")
print("merged", len(block["hooks"]["PreToolUse"]), "hook entry and", len(block["permissions"]["deny"]), "deny rules into", path)
'

echo "== check (every line must say OK; the hook takes effect in new Claude Code sessions)"
"$install_dir/d1-agent-hook" check
