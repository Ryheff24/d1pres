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

echo "== codex requirements (Codex keeps the protected files read-only by path, not by spelling; hook/codex.go)"
# Applies to every Codex session on this Mac: profile d1 is the default and only writing profile,
# :workspace and :danger-full-access are refused (developers.openai.com/codex/permissions).
codex=/Applications/ChatGPT.app/Contents/Resources/codex-cli/bin/codex
requirements=/etc/codex/requirements.toml
"$install_dir/d1-agent-hook" codex-requirements > "$build/requirements.toml"
if [ -f "$requirements" ] && ! cmp -s "$requirements" "$build/requirements.toml"; then
  backup="$requirements.before-d1-agent-hook.$(date +%Y%m%d%H%M%S)"
  sudo cp -p "$requirements" "$backup"
  echo "codex: the earlier $requirements is kept at $backup"
fi
sudo install -d -o root -g wheel -m 0755 /etc/codex
sudo install -o root -g wheel -m 0644 "$build/requirements.toml" "$requirements"
test -x "$codex" || { echo "FAIL codex: $codex is missing, so profile d1 is unmeasured"; exit 2; }

echo "== codex control (profile d1 under the installed requirements: what it must write, then every protected path refused)"
# Each probe opens a path for appending and writes nothing, so an existing file's bytes are never
# changed even if the profile fails. A refusal counts only when the output says "Operation not
# permitted": a missing path, or a Codex that cannot apply the policy, is not a refusal. A probe
# removes only what it created: an entry that was there before, a dangling link included, is left
# (GPT 6.1 sol final review of PR 9, finding 9), and a directory it made is removed only if empty.
# This terminal changes nothing at a path an agent can write except under noclobber in a directory
# mktemp made here, and the whole of such a directory with rm -rf, which does not follow links: a
# removal or a link inside the repository runs under profile d1 itself, so a path an agent swapped
# for a link mid-probe reaches only what an agent could reach anyway (second review of PR 9,
# findings 4 and 8).
codex_in() { local workspace=$1; shift; "$codex" sandbox macos -P d1 --include-managed-config -C "$workspace" -- "$@" 2>&1; }
codex_failed=0
# probe WORKSPACE PATH LABEL EXPECT: EXPECT is "write" (a control: it must succeed) or "refuse".
probe() {
  local workspace=$1 path=$2 label=$3 expect=$4 out status=0 existed=no dir
  local -a missing=()
  if [ -e "$path" ] || [ -L "$path" ]; then existed=yes; fi
  dir=${path%/*}
  while [ ! -e "$dir" ] && [ ! -L "$dir" ]; do missing+=("$dir"); dir=${dir%/*}; done
  out=$(codex_in "$workspace" /bin/sh -c 'mkdir -p "${1%/*}" && : >> "$1"' probe "$path") || status=$?
  if [ "$existed" = no ]; then
    codex_in "$workspace" /bin/sh -c 'if [ -f "$1" ] && [ ! -L "$1" ]; then rm -f "$1"; fi; shift; for dir do rmdir "$dir" 2>/dev/null; done; :' \
      cleanup "$path" ${missing[@]+"${missing[@]}"} > /dev/null || true
    if [ -f "$path" ] && [ ! -L "$path" ]; then echo "note: this probe made $path and profile d1 refuses removing it; remove it by hand"; fi
  fi
  if [ "$expect" = write ]; then
    if [ "$status" = 0 ]; then echo "OK   codex control: profile d1 writes $label"; return 0; fi
    echo "FAIL codex control: profile d1 could not write $label, so the refusals below prove nothing: $out"; exit 2
  fi
  if [ "$status" = 0 ]; then echo "FAIL codex: profile d1 opened $label for writing"; codex_failed=1
  else case "$out" in
    *"Operation not permitted"*) echo "OK   codex: profile d1 refuses writing $label" ;;
    *) echo "FAIL codex: writing $label failed without a sandbox refusal: $out"; codex_failed=1 ;;
  esac; fi
}
# runs/ must be the repository's own directory: were it a link to somewhere outside the workspace,
# every refusal below would be the workspace boundary's and not the profile's. Each directory a probe
# uses is made by mktemp with a name nobody can guess, and each also gets a control write from the
# repository's workspace, which fails if the directory is not inside it.
if [ -L "$root/runs" ] || { [ -e "$root/runs" ] && [ ! -d "$root/runs" ]; }; then
  echo "FAIL codex control: $root/runs is not a plain directory, so the probes would not measure the profile"; exit 2
fi
mkdir -p "$root/runs"
probe_dir=$(mktemp -d "$root/runs/.codex-control.XXXXXX")
probe "$root" "$probe_dir/probe" "runs/" write
rm -rf "$probe_dir"
for name in CLAUDE.md containment/install.sh .cargo/config.toml containment/go/.codex-probe containment/c/.codex-probe .claude/hooks/.codex-probe .git/hooks/.codex-probe; do
  probe "$root" "$root/$name" "$name" refuse
done

# Worktrees (finding 5): the profile's glob keys, measured on two worktree directories made here,
# with Codex started in the repository (the worktree is a directory in its workspace) and started in
# the worktree (the worktree is its workspace root, which the d1 hook does not cover). The files the
# probes aim at are made first, under noclobber, so neither a planted file nor a planted link is
# truncated or followed into an existing file.
lower=$(mktemp -d "$root/runs/wt-codex-probe.XXXXXX")
upper=$(mktemp -d "$root/runs/WT-codex-probe.XXXXXX")
if ! ( set -C; mkdir "$lower/containment" "$lower/containment/go" && : > "$lower/CLAUDE.md" && : > "$upper/CLAUDE.md" ); then
  rm -rf "$lower" "$upper"
  echo "FAIL codex control: the worktree probe directories changed while they were being made"; exit 2
fi
probe "$root" "$lower/control.txt" "runs/wt-*/, a directory in the repository" write
probe "$root" "$upper/control.txt" "runs/WT-*/, a directory in the repository" write
probe "$lower" "$lower/notes.txt" "a worktree, as its root" write
probe "$root" "$lower/CLAUDE.md" "runs/wt-*/CLAUDE.md" refuse
probe "$root" "$upper/CLAUDE.md" "runs/WT-*/CLAUDE.md" refuse
probe "$root" "$lower/containment/go/.codex-probe" "runs/wt-*/containment/go/" refuse
probe "$lower" "$lower/CLAUDE.md" "CLAUDE.md of a worktree that is the workspace root" refuse
probe "$lower" "$lower/containment/go/.codex-probe" "containment/go/ of a worktree that is the workspace root" refuse
rm -rf "$lower" "$upper"

# Hard links (finding 8). A link to an unprotected file is the control; then a link to CLAUDE.md is
# either refused, or made and refused when opened for writing. A link that opens for writing stops
# the install. The control's source is in $work, which no sandbox may write; each link is made under
# profile d1 in a directory mktemp made here, with ln -n, so a link planted at the name fails with
# "File exists" instead of putting the new link inside the directory it points to (second review of
# PR 9, finding 8). A link that was made must be the same file as CLAUDE.md, or the probe stops.
# Never a byte is written through one; they are removed under profile d1, with their directory.
link_source=$(mktemp "$work/link-source.XXXXXX")
link_dir=$(mktemp -d "$root/runs/.codex-link.XXXXXX")
if codex_in "$root" /bin/ln -n "$link_source" "$link_dir/control" > /dev/null; then link_control=made; else link_control=refused; fi
status=0
out=$(codex_in "$root" /bin/ln -n "$root/CLAUDE.md" "$link_dir/link") || status=$?
if [ "$status" != 0 ]; then
  case "$out" in
    *"Operation not permitted"*) echo "OK   codex: profile d1 refuses hard-linking CLAUDE.md (a link to a file no sandbox writes is $link_control)" ;;
    *) echo "FAIL codex: hard-linking CLAUDE.md failed without a sandbox refusal: $out"; codex_failed=1 ;;
  esac
elif [ ! "$link_dir/link" -ef "$root/CLAUDE.md" ] || [ -L "$link_dir/link" ]; then
  echo "FAIL codex: ln reported a hard link to CLAUDE.md, but $link_dir/link is not one, so the probe measured nothing"; codex_failed=1
else
  status=0
  out=$(codex_in "$root" /bin/sh -c ': >> "$1"' probe "$link_dir/link") || status=$?
  case "$status:$out" in
    0:*) echo "FAIL codex: under profile d1 a hard link to CLAUDE.md made in runs/ opens for writing, so a write through it changes CLAUDE.md"; codex_failed=1 ;;
    *"Operation not permitted"*) echo "OK   codex: profile d1 makes a hard link to CLAUDE.md but refuses opening it for writing" ;;
    *) echo "FAIL codex: opening a hard link to CLAUDE.md failed without a sandbox refusal: $out"; codex_failed=1 ;;
  esac
fi
codex_in "$root" /bin/rm -f "$link_dir/link" "$link_dir/control" > /dev/null || true
rm -rf "$link_dir"
test "$codex_failed" = 0 || { echo "FAIL codex: a protected path is writable under profile d1, or a probe could not tell"; exit 2; }

echo "== check (every line must say OK; the hook takes effect in new Claude Code sessions)"
"$install_dir/d1-agent-hook" check
