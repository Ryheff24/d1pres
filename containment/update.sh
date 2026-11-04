#!/bin/bash
# Brings containment/ and CLAUDE.md up to main of github.com/Ryheff24/d1pres, then runs the new
# install.sh. Run by the owner, in their own terminal, outside any sandbox, after merging there:
#   bash /Users/ryanheffernan/Documents/projects/d1preservation/containment/update.sh          update and install
#   bash /Users/ryanheffernan/Documents/projects/d1preservation/containment/update.sh check    report only, change nothing
# main is cloned fresh into a folder in your home that no agent or contained program can write
# (they write only in this repository, temporary space and cargo's caches), so nothing left in this
# repository chooses what is checked out. Files here that differ from main are listed, then
# overwritten. A file under containment/go or containment/c that main lacks stops it before anything
# is written: the build would compile or embed it. Everything printed also goes to
# runs/containment-update-*.log. The braces make bash read the whole script before it runs, because
# the checkout rewrites this file.
{
set -euo pipefail
root=/Users/ryanheffernan/Documents/projects/d1preservation
url=https://github.com/Ryheff24/d1pres.git
mode=${1:-update}
case "$mode" in
  update|check) ;;
  *) echo "usage: bash $0 [check]"; exit 2 ;;
esac
mkdir -p "$root/runs"
log=$(mktemp "$root/runs/containment-update-XXXXXX")
exec > >(tee "$log") 2>&1
clone=$(mktemp -d "$HOME/.d1pres-update.XXXXXX")
trap 'rm -rf "$clone"' EXIT
export GIT_NO_REPLACE_OBJECTS=1
# g runs git on the fresh clone with this repository as its working tree; no hook or monitor runs.
g() { git -c core.hooksPath=/dev/null -c core.fsmonitor=false --git-dir="$clone" --work-tree="$root" "$@"; }

if ! git -c core.hooksPath=/dev/null clone -q --bare --single-branch --branch main "$url" "$clone"; then
  echo "STOP: cannot clone $url (sign in with gh auth login, then run this again); nothing was changed"; exit 2
fi
echo "== main is $(g log -1 --format='%h %s')"

extra=""
kept=""
# Every entry that is not a directory is read, links included: "find -type f" left out a symbolic
# link such as containment/go/hook/planted_test.go -> ../../../runs/payload.go, the checkout does
# not remove an untracked one, and go test ./... compiles a linked source file as its own (GPT 6.1
# sol final review of PR 9, finding 6). A link under containment/go or containment/c stops this
# even when main has a file of that name. The patterns ignore case, as the volume does: find prints
# a planted containment/Go/hook/x_test.go as it is spelled, git's tree has no such name, and go
# builds it as containment/go/hook (second review of PR 9, finding 5).
shopt -s nocasematch
while IFS= read -r path; do
  case "$path" in
    containment/go/*|containment/c/*)
      if [ -L "$root/$path" ]; then extra+="  $path (a symbolic link)"$'\n'; continue; fi ;;
  esac
  if ! g cat-file -e "HEAD:$path" 2>/dev/null; then
    case "$path" in
      containment/go/*|containment/c/*) extra+="  $path"$'\n' ;;
      *) kept+="  $path"$'\n' ;;
    esac
  fi
done < <(cd "$root" && find containment ! -type d ! -path '*/.gocache/*' ! -path '*/.p-*' ! -path '*/.claude/*' ! -name .DS_Store | sort)
shopt -u nocasematch
if [ -n "$kept" ]; then
  printf '== here but not in main (kept, never built):\n%s' "$kept"
fi
if [ -n "$extra" ]; then
  printf 'STOP: these are under containment/go or containment/c but not in main, and the build would use them; nothing was changed. Move or delete them, then run this again:\n%s' "$extra"
  exit 2
fi

g read-tree HEAD
echo "== here and different from main:"
g diff --stat -- containment CLAUDE.md
if [ "$mode" = check ]; then
  echo "(check only: nothing was changed)"
  echo "DONE ($log)"
  exit 0
fi

g checkout -f HEAD -- containment CLAUDE.md
# install.sh used to cache the build under containment/go/.gocache, which every contained process
# could write; it builds in $HOME now, so whatever is left there is stale and nothing should read it
# again (audit 2026-10-31, N4).
rm -rf "$root/containment/go/.gocache"
if ! g diff --quiet -- containment CLAUDE.md; then
  echo "STOP: after the checkout these still differ from main:"; g diff --stat -- containment CLAUDE.md; exit 2
fi
echo "== containment/ and CLAUDE.md now match main $(g rev-parse --short HEAD)"
echo "== install.sh (sudo asks for your password)"
bash "$root/containment/install.sh"
echo "DONE ($log)"
exit 0
}
