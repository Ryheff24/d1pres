#!/bin/bash
# Adds the allow rules that keep Claude Code's auto-mode classifier out of the known-good shapes:
# the two launchers (the hook still enforces their exact form on every call) and edits under the
# game runtime directory (its protected files are covered by deny rules, which always win over
# allow rules). Run by the owner, in their own terminal:
#   bash /Users/ryanheffernan/Documents/projects/d1preservation/containment/settings-allow.sh
# It backs up ~/.claude/settings.json first and adds only the rules that are not there yet.
set -euo pipefail

settings="$HOME/.claude/settings.json"
cp "$settings" "$settings.before-allow-rules"
python3 - "$settings" <<'PY'
import json, sys
path = sys.argv[1]
settings = json.load(open(path))
rules = [
    "Bash(/usr/local/libexec/d1-agent/d1-nonet *)",
    "Bash(/usr/local/libexec/d1-agent/d1-localonly *)",
    "Edit(//Users/ryanheffernan/Documents/projects/d1preservation/d1-server/crates/d1-recomp/runtime/**)",
]
allow = settings.setdefault("permissions", {}).setdefault("allow", [])
added = [rule for rule in rules if rule not in allow]
allow.extend(added)
json.dump(settings, open(path, "w"), indent=2)
open(path, "a").write("\n")
print("added", len(added), "allow rule(s); deny rules untouched:", len(settings["permissions"].get("deny", [])))
PY
echo "Next: start a new Claude Code session in auto mode and have an agent run"
echo "  /usr/local/libexec/d1-agent/d1-nonet /Users/ryanheffernan/Documents/projects/d1preservation/d1-server/target/release/d1-oracle --help"
echo "with the sandbox off, once bare and once with a leading D1_EBOOT=/x assignment. If the second one"
echo "still prompts, the prefix rule does not cover a leading assignment; say so and the rule gets a companion."
