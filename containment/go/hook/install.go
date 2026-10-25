package hook

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"d1preservation/netguard/gate"
)

// HookPath is the installed hook, the command Claude Code runs.
func HookPath(config Config) string {
	return filepath.Join(config.LauncherDirectory, "d1-agent-hook")
}

// Settings is the block for ~/.claude/settings.json: the hook on Bash and the edit tools, and an
// Edit deny rule for each protected file ("//" starts an absolute path there). The deny rules are
// Claude Code's own check on its file tools; the hook does not rely on them.
func Settings(config Config) map[string]any {
	command := map[string]any{"type": "command", "command": HookPath(config)}
	entry := map[string]any{"matcher": Matcher, "hooks": []any{command}}
	return map[string]any{
		"hooks":       map[string]any{"PreToolUse": []any{entry}},
		"permissions": map[string]any{"deny": denyRules(config)},
	}
}

// denyRules is one Edit rule per protected path.
func denyRules(config Config) []string {
	var rules []string
	for _, path := range ProtectedPaths(config) {
		rules = append(rules, "Edit(/"+path+")")
	}
	return rules
}

// Line is one fact Check measured: OK or not, and what it says.
type Line struct {
	OK   bool
	Text string
}

// optionalFiles are protected files that need not exist: the rules refuse creating them.
var optionalFiles = []string{"AGENTS.md", ".claude/settings.json", ".claude/settings.local.json", ".cargo/config.toml", "d1-server/.cargo/config.toml"}

// Check reports the facts the install rests on, one line each: the root set at build time, the
// launcher directory and each binary root-owned, the settings in place, each protected file present.
// It is a report, not a gate: it changes nothing and nothing waits on it.
func Check(config Config) []Line {
	lines := []Line{fact(gate.CheckRoot(config.Root) == nil, "root: "+config.Root+" holds CLAUDE.md and containment/ (set at build time)")}
	for _, name := range []string{"", "d1-nonet", "d1-localonly", "d1-agent-hook"} {
		path := filepath.Join(config.LauncherDirectory, name)
		why := RootOwned(path)
		info, err := os.Stat(path)
		executable := err == nil && (name == "" || info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0)
		lines = append(lines, fact(why == "" && executable, fmt.Sprintf("install: %s root-owned, closed to other writes%s %s", path, modeText(info, err), why)))
	}
	lines = append(lines, checkSettings(config)...)
	for _, name := range gate.ProtectedFiles {
		_, err := os.Stat(filepath.Join(config.Root, name))
		optional := slices.Contains(optionalFiles, name)
		lines = append(lines, fact(err == nil || optional, "protected: "+name+presence(err, optional)))
	}
	return lines
}

// fact makes a Line.
func fact(ok bool, text string) Line {
	return Line{OK: ok, Text: strings.TrimSpace(text)}
}

// modeText is ", mode -rwxr-xr-x" for a path that exists, else why it cannot be read.
func modeText(info os.FileInfo, err error) string {
	if err != nil {
		return " (" + err.Error() + ")"
	}
	return ", mode " + info.Mode().String()
}

// presence says whether a protected file is there.
func presence(err error, optional bool) string {
	if err == nil {
		return " is present"
	}
	if optional {
		return " is absent; creating it is refused"
	}
	return " is missing (" + err.Error() + ")"
}

// settingsFile is the part of ~/.claude/settings.json that Check reads.
type settingsFile struct {
	Hooks struct {
		PreToolUse []struct {
			Matcher string `json:"matcher"`
			Hooks   []struct {
				Command string `json:"command"`
			} `json:"hooks"`
		} `json:"PreToolUse"`
	} `json:"hooks"`
	Permissions struct {
		Deny []string `json:"deny"`
	} `json:"permissions"`
	Sandbox struct {
		ExcludedCommands []string `json:"excludedCommands"`
	} `json:"sandbox"`
}

// checkSettings reads ~/.claude/settings.json and reports: the hook on every tool of Matcher,
// every deny rule Settings prints, and every sandbox.excludedCommands entry one this hook holds
// to a command alone (an unknown one runs outside the sandbox unseen).
func checkSettings(config Config) []Line {
	path := filepath.Join(config.Home, ".claude", "settings.json")
	var settings settingsFile
	text, err := os.ReadFile(path)
	if err == nil {
		err = json.Unmarshal(text, &settings)
	}
	if err != nil {
		return []Line{fact(false, "settings: cannot read "+path+" ("+err.Error()+")")}
	}
	covered := map[string]bool{}
	for _, entry := range settings.Hooks.PreToolUse {
		for _, hook := range entry.Hooks {
			for _, tool := range strings.Split(entry.Matcher, "|") {
				covered[tool] = covered[tool] || hook.Command == HookPath(config)
			}
		}
	}
	var uncovered, missing, unknown []string
	for _, tool := range strings.Split(Matcher, "|") {
		if !covered[tool] {
			uncovered = append(uncovered, tool)
		}
	}
	for _, rule := range denyRules(config) {
		if !slices.Contains(settings.Permissions.Deny, rule) {
			missing = append(missing, rule)
		}
	}
	for _, entry := range settings.Sandbox.ExcludedCommands {
		if !isExcludedName(strings.TrimSuffix(strings.Fields(entry + " x")[0], "*")) {
			unknown = append(unknown, entry)
		}
	}
	return []Line{
		fact(len(uncovered) == 0, "settings: PreToolUse runs "+HookPath(config)+" for "+Matcher+listed(" (not for ", uncovered)),
		fact(len(missing) == 0, "settings: permissions.deny has an Edit rule for each protected file"+listed(" (missing ", missing)),
		fact(len(unknown) == 0, "settings: every sandbox.excludedCommands entry is one the hook holds to a command alone"+listed(" (not ", unknown)),
	}
}

// listed is prefix, the items joined, and ")" when there are items, else "".
func listed(prefix string, items []string) string {
	if len(items) == 0 {
		return ""
	}
	return prefix + strings.Join(items, ", ") + ")"
}
