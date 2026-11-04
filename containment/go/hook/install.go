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

// denyRules is one Edit rule per protected path, and one per protected tree, which Claude Code
// reads as a gitignore-style pattern (so it also denies Bash writes under the tree in the agent's
// own sandbox). Each worktree pattern (codexWorktreePatterns) gets the same rules, as globs, so a
// worktree's CLAUDE.md, gate call sites and containment sources are denied to Claude Code's tools
// as the main checkout's are (second review of PR 9, finding 6). A worktree outside the patterns is
// refused at git worktree add and move, and reported by check.
func denyRules(config Config) []string {
	var rules []string
	for _, path := range ProtectedPaths(config) {
		rules = append(rules, "Edit(/"+path+")")
	}
	for _, path := range ProtectedTreePaths(config) {
		rules = append(rules, "Edit(/"+path+"/**)")
	}
	for _, pattern := range codexWorktreePatterns {
		base := filepath.Join(config.Root, pattern)
		for _, name := range gate.ProtectedFiles {
			rules = append(rules, "Edit(/"+filepath.Join(base, name)+")")
		}
		for _, tree := range gate.ProtectedTrees {
			rules = append(rules, "Edit(/"+filepath.Join(base, tree)+"/**)")
		}
	}
	return rules
}

// checkWorktrees reports each worktree git has registered: inside the patterns the Codex
// requirements and the deny rules cover, or not. One outside them has only the hook's
// RegisteredWorktrees check over its protected copies, and none from Codex's profile.
func checkWorktrees(config Config) []Line {
	root, err := canonicalPath(config.Root)
	if err != nil {
		return []Line{fact(false, "worktrees: the root cannot be resolved ("+err.Error()+")")}
	}
	var lines []Line
	for _, worktree := range RegisteredWorktrees(config) {
		resolved, err := canonicalPath(worktree)
		if err != nil {
			continue
		}
		inside := inWorktreePattern(resolved, root)
		text := "worktree: " + worktree + " is inside runs/wt-NAME or .claude/worktrees/NAME, where its protected copies are read-only"
		if !inside {
			text = "worktree: " + worktree + " is outside runs/wt-NAME and .claude/worktrees/NAME, so Codex's profile and Claude Code's deny rules do not cover its protected copies; move it with git worktree move"
		}
		lines = append(lines, fact(inside, text))
	}
	return lines
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
	lines = append(lines, checkCodex(config)...)
	lines = append(lines, checkWorktrees(config)...)
	for _, name := range gate.ProtectedFiles {
		_, err := os.Stat(filepath.Join(config.Root, name))
		optional := slices.Contains(optionalFiles, name)
		lines = append(lines, fact(err == nil || optional, "protected: "+name+presence(err, optional)))
	}
	for _, name := range gate.ProtectedTrees {
		info, err := os.Stat(filepath.Join(config.Root, name))
		directory := err == nil && info.IsDir()
		lines = append(lines, fact(directory || err != nil, "protected tree: "+name+"/ (every file under it)"+treePresence(err, directory)))
	}
	return lines
}

// treePresence says whether a protected tree is a directory; one that does not exist yet is
// protected against being created, like an optional file.
func treePresence(err error, directory bool) string {
	switch {
	case directory:
		return " is present"
	case err != nil:
		return " is absent; creating a file in it is refused"
	default:
		return " is not a directory"
	}
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
		// The Codex plugin's two entries are node on its companion script, which CompanionForm holds
		// to one command; without this the check printed a FAIL nobody could clear (2026-10-27
		// review §1: a check that always fails is a check nobody reads).
		if isCompanion(strings.ReplaceAll(entry, "*", "")) {
			continue
		}
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
