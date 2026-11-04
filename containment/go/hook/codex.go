package hook

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"d1preservation/netguard/gate"
)

// CodexRequirementsPath is where Codex reads managed requirements on macOS and Linux (/etc is a
// link to /private/etc; the resolved path is used so RootOwned can check every directory above it).
const CodexRequirementsPath = "/private/etc/codex/requirements.toml"

// CodexProfile is the permission profile the requirements make Codex's default and only writing
// profile on this Mac.
const CodexProfile = "d1"

// codexRequirementsPath is CodexRequirementsPath, replaced by tests.
var codexRequirementsPath = CodexRequirementsPath

// CodexRequirements is the text of /etc/codex/requirements.toml: Codex's own sandbox, told which
// paths it keeps read-only, so the protected files hold in Codex by path and not by spelling.
//
// Before this, in a Codex session the hook's tripwire was the only rule against a Bash write of a
// protected file, and it is spelling-based ("cp x CLAUDE.m?" passes it). Codex's workspace-write
// sandbox let it write anywhere in the repository but .git. Managed requirements are the layer
// Codex applies over every user config, flag and profile (Codex 0.138 or later; the docs:
// developers.openai.com/codex/permissions and /codex/enterprise/managed-configuration):
//
//   - default_permissions is "d1", a profile that extends the built-in :workspace (the workspace
//     roots writable, .git, .codex, .agents and .aws read-only in each) and makes every protected
//     file and tree "read". The more specific path wins, so each stays readable and is not
//     writable, whatever the command spells.
//   - allowed_permission_profiles lists :read-only and d1 alone. Codex denies every profile it
//     omits, :workspace and :danger-full-access included, and a managed allowlist makes Codex use
//     profiles even where an older --sandbox or sandbox_mode is given (where they disagree it falls
//     back to a value the requirements allow).
//
// The file is root-owned (install.sh writes it with sudo), so no agent and no contained process
// can change it. It applies to every Codex session on this Mac: elsewhere d1 is :workspace.
func CodexRequirements(config Config) (string, error) {
	var lines []string
	add := func(format string, values ...any) { lines = append(lines, fmt.Sprintf(format, values...)) }
	add("# Written by %s/containment/install.sh from \"d1-agent-hook codex-requirements\"; edit the hook, not this file.", config.Root)
	add("# Codex keeps every protected file and tree of %s read-only (hook/codex.go explains each line).", config.Root)
	add("default_permissions = %q", CodexProfile)
	add("")
	add("[allowed_permission_profiles]")
	add("%q = true", ":read-only")
	add("%s = true", CodexProfile)
	add("")
	add("[permissions.%s]", CodexProfile)
	add("description = %q", "The workspace, with the protected files and trees of "+config.Root+" read-only (containment/agent-containment.md)")
	add("extends = %q", ":workspace")
	add("")
	add("[permissions.%s.filesystem]", CodexProfile)
	for _, path := range append(append(ProtectedPaths(config), ProtectedTreePaths(config)...), codexWorktreePaths(config)...) {
		key, err := tomlKey(path)
		if err != nil {
			return "", err
		}
		add("%s = %q", key, "read")
	}
	return strings.Join(lines, "\n") + "\n", nil
}

// codexWorktreePatterns are the worktree directories (worktreeRoots) as Codex glob patterns. The
// volume ignores case and a glob does not, so "wt-" is listed in each of its four spellings; a
// worktree's directory exists before anything is written in it, so its own spelling is what the
// sandbox compares.
var codexWorktreePatterns = []string{".claude/worktrees/*", "runs/wt-*", "runs/wT-*", "runs/Wt-*", "runs/WT-*"}

// codexWorktreePaths are the protected files and trees inside every worktree, as glob keys: each
// file, each tree and each tree's "**". The profile kept only the main checkout's copies, so
// "cp runs/p runs/wt-demo/CLAUDE.m?" was a write Codex allowed and only the spelling-based tripwire
// stood against (GPT 6.1 sol final review of PR 9, finding 5). They are per-file, not the whole
// worktree directory, because a Codex session started inside a worktree has that worktree as its
// workspace root, which is more specific than its parent directory and would win; and the d1 hook
// does not run there at all, since Codex trusts d1preservation/.codex/hooks.json by its path. Read
// and write globs are supported on macOS (developers.openai.com/codex/permissions); install.sh
// measures one, as the parent and as the root.
func codexWorktreePaths(config Config) []string {
	var paths []string
	for _, pattern := range codexWorktreePatterns {
		base := filepath.Join(config.Root, pattern)
		for _, name := range gate.ProtectedFiles {
			paths = append(paths, filepath.Join(base, name))
		}
		for _, tree := range gate.ProtectedTrees {
			paths = append(paths, filepath.Join(base, tree), filepath.Join(base, tree, "**"))
		}
	}
	return paths
}

// tomlKey is path as a TOML quoted key. A path with a quote, a backslash or a control character is
// refused rather than escaped: gate.CheckRoot keeps such a root out, and the profile text must be
// the path and nothing else.
func tomlKey(path string) (string, error) {
	if !filepath.IsAbs(path) || strings.ContainsAny(path, "\"\\") || strings.IndexFunc(path, func(character rune) bool { return character < 0x20 || character == 0x7f }) >= 0 {
		return "", fmt.Errorf("%q cannot be written into the Codex requirements: it is not absolute, or holds a quote, a backslash or a control character", path)
	}
	return "\"" + path + "\"", nil
}

// legacySandboxKeys are the older sandbox settings that the docs say to remove before a managed
// profile allowlist is deployed.
var legacySandboxKeys = []string{"sandbox_mode", "[sandbox_workspace_write]"}

// checkCodex reports: the requirements file root-owned, closed to other writes and exactly what
// CodexRequirements prints; and ~/.codex/config.toml without the older sandbox settings.
func checkCodex(config Config) []Line {
	wanted, err := CodexRequirements(config)
	if err != nil {
		return []Line{fact(false, "codex: "+err.Error())}
	}
	text, readError := os.ReadFile(codexRequirementsPath)
	owned := RootOwned(codexRequirementsPath)
	same := readError == nil && string(text) == wanted
	why := owned
	switch {
	case readError != nil:
		why = readError.Error()
	case !same:
		why = "it differs from what d1-agent-hook codex-requirements prints; run install.sh"
	}
	lines := []Line{fact(owned == "" && same, "codex: "+codexRequirementsPath+" is root-owned, closed to other writes, and keeps the protected paths read-only in profile "+CodexProfile+" "+why)}
	userConfig := filepath.Join(config.Home, ".codex", "config.toml")
	var found []string
	if user, err := os.ReadFile(userConfig); err == nil {
		for _, line := range strings.Split(string(user), "\n") {
			line = strings.TrimSpace(line)
			for _, key := range legacySandboxKeys {
				if strings.HasPrefix(line, key) {
					found = append(found, line)
				}
			}
		}
	}
	return append(lines, fact(len(found) == 0, "codex: "+userConfig+" sets none of the older sandbox settings, which a profile allowlist replaces"+listed(" (remove ", found)))
}
