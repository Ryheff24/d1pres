package hook

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
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
	for _, path := range append(ProtectedPaths(config), ProtectedTreePaths(config)...) {
		key, err := tomlKey(path)
		if err != nil {
			return "", err
		}
		add("%s = %q", key, "read")
	}
	return strings.Join(lines, "\n") + "\n", nil
}

// codexWorktreePatterns are the worktree directories (worktreeRoots) as glob patterns, for Claude
// Code's Edit deny rules (install.go). The volume ignores case and a glob does not, so "wt-" is
// listed in each of its four spellings.
//
// Codex does not get them. b37deed gave every worktree's protected files and trees "read" glob keys
// (GPT 6.1 sol final review of PR 9, finding 5), on the docs' word that read globs work on macOS.
// Codex 0.160 refuses the file instead: "filesystem glob path ... only supports `deny` access; use an
// exact path or trailing `/**` for `read` subtree access" (the owner's install, 2026-11-03, whose
// control caught it). A deny glob would refuse reading as well, and a worktree's build reads
// containment/c/d1netgate.c. So in Codex a worktree's copies are protected only by the tripwire's
// spelling, as before b37deed; the hook's worktreeTarget still refuses Edit and apply_patch there.
var codexWorktreePatterns = []string{".claude/worktrees/*", "runs/wt-*", "runs/wT-*", "runs/Wt-*", "runs/WT-*"}

// tomlKey is path as a TOML quoted key. A path with a quote, a backslash or a control character is
// refused rather than escaped: gate.CheckRoot keeps such a root out, and the profile text must be
// the path and nothing else. So is a glob anywhere but a final "/**": Codex 0.160 takes a glob key
// only with "deny" access and refuses the whole file otherwise, which stops every Codex session on
// this Mac, since the requirements apply to all of them.
func tomlKey(path string) (string, error) {
	if !filepath.IsAbs(path) || strings.ContainsAny(path, "\"\\") || strings.IndexFunc(path, func(character rune) bool { return character < 0x20 || character == 0x7f }) >= 0 {
		return "", fmt.Errorf("%q cannot be written into the Codex requirements: it is not absolute, or holds a quote, a backslash or a control character", path)
	}
	if strings.ContainsAny(strings.TrimSuffix(path, "/**"), "*?[]{}") {
		return "", fmt.Errorf("%q cannot be written into the Codex requirements: Codex reads a key with a glob only as \"deny\"; use an exact path or one ending in /**", path)
	}
	return "\"" + path + "\"", nil
}

// legacySandboxKeys are the older sandbox settings that the docs say to remove before a managed
// profile allowlist is deployed.
var legacySandboxKeys = []string{"sandbox_mode", "[sandbox_workspace_write]"}

// legacySandboxLines are text's lines that set one of legacySandboxKeys, trimmed.
func legacySandboxLines(text string) []string {
	var found []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		for _, key := range legacySandboxKeys {
			if strings.HasPrefix(line, key) {
				found = append(found, line)
			}
		}
	}
	return found
}

// tomlTableHeader is a TOML table or array-of-tables header: bare or quoted keys joined by dots. A
// value's continuation line, such as `["a"],` inside a multi-line array, is not one.
var tomlTableHeader = regexp.MustCompile(`^\[\[?\s*[A-Za-z0-9_-]+(\s*\.\s*([A-Za-z0-9_-]+|"[^"]*"))*\s*\]\]?\s*(#.*)?$`)

// withoutLegacySandbox is text without the older sandbox settings: each sandbox_mode line, and the
// [sandbox_workspace_write] table from its header to the next table header. removed lists the
// non-blank lines taken out.
func withoutLegacySandbox(text string) (kept string, removed []string) {
	var keep strings.Builder
	inTable := false
	for _, line := range strings.SplitAfter(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if tomlTableHeader.MatchString(trimmed) {
			inTable = strings.HasPrefix(trimmed, "[sandbox_workspace_write]")
		}
		if inTable || strings.HasPrefix(trimmed, "sandbox_mode") {
			if trimmed != "" {
				removed = append(removed, trimmed)
			}
			continue
		}
		keep.WriteString(line)
	}
	return keep.String(), removed
}

// RemoveLegacySandbox takes the older sandbox settings out of ~/.codex/config.toml, which check
// requires (owner, 2026-11-04: the install does it, not the owner by hand). Under the managed
// allowlist they no longer apply anyway (a writable_roots there is ignored; profile d1 decides).
// The earlier file is kept beside it as config.toml.before-d1-agent-hook.<time>, and the new one
// replaces it in one rename. A missing file, or one without them, is left alone.
func RemoveLegacySandbox(config Config) (removed []string, backup string, err error) {
	path := filepath.Join(config.Home, ".codex", "config.toml")
	text, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", err
	}
	kept, removed := withoutLegacySandbox(string(text))
	if len(removed) == 0 {
		return nil, "", nil
	}
	if left := legacySandboxLines(kept); len(left) > 0 {
		return nil, "", fmt.Errorf("%s: after removing the older sandbox settings, %q is still there; nothing was changed", path, left)
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, "", err
	}
	backup = path + ".before-d1-agent-hook." + time.Now().Format("20060102150405")
	if err := os.WriteFile(backup, text, info.Mode().Perm()); err != nil {
		return nil, "", err
	}
	next, err := os.CreateTemp(filepath.Dir(path), ".config.toml.d1-agent-hook.*")
	if err != nil {
		return nil, "", err
	}
	defer os.Remove(next.Name())
	if _, err := next.WriteString(kept); err != nil {
		next.Close()
		return nil, "", err
	}
	if err := next.Chmod(info.Mode().Perm()); err != nil {
		next.Close()
		return nil, "", err
	}
	if err := next.Close(); err != nil {
		return nil, "", err
	}
	if err := os.Rename(next.Name(), path); err != nil {
		return nil, "", err
	}
	return removed, backup, nil
}

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
		found = legacySandboxLines(string(user))
	}
	return append(lines, fact(len(found) == 0, "codex: "+userConfig+" sets none of the older sandbox settings, which a profile allowlist replaces"+listed(" (remove ", found)))
}
