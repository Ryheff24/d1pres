package hook

import (
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// companionScript is the runtime script of OpenAI's Codex plugin for Claude Code (owner installed
// it 2026-10-25, replacing codex exec from Bash). The plugin cache is write-denied to agents, so
// the file is the owner's. The script starts codex app-server, which cannot start inside the
// sandbox, so it runs outside it like codex exec; Codex applies its own -s sandbox to its tools.
var companionScript = regexp.MustCompile(`^/Users/ryanheffernan/\.claude/plugins/cache/openai-codex/codex/[0-9]+\.[0-9]+\.[0-9]+/scripts/codex-companion\.mjs$`)

// companionCommands are the plugin subcommands admitted. review and adversarial-review are left
// out: they start ephemeral threads, and every Codex session stays persisted (owner).
var companionCommands = []string{"setup", "task", "task-resume-candidate", "status", "result", "cancel"}

// isCompanion reports whether command starts node on a script named codex-companion.mjs.
func isCompanion(command string) bool {
	words := strings.Fields(command)
	return len(words) > 1 && words[0] == "node" && strings.HasSuffix(strings.Trim(words[1], `"'`), "/codex-companion.mjs")
}

// CompanionForm returns "" when command is node on companionScript, spelled out (no variables),
// with one of companionCommands, run alone under the same shell rules as ExcludedForm.
func CompanionForm(command string) string {
	line, rest := logicalLine(command)
	delimiter, why := scanShell(line)
	if why != "" {
		return "the Codex plugin command must run alone: " + why
	}
	words := strings.Fields(line)
	if len(words) < 3 || words[0] != "node" || !companionScript.MatchString(strings.Trim(words[1], `"'`)) {
		return "the Codex plugin runs only as node on its installed script, spelled out: " + companionScript.String()
	}
	if !slices.Contains(companionCommands, strings.Trim(words[2], `"'`)) {
		return "only the Codex plugin's " + strings.Join(companionCommands, ", ") + " are admitted, not " + words[2] + " (reviews start ephemeral threads; use task)"
	}
	return heredocEnds(rest, delimiter)
}

// excludedNames are the programs the owner's sandbox.excludedCommands runs outside Claude Code's
// sandbox with no flag set (owner, 2026-10-16: they stay, and codex exec keeps working; 2026-10-19:
// copilot -p joins them, allowed the same way codex is).
var excludedNames = []string{"xcrun", "xcodebuild", "codesign", "security", "system_profiler", "log", "codex", "copilot"}

// excludedPaths are the only absolute spellings accepted for them: the system's own, and the
// codex and copilot the owner uses. Any other path could be a program planted under that name.
// The copilot path is nvm's: it moves when the owner's Node version changes.
var excludedPaths = []string{
	"/usr/bin/xcrun", "/usr/bin/xcodebuild", "/usr/bin/codesign", "/usr/bin/security",
	"/usr/sbin/system_profiler", "/usr/bin/log",
	"/Applications/ChatGPT.app/Contents/Resources/codex-cli/bin/codex",
	"/Users/ryanheffernan/.nvm/versions/node/v22.19.0/bin/copilot",
}

// copilotBlanket are the copilot flags that grant every tool, path or URL. Copilot has no sandbox
// of its own (codex runs -s read-only), so its --allow-tool list is its only boundary, and a
// command that widens it to everything is refused.
var copilotBlanket = []string{"--allow-all", "--allow-all-tools", "--allow-all-paths", "--allow-all-urls", "--yolo"}

// isExcludedName reports whether word names an excluded program, by name or by any path.
func isExcludedName(word string) bool {
	return slices.Contains(excludedNames, filepath.Base(word))
}

// ExcludedForm returns "" when command is one excluded program run alone: its name or accepted
// path first (codex only as "codex exec", copilot only as "copilot -p" with none of
// copilotBlanket, log only as "log show" or "log stream"), then arguments that may use quotes,
// $NAME, redirections and lines joined with a trailing backslash, and at most one heredoc with a
// quoted delimiter, whose body is data. Anything that could start a second command is refused, so
// nothing rides along outside the sandbox. Redirections stay allowed: the owner's codex pattern
// writes its log with one.
func ExcludedForm(command string) string {
	line, rest := logicalLine(command)
	delimiter, why := scanShell(line)
	if why != "" {
		return "a command naming an excluded program must be that program alone: " + why
	}
	words := strings.Fields(line)
	if len(words) == 0 || !isExcludedName(words[0]) || strings.Contains(words[0], "/") && !slices.Contains(excludedPaths, words[0]) {
		return "a command naming an excluded program must start with it, by name or as one of " + strings.Join(excludedPaths, ", ")
	}
	name := filepath.Base(words[0])
	subcommand := ""
	if len(words) > 1 {
		subcommand = words[1]
	}
	if name == "codex" && subcommand != "exec" || name == "copilot" && subcommand != "-p" ||
		name == "log" && subcommand != "show" && subcommand != "stream" {
		return "only codex exec, copilot -p, log show and log stream are excluded from the sandbox, not " + name + " " + subcommand
	}
	if name == "copilot" {
		for _, word := range words {
			if slices.Contains(copilotBlanket, strings.SplitN(word, "=", 2)[0]) {
				return "copilot runs only with an explicit --allow-tool list, never " + word
			}
		}
	}
	return heredocEnds(rest, delimiter)
}

// logicalLine joins the first line with the lines a trailing backslash continues, and returns
// the joined line and everything after it.
func logicalLine(command string) (string, string) {
	lines := strings.Split(command, "\n")
	joined := ""
	for index, line := range lines {
		if !strings.HasSuffix(line, "\\") {
			return joined + line, strings.Join(lines[index+1:], "\n")
		}
		joined += strings.TrimSuffix(line, "\\") + " "
	}
	return joined, ""
}

// scanShell reads one line as the shell would, tracking quotes, and returns the heredoc delimiter
// if there is one, or why the line could start a second command.
func scanShell(line string) (string, string) {
	quote := byte(0)
	delimiter := ""
	for index := 0; index < len(line); index++ {
		previous, character, next := around(line, index)
		switch {
		case quote == '\'':
			if character == '\'' {
				quote = 0
			}
		case character == '`' || character == '\\' || character == '$' && next == '(':
			return "", fmt.Sprintf("%q can run another command", string(character)+string(next))
		case quote == '"':
			if character == '"' {
				quote = 0
			}
		case character == '\'' || character == '"':
			quote = character
		case character == ';' || character == '|' || (character == '<' || character == '>') && next == '(':
			return "", fmt.Sprintf("%q starts another command", string(character))
		case character == '&' && previous != '>' && previous != '<' && next != '>':
			return "", "\"&\" starts another command"
		case character == '<' && next == '<':
			if delimiter != "" {
				return "", "a second heredoc"
			}
			var why string
			delimiter, index, why = readDelimiter(line, index+2)
			if why != "" {
				return "", why
			}
		}
	}
	if quote != 0 {
		return "", "an unclosed quote"
	}
	return delimiter, ""
}

// around is the byte before index (0 at the start), the byte at it, and the byte after it (0 at the end).
func around(line string, index int) (byte, byte, byte) {
	previous := byte(0)
	next := byte(0)
	if index > 0 {
		previous = line[index-1]
	}
	if index+1 < len(line) {
		next = line[index+1]
	}
	return previous, line[index], next
}

// readDelimiter reads a heredoc delimiter at start: an optional "-", spaces, then a word in
// single or double quotes. It returns the word and the index of its closing quote.
func readDelimiter(line string, start int) (string, int, string) {
	index := start
	for index < len(line) && (line[index] == '-' || line[index] == ' ' || line[index] == '\t') {
		index++
	}
	if index >= len(line) || line[index] != '\'' && line[index] != '"' {
		return "", index, "the heredoc delimiter must be quoted, or its body is expanded and can run commands"
	}
	end := strings.IndexByte(line[index+1:], line[index])
	word := ""
	if end >= 0 {
		word = line[index+1 : index+1+end]
	}
	if word == "" || strings.Trim(word, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_") != "" {
		return "", index, "the heredoc delimiter must be one quoted word of letters, digits and _"
	}
	return word, index + 1 + end, ""
}

// heredocEnds returns "" when rest is empty (no heredoc) or, with a delimiter, holds the body, a
// line that is exactly the delimiter (leading tabs allowed), and nothing after it but blank lines.
func heredocEnds(rest string, delimiter string) string {
	lines := strings.Split(rest, "\n")
	if delimiter == "" {
		if strings.TrimSpace(rest) != "" {
			return "a command naming an excluded program must be that program alone: a second line"
		}
		return ""
	}
	for index, line := range lines {
		if strings.TrimLeft(line, "\t") == delimiter {
			if strings.TrimSpace(strings.Join(lines[index+1:], "\n")) != "" {
				return "a command naming an excluded program must be that program alone: a line after the heredoc"
			}
			return ""
		}
	}
	return "the heredoc never ends with a line " + delimiter
}

// withoutHeredocBody is command with a quoted heredoc's body removed, so the words in a prompt
// handed to codex are not read as commands. A command it cannot read is returned whole.
func withoutHeredocBody(command string) string {
	line, rest := logicalLine(command)
	delimiter, why := scanShell(line)
	if why != "" || delimiter == "" || heredocEnds(rest, delimiter) != "" {
		return command
	}
	return line
}
