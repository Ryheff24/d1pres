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
// copilot -p joins them, allowed the same way codex is; 2026-10-25, on the access control matrix:
// elevated models only, and security only as find-identity, since its other subcommands read the
// keychain).
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

// copilotInstalled is the path excludedPaths pins for copilot. It does not exist on this Mac any
// more (nvm moved to v22.23.4), so "copilot" only ever resolved on PATH, and copilot has no sandbox
// of its own: "copilot -p ... --allow-tool shell" ran arbitrary code outside every sandbox, which
// --allow-all and --yolo were refused for (audit 2026-10-31, N3). It is refused outright until the
// owner pins a path that is real; the name stays in excludedNames so the hook still sees it while
// sandbox.excludedCommands lists it.
const copilotInstalled = "/Users/ryanheffernan/.nvm/versions/node/v22.19.0/bin/copilot"

// codexDangerous are the codex options that turn off the sandbox or the hook trust codex applies to
// its own tools; codexConfigKeys are the only "-c key=value" keys admitted, because
// "-c sandbox_mode=danger-full-access" is the same thing spelled as configuration (audit N3).
// codexSandboxes are the values "-s" may take: never danger-full-access.
var codexDangerous = []string{"--dangerously-bypass-approvals-and-sandbox", "--dangerously-bypass-hook-trust", "--yolo"}
var codexConfigKeys = []string{"model_reasoning_effort", "model_reasoning_summary", "model_verbosity", "model_supports_reasoning_summaries", "hide_agent_reasoning", "include_plan_tool"}
var codexSandboxes = []string{"read-only", "workspace-write"}

// isExcludedName reports whether word names an excluded program, by name or by any path.
func isExcludedName(word string) bool {
	return slices.Contains(excludedNames, filepath.Base(word))
}

// ExcludedForm returns "" when command is one excluded program run alone: its name or accepted
// path first (codex only as "codex exec" under codexForm, log only as "log show" or "log stream",
// security only as find-identity, xcrun only as xcrunForm admits, copilot not at all), then
// arguments that may use quotes, $NAME, redirections and lines joined with a trailing backslash,
// and at most one heredoc with a quoted delimiter, whose body is data. Anything that could start a
// second command is refused, so nothing rides along outside the sandbox. Redirections stay allowed:
// the owner's codex pattern writes its log with one.
//
// The command line itself then goes through the tripwire (audit 2026-10-31, N2): these programs run
// outside every sandbox whatever the sandbox flag says, so before this
// "xcodebuild -version > CLAUDE.md" and "codex exec -o ~/.claude/settings.json" were admitted. The
// heredoc body is left out of that check, because a codex prompt names protected files as data.
func ExcludedForm(command string, cwd string, config Config) string {
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
	if name == "copilot" {
		return "copilot is not excluded from the sandbox: the path the hook pins for it (" + copilotInstalled +
			") does not exist any more, it has no sandbox of its own, and \"--allow-tool shell\" grants outside every " +
			"sandbox what --allow-all was refused for. Use the Codex plugin (node .../codex-companion.mjs task) or ask " +
			"the owner to pin copilot's current path; remove it from sandbox.excludedCommands until then"
	}
	if name == "codex" && subcommand != "exec" ||
		name == "log" && subcommand != "show" && subcommand != "stream" || name == "security" && subcommand != "find-identity" {
		return "only codex exec, log show, log stream and security find-identity are excluded from the sandbox, not " + name + " " + subcommand
	}
	if why := heredocEnds(rest, delimiter); why != "" {
		return why
	}
	if name == "codex" {
		if why := codexForm(words[1:], cwd, config); why != "" {
			return why
		}
	}
	if name == "xcrun" {
		if why := xcrunForm(words[1:]); why != "" {
			return why
		}
	}
	if why := Tripwire(line, config); why != "" {
		return why
	}
	return ""
}

// codexForm returns "" when codex exec's arguments leave its own sandbox and hook trust in place
// and write their output inside this repository: no option in codexDangerous, "-s"/"--sandbox" only
// read-only or workspace-write, "-c"/"--config" only the keys in codexConfigKeys (never
// sandbox_mode), and "-o"/"--output" only a path in the repository that is not protected. Without
// these, codex runs arbitrary code outside every sandbox with the owner's credentials, which is what
// the sandbox exclusion was for one program's own sandbox, not for turning that one off (audit N3).
func codexForm(arguments []string, cwd string, config Config) string {
	for index, argument := range arguments {
		option, value, inline := strings.Cut(argument, "=")
		next := func() (string, bool) {
			if inline {
				return value, true
			}
			if index+1 < len(arguments) {
				return arguments[index+1], true
			}
			return "", false
		}
		switch {
		case slices.Contains(codexDangerous, option) || strings.HasPrefix(option, "--dangerously"):
			return "codex " + argument + " turns off the sandbox codex applies to its own tools, or the trust it asks for " +
				"its hooks; it is refused here. Run codex exec -s read-only (or -s workspace-write when the task is to edit)"
		case option == "-c" || option == "--config":
			setting, _ := next()
			key, _, _ := strings.Cut(setting, "=")
			if !slices.Contains(codexConfigKeys, key) {
				return "codex -c " + setting + " is not admitted: configuration can turn the sandbox off (sandbox_mode) " +
					"as surely as a flag. The keys admitted here: " + strings.Join(codexConfigKeys, ", ")
			}
		case option == "-s" || option == "--sandbox":
			mode, found := next()
			if !found || !slices.Contains(codexSandboxes, mode) {
				return "codex -s " + mode + " is not admitted; codex runs here as -s " + strings.Join(codexSandboxes, " or -s ")
			}
		case option == "-o" || option == "--output" || option == "--output-last-message":
			path, found := next()
			if !found {
				return "codex " + option + " needs a path"
			}
			if why := outputInRepository(path, cwd, config); why != "" {
				return "codex " + option + " " + path + ": " + why
			}
		}
	}
	return ""
}

// outputInRepository returns "" when path is a file codex may write: inside the repository (codex
// runs outside every sandbox, so nothing else holds it to one) and not a protected file.
func outputInRepository(path string, cwd string, config Config) string {
	if !filepath.IsAbs(path) {
		if !filepath.IsAbs(cwd) {
			return "it is relative and the session has no working directory"
		}
		path = filepath.Join(cwd, path)
	}
	if why := ProtectedTarget(path, cwd, config); why != "" {
		return why
	}
	canonical, err := canonicalPath(filepath.Clean(path))
	if err != nil {
		return err.Error()
	}
	root, err := canonicalPath(config.Root)
	if err != nil {
		return "the repository root cannot be resolved"
	}
	if !underPath(canonical, root) {
		return "a program the sandbox does not hold writes its output inside " + config.Root + ", nowhere else"
	}
	return ""
}

// xcrunQueries are the xcrun options that only print where the SDK or a tool is; xcrunTools are the
// tools it may start: the simulator and device controls and Instruments (xctrace).
var xcrunQueries = []string{"--show-sdk-path", "--show-sdk-version", "--show-sdk-build-version", "--show-sdk-platform-path", "--show-sdk-platform-version", "--version", "-f", "--find"}
var xcrunTools = []string{"simctl", "devicectl"}

// xcrunForm returns "" when xcrun's arguments only query the SDK ([--sdk NAME] and one of
// xcrunQueries) or start one of xcrunTools. xctrace is ProfilerForm's, at its own path (profiler.go,
// 2026-10-28); the --launch check below stays as a second line. xcrun outside the
// sandbox otherwise starts any developer tool by name (python3, swift, clang with a plugin), and
// xctrace --launch starts any program: both run code outside containment (2026-10-25).
func xcrunForm(arguments []string) string {
	if len(arguments) >= 2 && arguments[0] == "--sdk" {
		if len(arguments) < 3 || !slices.Contains(xcrunQueries, arguments[2]) {
			return "xcrun --sdk NAME only queries the SDK (" + strings.Join(xcrunQueries, ", ") + "); it does not start tools outside the sandbox"
		}
		return ""
	}
	if len(arguments) == 0 || !slices.Contains(xcrunQueries, arguments[0]) && !slices.Contains(xcrunTools, arguments[0]) {
		return "xcrun outside the sandbox only queries the SDK or starts " + strings.Join(xcrunTools, ", ") + "; any other developer tool runs inside the sandbox"
	}
	if arguments[0] == "xctrace" && slices.ContainsFunc(arguments, func(word string) bool { return strings.HasPrefix(word, "--launch") }) {
		return "xctrace --launch starts a program outside containment; record with --attach PID on a process started by its launcher"
	}
	return ""
}

// logicalLine joins the first line with the lines a trailing backslash continues, and returns
// the joined line and everything after it. Like bash, it removes the backslash and newline
// outright: joining with a space made "--allow-a\<newline>ll" two harmless words here and one
// --allow-all for bash (review, 2026-10-28).
func logicalLine(command string) (string, string) {
	lines := strings.Split(command, "\n")
	joined := ""
	for index, line := range lines {
		if !strings.HasSuffix(line, "\\") {
			return joined + line, strings.Join(lines[index+1:], "\n")
		}
		joined += strings.TrimSuffix(line, "\\")
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
		case character == '#' && (index == 0 || previous == ' ' || previous == '\t'):
			// The rest of the line is a comment for bash, so a "<<'EOF'" after it is no heredoc and
			// the "body" runs as commands (review, 2026-10-28).
			return "", "\"#\" starts a comment, and what follows would not be what this check read"
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
