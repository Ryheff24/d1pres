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

// codexValueOptions are codex exec's options that take a value and codexFlags those that take none,
// by long name; codexShort maps the short spellings to them. Read from "codex exec --help" of
// 0.160.0 (2026-11-03). Clap also reads "-sVALUE", "-s=VALUE" and "-hsVALUE", so a short word is
// read letter by letter (review of PR 9, R1), and an option not listed here is refused: what it
// does to the sandbox cannot be told.
var codexValueOptions = []string{"config", "enable", "disable", "image", "model", "local-provider", "profile", "sandbox", "cd", "add-dir",
	"thread-source", "cyber-access-program", "output-schema", "color", "output-last-message"}
var codexFlags = []string{"strict-config", "oss", "approve-for-me", "worktree", "skip-git-repo-check", "ephemeral", "ignore-user-config",
	"ignore-rules", "json", "help", "version"}
var codexShort = map[byte]string{'c': "config", 'i': "image", 'm': "model", 'p': "profile", 's': "sandbox", 'C': "cd", 'o': "output-last-message", 'h': "help", 'V': "version"}

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
//
// The arguments are checked as the program receives them (shellArguments: quotes removed,
// redirections apart), not as strings.Fields spells them: "'--dangerously-bypass-approvals-and-sandbox'"
// was a word no option matched, and the shell handed codex the bare flag (review of PR 9, R1). A
// redirection writes outside every sandbox like codex's -o does, so its file is held to the same
// place (redirectsInRepository, R2).
func ExcludedForm(command string, cwd string, config Config) string {
	line, rest := logicalLine(command)
	delimiter, why := scanShell(line)
	if why != "" {
		return "a command naming an excluded program must be that program alone: " + why
	}
	arguments, redirects := shellArguments(line)
	if len(arguments) == 0 || !arguments[0].literal || !isExcludedName(arguments[0].text) ||
		strings.Contains(arguments[0].text, "/") && !slices.Contains(excludedPaths, arguments[0].text) {
		return "a command naming an excluded program must start with it, by name or as one of " + strings.Join(excludedPaths, ", ")
	}
	words := make([]string, len(arguments))
	for index, argument := range arguments {
		words[index] = argument.text
	}
	name := filepath.Base(words[0])
	subcommand := ""
	if len(words) > 1 && arguments[1].literal {
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
		if why := codexForm(arguments[2:], cwd, config); why != "" {
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
	return redirectsInRepository(redirects, cwd, config)
}

// codexForm returns "" when codex exec's arguments (after "exec") leave its own sandbox and hook
// trust in place and write their output inside this repository: no option in codexDangerous,
// "-s"/"--sandbox" only read-only or workspace-write, "-c"/"--config" only the keys in
// codexConfigKeys (never sandbox_mode; --enable and --disable are -c features.NAME by another
// name), "-o"/"--output-last-message" only a path in the repository that is not protected, and
// "-C"/"--cd" and "--add-dir", the directories workspace-write lets it write, only inside the
// repository. Without these, codex runs arbitrary code outside every sandbox with the owner's
// credentials, which is what the sandbox exclusion was for one program's own sandbox, not for
// turning that one off (audit N3).
//
// Every word before "--" must be literal: an unquoted $NAME can split into options, and a path
// with $HOME or ~ in it is not the path codex is handed (review of PR 9, R1 and R2). The one
// expansion admitted is the owner's own "-C \"$PWD\"", which is the session's directory.
func codexForm(arguments []shellWord, cwd string, config Config) string {
	for index := 0; index < len(arguments); index++ {
		argument := arguments[index]
		if argument.literal && argument.text == "--" {
			return ""
		}
		if !argument.literal {
			return "codex " + argument.text + ": a word with an expansion ($, ~, a glob or braces) is not what codex is " +
				"handed, and can become an option; spell it out, or pass the prompt on stdin (-) from a quoted heredoc"
		}
		text := argument.text
		if text == "-" || !strings.HasPrefix(text, "-") {
			continue
		}
		var option string
		var value *shellWord
		if long, found := strings.CutPrefix(text, "--"); found {
			name, inline, hasInline := strings.Cut(long, "=")
			option = name
			if hasInline {
				value = &shellWord{text: inline, literal: true}
			}
		} else {
			for position := 1; position < len(text); position++ {
				name, known := codexShort[text[position]]
				if !known {
					return "codex " + text + ": -" + string(text[position]) + " is not one of codex exec's options, so what it " +
						"does to the sandbox cannot be told"
				}
				option = name
				if slices.Contains(codexValueOptions, name) {
					if rest := strings.TrimPrefix(text[position+1:], "="); rest != "" {
						value = &shellWord{text: rest, literal: true}
					}
					break
				}
			}
		}
		takesValue := slices.Contains(codexValueOptions, option)
		switch {
		case slices.Contains(codexDangerous, "--"+option) || strings.HasPrefix(option, "dangerously"):
			return "codex " + text + " turns off the sandbox codex applies to its own tools, or the trust it asks for " +
				"its hooks; it is refused here. Run codex exec -s read-only (or -s workspace-write when the task is to edit)"
		case !takesValue && !slices.Contains(codexFlags, option):
			return "codex " + text + " is not one of codex exec's options, so what it does to the sandbox cannot be told"
		case !takesValue && value != nil:
			return "codex " + text + ": --" + option + " takes no value"
		case !takesValue:
			continue
		}
		if value == nil {
			if index+1 >= len(arguments) {
				return "codex " + text + " needs a value"
			}
			index++
			value = &arguments[index]
		}
		if !value.literal && !(option == "cd" && isPWD(value.text)) {
			return "codex " + text + " " + value.text + ": a value with an expansion ($, ~, a glob or braces) is not the " +
				"value codex is handed; spell it out"
		}
		if why := codexValue(option, value.text, cwd, config); why != "" {
			return why
		}
	}
	return ""
}

// codexValue returns "" when value is admitted for codex exec's --option.
func codexValue(option string, value string, cwd string, config Config) string {
	switch option {
	case "config", "enable", "disable":
		key, _, _ := strings.Cut(value, "=")
		if option != "config" {
			key = "features." + value
		}
		if !slices.Contains(codexConfigKeys, key) {
			return "codex --" + option + " " + value + " is not admitted: configuration can turn the sandbox off (sandbox_mode) " +
				"as surely as a flag. The keys admitted here: " + strings.Join(codexConfigKeys, ", ")
		}
	case "sandbox":
		if !slices.Contains(codexSandboxes, value) {
			return "codex -s " + value + " is not admitted; codex runs here as -s " + strings.Join(codexSandboxes, " or -s ")
		}
	case "output-last-message":
		if why := outputInRepository(value, cwd, config); why != "" {
			return "codex -o " + value + ": " + why
		}
	case "cd", "add-dir":
		if isPWD(value) {
			value = cwd
		}
		if why := directoryInRepository(value, cwd, config); why != "" {
			return "codex --" + option + " " + value + ": " + why
		}
	}
	return ""
}

// isPWD reports whether text is the expansion of the shell's working directory and nothing else.
func isPWD(text string) bool {
	return text == "$PWD" || text == "${PWD}"
}

// directoryInRepository returns "" when path is this repository or a directory inside it, and not
// .git, a protected tree or a directory inside one: codex's workspace-write sandbox lets it write
// there, and it runs outside every other sandbox. Codex keeps a writable root's own .git read-only,
// so "--add-dir .git" or "--add-dir .claude/hooks" made a protected directory a root of its own,
// with nothing read-only below it (security review of PR 9, 2026-11-03). Both readings of the path
// are held to this (writeReadings).
func directoryInRepository(path string, cwd string, config Config) string {
	readings, why := writeReadings(path, cwd)
	if why != "" {
		return why
	}
	root, err := canonicalPath(config.Root)
	if err != nil {
		return "the repository root cannot be resolved"
	}
	held := append(ProtectedTreePaths(config), filepath.Join(config.Root, ".git"))
	for _, reading := range readings {
		canonical, err := canonicalPath(reading)
		if err != nil {
			return err.Error()
		}
		if !underPath(canonical, root) {
			return "codex's own sandbox writes where it is pointed, and it is pointed inside " + config.Root + ", nowhere else"
		}
		for _, directory := range held {
			inner, err := canonicalPath(directory)
			if err != nil {
				return directory + " cannot be resolved (" + err.Error() + "), so no directory can be checked against it"
			}
			if underPath(canonical, inner) {
				return "codex would write " + directory + " as a root of its own, where its sandbox keeps nothing read-only; " +
					"point it at the repository or another directory in it"
			}
		}
	}
	return ""
}

// redirectsInRepository returns "" when every file a redirection writes is one an excluded program
// may write: a literal path that outputInRepository admits, /dev/null, /dev/stdout or /dev/stderr,
// or the session's temporary directory spelled $TMPDIR/NAME (the owner's codex log). A redirection
// is opened by the shell, which the sandbox exclusion runs outside every sandbox, so before this
// "codex exec - > $HOME/.zshrc" wrote where -o was refused (review of PR 9, R2). Reading
// redirections, heredocs and descriptor merges write no file.
func redirectsInRepository(redirects []shellRedirect, cwd string, config Config) string {
	for _, redirect := range redirects {
		target := redirect.target
		switch {
		case strings.HasPrefix(redirect.operator, "<") && redirect.operator != "<>":
			continue
		case strings.HasSuffix(redirect.operator, "&") && target.literal && (target.text == "-" || strings.Trim(target.text, "0123456789") == ""):
			continue
		case target.literal && slices.Contains([]string{"/dev/null", "/dev/stdout", "/dev/stderr"}, target.text):
			continue
		case !target.literal && inTemporaryDirectory(target.text):
			continue
		case !target.literal:
			return redirect.operator + " " + target.text + ": the file a redirection writes must be spelled out (or be " +
				"$TMPDIR/NAME): the shell expands it outside every sandbox, and the hook cannot tell where it lands"
		}
		if why := outputInRepository(target.text, cwd, config); why != "" {
			return redirect.operator + " " + target.text + ": " + why + " (or under $TMPDIR)"
		}
	}
	return ""
}

// inTemporaryDirectory reports whether text is $TMPDIR (or ${TMPDIR}) followed by a plain relative
// path: letters, digits, ".", "_", "-" and "/", with no ".." step out of it.
func inTemporaryDirectory(text string) bool {
	rest, found := strings.CutPrefix(text, "$TMPDIR/")
	if !found {
		rest, found = strings.CutPrefix(text, "${TMPDIR}/")
	}
	if !found || rest == "" || strings.Trim(rest, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-/") != "" {
		return false
	}
	return !slices.Contains(strings.Split(rest, "/"), "..")
}

// outputInRepository returns "" when path is a file codex may write: inside the repository (codex
// runs outside every sandbox, so nothing else holds it to one) and not a protected file.
func outputInRepository(path string, cwd string, config Config) string {
	readings, why := writeReadings(path, cwd)
	if why != "" {
		return why
	}
	if why := ProtectedTarget(path, cwd, config); why != "" {
		return why
	}
	root, err := canonicalPath(config.Root)
	if err != nil {
		return "the repository root cannot be resolved"
	}
	for _, reading := range readings {
		canonical, err := canonicalPath(reading)
		if err != nil {
			return err.Error()
		}
		if !underPath(canonical, root) {
			return "a program the sandbox does not hold writes its output inside " + config.Root + ", nowhere else"
		}
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

// shellWord is one word of a command as the program receives it: quotes removed, and literal false
// when the shell would still change it ($ outside single quotes; ~, *, ?, [, { or } unquoted).
type shellWord struct {
	text    string
	literal bool
}

// shellRedirect is one redirection: its operator (">", ">>", "2>", "&>", ">&", "<", "<<", "<<-",
// "<>", ...) and the word after it (a file, a descriptor, or a heredoc delimiter).
type shellRedirect struct {
	operator string
	target   shellWord
}

// shellArguments splits a line that scanShell admitted into the words the program is handed and
// its redirections. scanShell has already refused backslashes, backquotes, $(, comments and every
// operator that starts a second command, so only quotes and redirections are left to read here.
func shellArguments(line string) ([]shellWord, []shellRedirect) {
	var arguments []shellWord
	var redirects []shellRedirect
	var word strings.Builder
	inWord, literal, quoted := false, true, false
	operator := ""
	end := func() {
		if !inWord {
			return
		}
		finished := shellWord{text: word.String(), literal: literal}
		if operator != "" {
			redirects = append(redirects, shellRedirect{operator: operator, target: finished})
			operator = ""
		} else {
			arguments = append(arguments, finished)
		}
		word.Reset()
		inWord, literal, quoted = false, true, false
	}
	quote := byte(0)
	for index := 0; index < len(line); index++ {
		character := line[index]
		switch {
		case quote == '\'':
			if character == '\'' {
				quote = 0
			} else {
				word.WriteByte(character)
			}
		case quote == '"':
			if character == '"' {
				quote = 0
			} else {
				literal = literal && character != '$'
				word.WriteByte(character)
			}
		case character == '\'' || character == '"':
			quote, inWord, quoted = character, true, true
		case character == ' ' || character == '\t':
			end()
		case character == '<' || character == '>' || character == '&':
			// A descriptor number written against the operator ("2>") belongs to it.
			descriptor := ""
			if inWord && !quoted && word.Len() > 0 && strings.Trim(word.String(), "0123456789") == "" {
				descriptor = word.String()
				word.Reset()
				inWord = false
			}
			end()
			start := index
			for index+1 < len(line) && strings.IndexByte("<>&", line[index+1]) >= 0 {
				index++
			}
			if strings.HasPrefix(line[start:index+1], "<<") && index+1 < len(line) && line[index+1] == '-' {
				index++
			}
			operator = descriptor + line[start:index+1]
		default:
			literal = literal && strings.IndexByte("$~*?[{}", character) < 0
			word.WriteByte(character)
			inWord = true
		}
	}
	end()
	return arguments, redirects
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
