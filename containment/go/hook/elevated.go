package hook

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// ElevatedModels are the models whose sessions may run the elevated tools with the sandbox off
// (owner, 2026-10-25: "gpt sol 6.1, gpt 6 astra, claude 5.5, fable 5.1 - elevated; everything else -
// current limit"; the same day, on the PR: every Claude 5.5 model, not only Opus; 2026-10-27:
// "mythos is elevated as well", claude-mythos-5-1). Exact model ids as the harness records them; a
// provider-prefixed id (anthropic/claude-opus-5-5 through OpenRouter) is not one of them. The access
// control matrix (matrix.go) is the summary.
var ElevatedModels = []string{"gpt-6.1-sol", "gpt-6-astra", "claude-opus-5-5", "claude-sonnet-5-5", "claude-haiku-5-5", "claude-fable-5-1", "claude-mythos-5-1"}

// anthropicAPI is the only base URL an elevated Claude Code session talks to. A session started
// with ANTHROPIC_BASE_URL set to anything else (ori, OpenRouter, a local proxy) stays at the current
// limit whatever model it names.
const anthropicAPI = "https://api.anthropic.com"

// SessionModel returns the model making this call as its harness recorded it, or "" when it cannot
// tell: Codex puts it in the event; Claude Code writes it into the session's transcript (a
// subagent's into its own file beside it), which agents cannot write (decideEdit refuses edits under
// the records directories, and Claude Code's sandbox denies writes to them).
func SessionModel(call event, config Config) string {
	if call.Model != "" {
		return call.Model
	}
	transcript := call.TranscriptPath
	if transcript == "" {
		return ""
	}
	if call.AgentID != "" {
		if strings.Trim(call.AgentID, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-") != "" {
			return ""
		}
		transcript = filepath.Join(strings.TrimSuffix(transcript, ".jsonl"), "subagents", "agent-"+call.AgentID+".jsonl")
	}
	if !insideRecords(transcript, filepath.Join(config.Home, ".claude", "projects")) {
		return ""
	}
	return transcriptModel(transcript)
}

// Elevated reports whether the session making this call may run the elevated tools, and if not,
// why, for the refusal. Anything it cannot read is not elevated.
func Elevated(call event, config Config) (bool, string) {
	if call.Model == "" && config.AnthropicBaseURL != "" && strings.TrimSuffix(config.AnthropicBaseURL, "/") != anthropicAPI {
		return false, "this session talks to " + config.AnthropicBaseURL + ", not Anthropic, so it has the current limits"
	}
	model := SessionModel(call, config)
	if model == "" {
		return false, "the hook cannot tell which model makes this call, so it has the current limits"
	}
	if !slices.Contains(ElevatedModels, model) {
		return false, model + " has the current limits; the elevated tools are for " + strings.Join(ElevatedModels, ", ")
	}
	return true, ""
}

// insideRecords reports whether path is a regular file, not a link, whose real path is below
// records' real path.
func insideRecords(path string, records string) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return false
	}
	root, err := filepath.EvalSymlinks(records)
	if err != nil {
		return false
	}
	return strings.HasPrefix(real, root+string(filepath.Separator))
}

// transcriptWindow is how much of a transcript's end is read for its last assistant entry.
const transcriptWindow = 4 << 20

// transcriptModel returns message.model of the last assistant entry in a Claude Code transcript
// (JSON lines), skipping Claude Code's own "<synthetic>" entries, or "". Each line is parsed as
// JSON, so text a model wrote that looks like a model field is never read as one.
func transcriptModel(path string) string {
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return ""
	}
	start := max(info.Size()-transcriptWindow, 0)
	buffer := make([]byte, info.Size()-start)
	_, err = file.ReadAt(buffer, start)
	if err != nil && err != io.EOF {
		return ""
	}
	lines := bytes.Split(buffer, []byte{'\n'})
	if start > 0 {
		lines = lines[1:]
	}
	for index := len(lines) - 1; index >= 0; index-- {
		var entry struct {
			Type    string `json:"type"`
			Message struct {
				Model string `json:"model"`
			} `json:"message"`
		}
		if json.Unmarshal(lines[index], &entry) != nil || entry.Type != "assistant" {
			continue
		}
		if entry.Message.Model != "" && entry.Message.Model != "<synthetic>" {
			return entry.Message.Model
		}
	}
	return ""
}

// grant is one program an elevated session may run with the sandbox off: the one path the hook
// accepts for it (a bare name must resolve there on the hook's PATH, so a program planted earlier
// on PATH under the same name is refused), whether it only inspects (its output may then be piped
// into pipeReaders), and the options refused because they write a file, open an app or start a
// program.
type grant struct {
	path    string
	inspect bool
	writing []string
}

// elevatedGrants are the elevated tools, one table; the access control matrix (matrix.go) shows
// them by row. sample -e opens TextEdit; leaks --atExit and anything after "--" run a program.
var elevatedGrants = map[string]grant{
	// processes, memory and network: they only read
	"ps":      {"/bin/ps", true, nil},
	"pgrep":   {"/usr/bin/pgrep", true, nil},
	"lsof":    {"/usr/sbin/lsof", true, nil},
	"nettop":  {"/usr/bin/nettop", true, nil},
	"top":     {"/usr/bin/top", true, nil},
	"vm_stat": {"/usr/bin/vm_stat", true, nil},
	"sample":  {"/usr/bin/sample", true, []string{"-file", "-e"}},
	"leaks":   {"/usr/bin/leaks", true, []string{"--outputGraph", "--atExit", "--"}},
	"vmmap":   {"/usr/bin/vmmap", true, nil},
	"heap":    {"/usr/bin/heap", true, nil},
	// stopping this project's processes (killForm)
	"kill":    {"/bin/kill", false, nil},
	"pkill":   {"/usr/bin/pkill", false, nil},
	"killall": {"/usr/bin/killall", false, nil},
	// opening this repository's files in the owner's VS Code (codeForm)
	"code": {"/usr/local/bin/code", false, nil},
}

// pipeReaders may follow an inspecting tool after "|". uniq and sort are left out: both can write a
// file named as an argument.
var pipeReaders = map[string]string{"grep": "/usr/bin/grep", "head": "/usr/bin/head", "tail": "/usr/bin/tail", "wc": "/usr/bin/wc"}

// ElevatedForm returns "" when an elevated session's sandbox-off command is one elevated tool run
// alone, or an inspector piped into readers, under these rules: no shell syntax that could start
// another command, expand a variable or write a file; every program at its accepted path; an
// inspector without its writing options; nettop and top only in logging mode (-l or -L), so they end;
// kill, pkill and killall only at this project's processes (projectProcess); code only on this
// repository's files (codeForm). cwd resolves code's relative paths.
func ElevatedForm(command string, cwd string, config Config) string {
	segments, why := splitPlain(command)
	if why != "" {
		return "sandbox off (elevated): " + why
	}
	first := segments[0]
	tool := filepath.Base(first[0])
	granted, known := elevatedGrants[tool]
	if !known {
		return "sandbox off (elevated): " + first[0] + " is neither a launcher nor an elevated tool (" + strings.Join(sortedKeys(elevatedGrants), ", ") + ")"
	}
	if why := acceptedPath(first[0], granted.path); why != "" {
		return "sandbox off (elevated): " + why
	}
	if len(segments) > 1 && !granted.inspect {
		return "sandbox off (elevated): only an inspecting tool's output may be piped, not " + tool + "'s"
	}
	for _, segment := range segments[1:] {
		reader := filepath.Base(segment[0])
		path, known := pipeReaders[reader]
		if !known {
			return "sandbox off (elevated): after \"|\" only " + strings.Join(sortedKeys(pipeReaders), ", ") + " may read, not " + segment[0]
		}
		if why := acceptedPath(segment[0], path); why != "" {
			return "sandbox off (elevated): " + why
		}
	}
	arguments := first[1:]
	for _, argument := range arguments {
		for _, option := range granted.writing {
			if argument == option || strings.HasPrefix(argument, option+"=") {
				return "sandbox off (elevated): " + tool + " " + option + " writes a file, opens an app or starts a program"
			}
		}
	}
	switch tool {
	case "nettop", "top":
		if !slices.ContainsFunc(arguments, func(argument string) bool {
			return strings.HasPrefix(argument, "-l") || strings.HasPrefix(argument, "-L")
		}) {
			return "sandbox off (elevated): " + tool + " runs only in logging mode (-l N), which ends; interactive mode never returns"
		}
	case "kill", "pkill", "killall":
		return killForm(tool, arguments, config)
	case "code":
		return codeForm(arguments, cwd, config)
	}
	return ""
}

// splitPlain reads command as the shell would and splits it at "|" into segments of words, quotes
// removed. It refuses what could run a second command, expand anything or write a file: ; & < > ` $
// \ ( ) a newline, and the glob and home characters * ? [ ] { } ~ outside quotes. Single and double
// quotes keep their contents literal ($ and ` are refused inside double quotes too).
func splitPlain(command string) ([][]string, string) {
	var segments [][]string
	var words []string
	word, inWord := "", false
	quote := byte(0)
	end := func() {
		if inWord {
			words = append(words, word)
		}
		word, inWord = "", false
	}
	for index := 0; index < len(command); index++ {
		character := command[index]
		switch {
		case quote == '\'':
			if character == '\'' {
				quote = 0
				continue
			}
			word += string(character)
		case quote == '"' && (character == '$' || character == '`' || character == '\\'):
			return nil, fmt.Sprintf("%q inside double quotes can expand or run a command", string(character))
		case quote == '"':
			if character == '"' {
				quote = 0
				continue
			}
			word += string(character)
		case character == '\'' || character == '"':
			quote, inWord = character, true
		case character == ' ' || character == '\t':
			end()
		case character == '|':
			end()
			if len(words) == 0 {
				return nil, "\"|\" with no command before it"
			}
			segments, words = append(segments, words), nil
		case strings.IndexByte(";&<>`$\\()\n*?[]{}~", character) >= 0:
			return nil, fmt.Sprintf("%q is not allowed; run one plain command, optionally piped into a reader", string(character))
		default:
			word, inWord = word+string(character), true
		}
	}
	if quote != 0 {
		return nil, "an unclosed quote"
	}
	end()
	if len(words) == 0 {
		return nil, "no command"
	}
	return append(segments, words), ""
}

// acceptedPath returns "" when spelled names the program at path: that path exactly, or a bare name
// that resolves to it on the hook's PATH.
func acceptedPath(spelled string, path string) string {
	if spelled == path {
		return ""
	}
	if strings.Contains(spelled, "/") {
		return spelled + " is not " + path + ", the only path accepted for it"
	}
	found, err := exec.LookPath(spelled)
	if err != nil {
		return spelled + " is not on PATH"
	}
	real, err := filepath.EvalSymlinks(found)
	want, wantErr := filepath.EvalSymlinks(path)
	if err != nil || wantErr != nil || real != want {
		return spelled + " resolves to " + found + ", not " + path + "; spell it " + path
	}
	return ""
}

// killForm admits kill [-SIG | -s SIG] PID..., pkill [-SIG] [-f] [-x] [-i] PATTERN and killall
// [-SIG] NAME only when every process they reach is one of this project's (projectProcess), and at
// least one is: pkill and killall are resolved first with pgrep (-x for killall) and the same match
// options. Process groups (negative ids), -1 and 0 are refused.
func killForm(tool string, arguments []string, config Config) string {
	var targets []string
	var match []string
	signal := false
	for index := 0; index < len(arguments); index++ {
		argument := arguments[index]
		switch {
		case tool == "kill" && argument == "-s" && index+1 < len(arguments) && !signal:
			index++
			signal = true
		case strings.HasPrefix(argument, "-") && isSignal(argument[1:]) && !signal && len(targets) == 0 && len(match) == 0:
			signal = true
		case tool == "pkill" && (argument == "-f" || argument == "-x" || argument == "-i"):
			match = append(match, argument)
		case strings.HasPrefix(argument, "-"):
			return "sandbox off (elevated): " + tool + " " + argument + " is not admitted; use " + tool + " [-SIGNAL] and " + map[string]string{"kill": "process ids", "pkill": "-f, -x or -i and one pattern", "killall": "one name"}[tool]
		default:
			targets = append(targets, argument)
		}
	}
	if len(targets) == 0 {
		return "sandbox off (elevated): " + tool + " names no process"
	}
	var pids []int
	if tool == "kill" {
		for _, target := range targets {
			pid, err := strconv.Atoi(target)
			if err != nil || pid < 2 {
				return "sandbox off (elevated): kill takes process ids above 1, not " + target
			}
			pids = append(pids, pid)
		}
	} else {
		if len(targets) != 1 {
			return "sandbox off (elevated): " + tool + " takes one pattern"
		}
		if tool == "killall" {
			match = []string{"-x"}
		}
		var err error
		pids, err = findProcesses(append(match, targets[0]))
		if err != nil {
			return "sandbox off (elevated): cannot resolve " + tool + " " + targets[0] + ": " + err.Error()
		}
		if len(pids) == 0 {
			return "sandbox off (elevated): " + tool + " " + targets[0] + " matches no process"
		}
	}
	for _, pid := range pids {
		if why := projectProcess(pid, config.Root); why != "" {
			return "sandbox off (elevated): " + tool + " would reach process " + strconv.Itoa(pid) + ", " + why + "; only this project's processes are stopped (CLAUDE.md, this project's processes)"
		}
	}
	return ""
}

// isSignal reports whether name is a signal number or an upper-case signal name (KILL, TERM, INT).
func isSignal(name string) bool {
	if name == "" {
		return false
	}
	if number, err := strconv.Atoi(name); err == nil {
		return number > 0 && number < 32
	}
	return strings.Trim(name, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") == ""
}

// projectNames are the programs CLAUDE.md lists as this project's ("this project's processes")
// besides those built in the repository: the d1- tools, the solvers and TLA+ tools, make. codex is
// left out: GPT's jobs stop through the Codex plugin's cancel.
var projectNames = []string{"z3", "java", "tlapm", "poly", "make"}

// projectProcess returns "" when pid's working directory is in root and its executable is in root,
// starts with d1-, or is one of projectNames; else what it is. The owner's other projects, the agent
// sessions themselves (claude, node, codex) and the owner's apps are never this project's.
func projectProcess(pid int, root string) string {
	program, directory, why := readProcess(pid)
	if why != "" {
		return why
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "and the repository root cannot be resolved"
	}
	inRoot := func(path string) bool {
		real, err := filepath.EvalSymlinks(path)
		return err == nil && (real == realRoot || strings.HasPrefix(real, realRoot+string(filepath.Separator)))
	}
	if directory == "" || !inRoot(directory) {
		return program + " working in " + directory
	}
	name := filepath.Base(program)
	if !inRoot(program) && !strings.HasPrefix(name, "d1-") && !slices.Contains(projectNames, name) {
		return program + ", which is not one of this project's programs"
	}
	return ""
}

// readProcess returns a process's executable (ps) and working directory (lsof), or why it cannot.
// A variable so the rules are tested without real processes: inside d1-nonet's profile ps sees none.
var readProcess = func(pid int) (string, string, string) {
	executable, err := exec.Command("/bin/ps", "-o", "comm=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return "", "", "which is not running"
	}
	program := strings.TrimSpace(string(executable))
	output, err := exec.Command("/usr/sbin/lsof", "-a", "-p", strconv.Itoa(pid), "-d", "cwd", "-Fn").Output()
	if err != nil {
		return "", "", program + ", whose working directory cannot be read"
	}
	directory := ""
	for _, line := range strings.Split(string(output), "\n") {
		if strings.HasPrefix(line, "n") {
			directory = line[1:]
		}
	}
	return program, directory, ""
}

// pgrep is findProcesses outside tests.
var findProcesses = pgrep

// pgrep returns the process ids pgrep finds for these arguments (none is not an error).
func pgrep(arguments []string) ([]int, error) {
	output, err := exec.Command("/usr/bin/pgrep", arguments...).Output()
	if exit, ok := err.(*exec.ExitError); ok && exit.ExitCode() == 1 {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var pids []int
	for _, field := range strings.Fields(string(output)) {
		pid, err := strconv.Atoi(field)
		if err != nil {
			return nil, fmt.Errorf("pgrep printed %q", field)
		}
		pids = append(pids, pid)
	}
	return pids, nil
}

// codeOptions are the code options admitted: open in the current window, and go to a line.
var codeOptions = []string{"-r", "--reuse-window", "-g", "--goto"}

// codeForm admits code with codeOptions and one or more existing regular files in this repository
// (by real path, so a link out of it is refused), at most 20, each optionally path:line[:column]
// with -g. Folders, .code-workspace files and anything under .vscode or .git are refused: opening a
// folder or workspace can start its tasks, and those files configure VS Code itself.
func codeForm(arguments []string, cwd string, config Config) string {
	goTo := slices.Contains(arguments, "-g") || slices.Contains(arguments, "--goto")
	realRoot, err := filepath.EvalSymlinks(config.Root)
	if err != nil {
		return "sandbox off (elevated): the repository root cannot be resolved"
	}
	files := 0
	for _, argument := range arguments {
		if slices.Contains(codeOptions, argument) {
			continue
		}
		if strings.HasPrefix(argument, "-") {
			return "sandbox off (elevated): code " + argument + " is not admitted; only " + strings.Join(codeOptions, ", ") + " and this repository's files"
		}
		path := argument
		if goTo {
			path = stripLine(path)
		}
		if !filepath.IsAbs(path) {
			if !filepath.IsAbs(cwd) {
				return "sandbox off (elevated): code " + argument + " is relative and the session has no working directory"
			}
			path = filepath.Join(cwd, path)
		}
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() {
			return "sandbox off (elevated): code opens existing files only, and " + argument + " is not one"
		}
		real, err := filepath.EvalSymlinks(path)
		if err != nil || !strings.HasPrefix(real, realRoot+string(filepath.Separator)) {
			return "sandbox off (elevated): code opens only this repository's files, and " + argument + " is outside it"
		}
		relative := strings.TrimPrefix(real, realRoot+string(filepath.Separator))
		parts := strings.Split(relative, string(filepath.Separator))
		if strings.HasSuffix(real, ".code-workspace") || slices.Contains(parts, ".vscode") || slices.Contains(parts, ".git") {
			return "sandbox off (elevated): code does not open " + relative + ": workspace, .vscode and .git files configure VS Code or git"
		}
		files++
	}
	if files == 0 {
		return "sandbox off (elevated): code names no file"
	}
	if files > 20 {
		return "sandbox off (elevated): code opens at most 20 files at once"
	}
	return ""
}

// stripLine removes a trailing :line or :line:column from a -g argument.
func stripLine(argument string) string {
	for range 2 {
		at := strings.LastIndexByte(argument, ':')
		if at < 0 {
			break
		}
		if _, err := strconv.Atoi(argument[at+1:]); err != nil {
			break
		}
		argument = argument[:at]
	}
	return argument
}

// sortedKeys is a map's keys in order, for refusals that list them.
func sortedKeys[V any](table map[string]V) []string {
	keys := make([]string, 0, len(table))
	for key := range table {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

// recordDirectories are the harness records the elevated check reads: Claude Code's transcripts
// and Codex's session rollouts. No agent edits them, so no session can rewrite the model it is
// recorded as.
func recordDirectories(config Config) []string {
	return []string{filepath.Join(config.Home, ".claude", "projects"), filepath.Join(config.Home, ".codex", "sessions")}
}

// RecordsTarget returns "" unless path is in one of recordDirectories (by real path of its deepest
// existing part), then why it is refused. A project's memory directory
// (~/.claude/projects/<project>/memory/) is not a record.
func RecordsTarget(path string, cwd string, config Config) string {
	if !filepath.IsAbs(path) {
		path = filepath.Join(cwd, path)
	}
	existing := filepath.Clean(path)
	for {
		if _, err := os.Lstat(existing); err == nil || existing == filepath.Dir(existing) {
			break
		}
		existing = filepath.Dir(existing)
	}
	real, err := filepath.EvalSymlinks(existing)
	if err != nil {
		return path + " cannot be resolved (" + err.Error() + "), so it cannot be checked against the session records"
	}
	for _, records := range recordDirectories(config) {
		root, err := filepath.EvalSymlinks(records)
		if err != nil {
			continue
		}
		if real != root && !strings.HasPrefix(real, root+string(filepath.Separator)) {
			continue
		}
		// Claude Code keeps each project's memory beside its transcripts; agents write that.
		full := real + strings.TrimPrefix(filepath.Clean(path), existing)
		below := strings.Split(strings.TrimPrefix(full, root+string(filepath.Separator)), string(filepath.Separator))
		if strings.HasSuffix(records, "projects") && len(below) >= 3 && below[1] == "memory" {
			continue
		}
		return records + " holds the harness's session records, which the hook reads to tell the model; no agent edits them"
	}
	return ""
}
