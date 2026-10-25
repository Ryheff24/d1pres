// Package hook holds d1-agent-hook's rules: a Claude Code (or Codex) PreToolUse event in, a
// decision out. Codex sends the same event shape; its shell calls arrive as Bash and its file
// edits as apply_patch.
// "" lets the call go on to Claude Code's own permission flow; anything else is the reason it is
// refused. Every input it cannot read is refused (fail closed).
package hook

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"unicode"

	"d1preservation/netguard/gate"
)

// LauncherDirectory is the owner's root-owned install of d1-nonet, d1-localonly and the hook.
const LauncherDirectory = "/usr/local/libexec/d1-agent"

// Matcher is the PreToolUse matcher: Bash and every tool that edits a file.
const Matcher = "Bash|Edit|Write|MultiEdit|NotebookEdit"

// Config is what the rules are decided against: the repository (set at build time), the
// account's home directory, the launcher directory, and the session's ANTHROPIC_BASE_URL (empty
// when unset), which keeps a session on another provider at the current limits (Elevated).
type Config struct {
	Root              string
	Home              string
	LauncherDirectory string
	AnthropicBaseURL  string
}

// event is the part of the PreToolUse event the rules read. Codex sends the model; Claude Code
// sends the transcript and, for a subagent's call, its agent id (SessionModel).
type event struct {
	HookEventName  string          `json:"hook_event_name"`
	ToolName       string          `json:"tool_name"`
	ToolInput      json.RawMessage `json:"tool_input"`
	Cwd            string          `json:"cwd"`
	TranscriptPath string          `json:"transcript_path"`
	AgentID        string          `json:"agent_id"`
	Model          string          `json:"model"`
}

// toolInput is the part of a tool's input the rules read; a field of the wrong type refuses.
type toolInput struct {
	Command                   *string `json:"command"`
	DangerouslyDisableSandbox *bool   `json:"dangerouslyDisableSandbox"`
	FilePath                  string  `json:"file_path"`
	NotebookPath              string  `json:"notebook_path"`
}

// Decide reads one event and applies the rule for its tool. projectDirectory is
// CLAUDE_PROJECT_DIR from the hook's environment.
func Decide(raw []byte, projectDirectory string, config Config) string {
	var call event
	var input toolInput
	err := json.Unmarshal(raw, &call)
	if err == nil {
		err = json.Unmarshal(call.ToolInput, &input)
	}
	if err != nil {
		return "the event is not one this hook can read (" + err.Error() + ")"
	}
	if call.HookEventName != "" && call.HookEventName != "PreToolUse" && call.HookEventName != "preToolUse" {
		// *CRITICAL FLAG FOR MYTHOS*
		// I added `&& call.HookEventName != "preToolUse"` for cursor here. otherwise it would always error for the agent at least on bash
		// just double check that this logic, cursor may have more flows same for codex and claude, im assuming this coverage is not good enough
		// over the last week from agent use, i've really learned common patterns here of how the agents are behaving and some love to miss-behave
		// first, the containment needs to have better automatic containment it shouldn't be a critical blocker, first off, deny and specify correct
		// use. thats 90% of the issue, its like "this is not allowed", then the agents have no idea whats not allowed, they just blank hard.
		// i point them at what i think would be relevant documentation explaining the procedure(agent-containments usually, then 2nd is the
		// research skill). its not drilled in enough what to not do and what to do. theres a lot of conflicting information and old procedures
		// that while they are quoted out, cause drift. claude.md for example, or the fact that gpt was read only at first, then i added sandbox access
		// but the agents.md and claude.md should me symlinks, strip the prior source content from these docs entirely and focus on how shit works
		// the main issue are agents that aren't smart, they just cannot understand whats occuring,
		// this needs a larger look though, its extremely easy for claude opus 5.5 to understand and work here because its the most intelligent.
		// but for literally anyone else, likely half because documentation is written specifically for claude from claude,.
		// another example, the last mythos reviewer, who was testing the sandbox to make sure it worked, executed 2 tool calls (iirc it was bash)
		// with failed do to the hook(the test) then could be seen executing a 3rd tool call to i believe update a file that was considered a
		// locked file, and should've failed the hook. A second example, the original specification was everything ran in containment that ran code in
		// any way, tests included. but i don't think thats being followed, and its systemic because its not being prevented at the code level,
		// i keep sharing this pdf with agents from a talk at gdc from i think the lead engineer on the engine for destiny 1, this talk was in 2015
		// but specifically where it talks about rules of the codebase, enforcement, etc. it all applies here in a different way. Any tool, place, method, etc,
		// where code is tested or ran in any way, must be in containment, AUTOMATICALLY.
		return "this hook decides PreToolUse events, and was sent " + call.HookEventName
	}
	switch call.ToolName {
	case "Bash":
		return decideBash(call, input, []string{projectDirectory, call.Cwd}, config)
	case "Edit", "Write", "MultiEdit", "NotebookEdit":
		return decideEdit(call.ToolName, input, call.Cwd, config)
	case "apply_patch":
		return decidePatch(input, call.Cwd, config)
	}
	return fmt.Sprintf("this hook decides Bash, the edit tools and apply_patch only, and was sent %q", call.ToolName)
}

// decideBash: a game binary named without the launcher is refused from any session. In sessions
// in, inside or above this repository, a command naming one of the owner's excluded programs must
// be that command alone, and then skips the tripwire (the program runs outside the sandbox by the
// owner's choice, and a heredoc body is its data: codex prompts name protected files); any other
// command naming a protected file must be a pure read (Tripwire), and a call with the sandbox off
// must be the launcher form, or, from an elevated model's session, an elevated tool (ElevatedForm).
func decideBash(call event, input toolInput, directories []string, config Config) string {
	if input.Command == nil {
		return "Bash: no command string in the event"
	}
	command := *input.Command
	code := withoutHeredocBody(command)
	game := firstWordMatching(code, func(word string) bool { return slices.Contains(gate.GameBinaries, filepath.Base(word)) })
	if game != "" {
		return game + " runs game code; start it only as the argument of " + config.LauncherDirectory + "/d1-nonet"
	}
	if !inScope(directories, config.Root) {
		return ""
	}
	if isCompanion(code) {
		return CompanionForm(command)
	}
	if firstWordMatching(code, isExcludedName) != "" {
		return ExcludedForm(command)
	}
	override := overridesTestGate(code)
	if override != "" {
		return override + " would build or run a Rust test without the test gate that d1-server/.cargo/config.toml links in; every test runs inside the network sandbox (containment/agent-containment.md, Tests)"
	}
	tripped := Tripwire(command)
	if tripped != "" {
		return tripped
	}
	if input.DangerouslyDisableSandbox == nil || !*input.DangerouslyDisableSandbox {
		return ""
	}
	launcher, why := LauncherForm(command, config)
	if why == "" {
		return RootOwned(launcher)
	}
	words := strings.Fields(command)
	if len(words) == 0 || !isElevatedToolWord(words[0]) {
		return why
	}
	elevated, because := Elevated(call, config)
	if !elevated {
		return why + "; " + words[0] + " is an elevated tool, and " + because
	}
	return ElevatedForm(command, call.Cwd, config)
}

// isElevatedToolWord reports whether word names one of elevatedTools, by name or path.
func isElevatedToolWord(word string) bool {
	_, known := elevatedTools[filepath.Base(word)]
	return known
}

// firstWordMatching returns the first word of any command segment (split at ; & | ( ) { } `,
// $( and newlines, assignments skipped) that matches, or "". A tripwire: it is spelling-based.
func firstWordMatching(command string, matches func(string) bool) string {
	segments := strings.FieldsFunc(strings.ReplaceAll(command, "$(", ";"), func(character rune) bool {
		return strings.ContainsRune(";&|(){}`\n", character)
	})
	for _, segment := range segments {
		for _, word := range strings.Fields(segment) {
			if isAssignment(word) {
				continue
			}
			if matches(word) {
				return word
			}
			break
		}
	}
	return ""
}

// testGateOverrides are the variable-name spellings that would drop the test gate from a Rust
// build: any RUSTFLAGS or RUSTDOCFLAGS variable replaces the config file's flags, and a substitute
// compiler, wrapper or linker could leave the archive out.
var testGateOverrides = []string{"RUSTFLAGS", "RUSTDOC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "CARGO_BUILD_RUSTC"}

// overridesTestGate returns the first word of command that would build or run a Rust test without
// the test gate, or "": a variable named in testGateOverrides, RUSTC, a CARGO_TARGET_*_LINKER or
// _RUNNER, or cargo's --config. A tripwire, spelling-based like the rest of this file; the gate
// itself is in each test binary.
func overridesTestGate(command string) string {
	words := strings.FieldsFunc(command, func(character rune) bool {
		return unicode.IsSpace(character) || strings.ContainsRune(";&|(){}`'\"$", character)
	})
	for _, word := range words {
		name, _, _ := strings.Cut(word, "=")
		if name == "RUSTC" || strings.HasPrefix(name, "CARGO_TARGET_") && (strings.HasSuffix(name, "_LINKER") || strings.HasSuffix(name, "_RUNNER")) {
			return word
		}
		for _, override := range testGateOverrides {
			if strings.Contains(name, override) {
				return word
			}
		}
		if strings.HasPrefix(word, "--config") && strings.Contains(command, "cargo") {
			return word
		}
	}
	return ""
}

// isAssignment reports whether word is NAME=value with an upper-case shell name.
func isAssignment(word string) bool {
	name, _, found := strings.Cut(word, "=")
	return found && name != "" && strings.Trim(name, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_") == ""
}

// LauncherForm accepts one plain command: D1_* assignments (never D1_NET*), then a launcher from
// the launcher directory spelled exactly, then the program by absolute path (for d1-nonet, a game
// binary built in this repository; for d1-localonly, anything but one), then arguments. No quotes,
// $, backquotes, ; & | < > or newlines, so the launcher is the only program the shell starts, and
// nothing but D1_* variables is added to the environment it starts with. It returns the launcher.
func LauncherForm(command string, config Config) (string, string) {
	for _, character := range command {
		if !strings.ContainsRune(" \t_./:,=@%+-", character) && !isAlphanumeric(character) {
			return "", fmt.Sprintf("sandbox off: %q is not allowed; run one plain command with no shell syntax", character)
		}
	}
	words := strings.Fields(command)
	for len(words) > 0 && isAssignment(words[0]) {
		name, _, _ := strings.Cut(words[0], "=")
		if !strings.HasPrefix(name, "D1_") || strings.HasPrefix(name, "D1_NET") {
			return "", "sandbox off: " + name + " may not be set; only D1_* variables, never D1_NET*, reach the launcher"
		}
		words = words[1:]
	}
	nonet := config.LauncherDirectory + "/d1-nonet"
	localonly := config.LauncherDirectory + "/d1-localonly"
	if len(words) > 0 && words[0] != nonet && words[0] != localonly {
		return "", "sandbox off: " + words[0] + " is not a launcher; start the command with " + nonet + " or " + localonly + ", spelled exactly"
	}
	if len(words) < 2 {
		return "", "sandbox off: run a launcher followed by the absolute path of the program it runs"
	}
	isGame := slices.Contains(gate.GameBinaries, filepath.Base(words[1]))
	switch {
	case words[0] == nonet && !isTestBinary(words[1], config) && (!isGame || words[1] != filepath.Join(config.Root, "d1-server/target/release", filepath.Base(words[1]))):
		return "", "sandbox off: d1-nonet runs only a game binary in " + filepath.Join(config.Root, "d1-server/target/release") +
			", a cargo test binary in " + filepath.Join(config.Root, "d1-server/target/{debug,release}/deps") +
			" or a Go test binary " + filepath.Join(config.Root, "testbin/<name>.test")
	case words[0] == localonly && (isGame || !filepath.IsAbs(words[1])):
		return "", "sandbox off: d1-localonly runs a program named by its absolute path, never a game binary (those run under d1-nonet)"
	case words[0] == localonly && runsTests(words[1:], config):
		return "", "sandbox off: tests run only under d1-nonet, never d1-localonly: every test runs inside the network sandbox (containment/agent-containment.md, Tests)"
	}
	return words[0], ""
}

// runsTests reports whether a program and its arguments run tests: a test binary, or cargo or go
// with a test, bench or nextest subcommand (cargo's t alias included).
func runsTests(words []string, config Config) bool {
	if isTestBinary(words[0], config) || strings.HasSuffix(words[0], ".test") {
		return true
	}
	program := filepath.Base(words[0])
	if program != "cargo" && program != "go" {
		return false
	}
	for _, word := range words[1:] {
		if word == "test" || word == "t" || word == "bench" || word == "nextest" {
			return true
		}
	}
	return false
}

// isTestBinary reports whether path is a test binary built in this repository: a cargo one,
// d1-server/target/{debug,release}/deps/<crate>-<16 hex digits>, or a Go one built with
// "go test -c -o <root>/testbin/<name>.test". Every test runs only under d1-nonet (owner,
// 2026-10-18: "tests are always ran inside containment"; 2026-10-19: any test at all). Cargo
// writes crate names there with "_", so the one "-" is the hash separator.
func isTestBinary(path string, config Config) bool {
	directory, name := filepath.Split(path)
	if directory == filepath.Join(config.Root, "testbin")+"/" {
		stem, found := strings.CutSuffix(name, ".test")
		return found && stem != "" && strings.Trim(stem, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-") == ""
	}
	if directory != filepath.Join(config.Root, "d1-server/target/debug/deps")+"/" &&
		directory != filepath.Join(config.Root, "d1-server/target/release/deps")+"/" {
		return false
	}
	crate, hash, found := strings.Cut(name, "-")
	if !found || crate == "" || len(hash) != 16 {
		return false
	}
	for _, character := range crate {
		if character != '_' && !isAlphanumeric(character) {
			return false
		}
	}
	for _, character := range hash {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

// isAlphanumeric reports whether character is an ASCII letter or digit.
func isAlphanumeric(character rune) bool {
	return character < 128 && (character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9')
}

// RootOwned returns "" when path and every directory above it are owned by root, writable by no
// one else and not symbolic links: then no process of the user's can replace the launcher, or a
// directory on its path, between this check and the exec.
func RootOwned(path string) string {
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return "the launcher install cannot be trusted: " + err.Error()
		}
		status, readable := info.Sys().(*syscall.Stat_t)
		if !readable || info.Mode()&os.ModeSymlink != 0 || status.Uid != 0 || info.Mode().Perm()&0o022 != 0 {
			return fmt.Sprintf("the launcher install cannot be trusted: %s is %v owned by uid %d; it must be root-owned, not a link, and closed to group and other writes", current, info.Mode(), ownerOf(status))
		}
		if current == filepath.Dir(current) {
			return ""
		}
	}
}

// ownerOf is the owner's uid, or -1 when it could not be read.
func ownerOf(status *syscall.Stat_t) int64 {
	if status == nil {
		return -1
	}
	return int64(status.Uid)
}

// inScope reports whether any of the session's directories is this repository, inside it or
// above it. A directory that is not absolute or cannot be read counts as in scope, as does a
// session with none: the stricter rules then apply.
func inScope(directories []string, root string) bool {
	known := 0
	for _, directory := range directories {
		if directory == "" {
			continue
		}
		known++
		if !filepath.IsAbs(directory) || within(directory, root) || within(root, directory) {
			return true
		}
	}
	return known == 0
}

// within reports whether inner is outer or below it, by file identity, so neither case nor a
// symbolic link changes the answer. An outer it cannot read counts as containing.
func within(outer string, inner string) bool {
	outerInfo, err := os.Stat(outer)
	if err != nil {
		return true
	}
	for current := filepath.Clean(inner); ; current = filepath.Dir(current) {
		info, err := os.Stat(current)
		if err == nil && os.SameFile(info, outerInfo) {
			return true
		}
		if current == filepath.Dir(current) {
			return false
		}
	}
}
